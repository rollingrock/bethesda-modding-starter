#!/usr/bin/env python3
"""Turn the C++ signature sitting in a function's NAME into an applied prototype.

The BethesdaGhidraScripts pipeline names tens of thousands of functions from the VR address
library, and those names carry full signatures --
`BGSAIWorldLocationPointRadius::Allocate(NiPoint3&,TESObjectCELL*,TESWorldSpace*,float,float)`
-- but it sets names only. The decompiler therefore still shows

    (undefined4 *param_1, longlong param_2, longlong param_3, float param_4, ...)

while all ~44,700 CommonLibF4 types sit loaded in the same program, unused. This closes that
gap by parsing each name and applying it with /set_function_prototype.

WHY THIS IS NOT A ONE-LINER -- a demangled C++ name is missing two things:

  1. `this`. The arg list excludes the this-pointer, so we must decide whether to prepend
     one. Get it wrong and EVERY parameter shifts by one position, which is strictly worse
     than leaving the function alone. Nothing in the source data says static vs instance:
     the address-library CSV is `id,fo4,vr,status,name`, and BGS's PDB publics corpus is
     already demangled with no access specifiers. The only local signal is Ghidra's own
     decompiler arity, which can UNDERCOUNT (it infers from registers actually used) but
     never overcount -- so `inferred == args + 1` proves a this-pointer, while
     `inferred == args` is genuinely ambiguous (static, or instance with an unused arg).
     Measured on a 150-function sample: 67% decisive, 26% ambiguous. We skip the ambiguous.

  2. The return type. Nowhere in the data. Writing `void` would DESTROY the decompiler's
     own inference, so we emit `undefined8` -- Ghidra's honest "unknown 8 bytes".

Phases (each cached, so you pay the slow one once):

    fetch    pull the function list and the data-type index          (~20 s)
    probe    decompile candidates to learn this-ness -- SLOW,        (~150 min for the full
             ~347 ms/function, resumable, safe to interrupt           corpus; --limit to trim)
    report   tier everything and write the proposed prototypes       (instant)
    apply    validate then set, journalling every change             (~50 ms/function)

Dry-run is the default. `apply` requires --apply, and even then validates every prototype
against Ghidra's own parser first.

    python apply_prototypes.py fetch
    python apply_prototypes.py probe --limit 2000
    python apply_prototypes.py report
    python apply_prototypes.py apply --apply

BACK UP THE PROJECT FIRST. This writes to a database that took hours to build.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

DEFAULT_URL = "http://127.0.0.1:8089"

# /decompile_function accepts `functions=` as a comma-separated batch, but silently caps it:
# ask for 25 and exactly 20 come back, tail dropped, no error and nothing in the endpoint's
# own description. Measured 2026-08-16 against GhidraMCP 7.0.0 (5->5, 20->20, 21->20, 40->20).
DECOMPILE_BATCH_CAP = 20

# ---------------------------------------------------------------- HTTP


def _get(url: str, timeout: int = 300) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _post(url: str, payload: dict, timeout: int = 300) -> str:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


# ---------------------------------------------------------------- C++ name parsing

SIG_RE = re.compile(r"^(?P<qual>[^()]+?)\((?P<args>.*)\)$")

BUILTIN = {
    "void", "bool", "char", "signed char", "unsigned char", "short", "unsigned short",
    "int", "unsigned int", "long", "unsigned long", "float", "double", "wchar_t",
    "__int8", "__int16", "__int32", "__int64", "long long",
}
# The pipeline writes some builtins with underscores where spaces were.
BUILTIN_ALIAS = {
    "unsigned___int64": "unsigned __int64",
    "unsigned___int32": "unsigned int",
    "unsigned___int16": "unsigned short",
    "unsigned___int8": "unsigned char",
    "unsigned_int": "unsigned int",
    "unsigned_char": "unsigned char",
    "unsigned_short": "unsigned short",
    "unsigned_long": "unsigned long",
    "long_long": "long long",
}


def split_top_level(s: str) -> list[str]:
    """Split on commas that are not inside <>, () or []."""
    out: list[str] = []
    depth = 0
    cur = ""
    for ch in s:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def split_qualifier(qual: str) -> tuple[str | None, str]:
    """Return (owning class, member name), splitting on the last top-level '::'."""
    depth = 0
    cut = -1
    i = 0
    while i < len(qual):
        ch = qual[i]
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        elif ch == ":" and depth == 0 and i + 1 < len(qual) and qual[i + 1] == ":":
            cut = i
            i += 1
        i += 1
    if cut < 0:
        return None, qual
    return qual[:cut], qual[cut + 2:]


def sanitize_identifier(member: str) -> str:
    """Ghidra's signature parser wants a plain identifier for the function name.

    It is used ONLY for parsing -- set_function_prototype does not rename the function --
    so mangling operator/ctor names here is harmless.
    """
    ident = re.sub(r"[^A-Za-z0-9_]", "_", member)
    if not ident or ident[0].isdigit():
        ident = "f_" + ident
    return ident


# A struct this small is a forward-declared placeholder, not a real layout. Ghidra stores
# uninstantiated templates that way -- NiPointer, BSTSmartPointer, CArgs and StreamRequest
# are all 1 byte. Pointing a parameter at one is worse than leaving it undefined: the
# decompiler then reports confidently wrong field offsets. Measured against F4VR.
PLACEHOLDER_MAX_BYTES = 1


class TypeIndex:
    """The program's data types, with sizes, indexed for signature lookup.

    Resolution is deliberately conservative. Three match kinds, in descending confidence:

      exact     the token names a type that exists verbatim -- trustworthy
      template  only the BASE of a templated name exists (BSTSmartPointer for
                BSTSmartPointer<Foo,Bar>) -- almost always a 1-byte stub, see above
      leaf      only the last :: component matches -- outright dangerous, because names
                like `Entry` are shared by 4 unrelated types in this program

    Only `exact` is trusted by default; --loose promotes `template`.
    """

    def __init__(self, entries: list[str]):
        self.size: dict[str, int] = {}
        self.exact: set[str] = set()
        for e in entries:
            parts = [p.strip() for p in e.split(" | ")]
            head = parts[0] if parts else ""
            if not head:
                continue
            self.exact.add(head)
            base = re.sub(r"\s*\*\d*$", "", head).strip()   # "Foo *64" -> "Foo"
            if base:
                self.exact.add(base)
            n_bytes = None
            for p in parts:
                m = re.match(r"^(\d+)\s+bytes$", p)
                if m:
                    n_bytes = int(m.group(1))
            if n_bytes is not None:
                self.size.setdefault(head, n_bytes)
                if base:
                    self.size.setdefault(base, n_bytes)
        self.leaf_counts: Counter = Counter(n.split("::")[-1] for n in self.exact)
        self.by_leaf: dict[str, str] = {}
        for n in self.exact:
            self.by_leaf.setdefault(n.split("::")[-1], n)

        # Ghidra keeps the RE:: namespace inside template arguments; the pipeline's names do
        # not. `NiPointer<TESObjectREFR>` and `NiPointer<RE::TESObjectREFR>` (8 bytes, a real
        # layout) are the same type. Canonicalising both sides recovers those -- and unlike
        # the leaf fallback this is a normalisation, not a guess, so it is trusted as exact.
        # Kept honest by dropping any key two different types canonicalise onto.
        norm_hits: dict[str, list[str]] = {}
        for n in self.exact:
            norm_hits.setdefault(self._canon(n), []).append(n)
        self.by_norm = {k: v[0] for k, v in norm_hits.items() if len(v) == 1}

    @staticmethod
    def _canon(name: str) -> str:
        s = re.sub(r"\bRE::", "", name)
        s = re.sub(r"\bconst\b|\bvolatile\b|\bclass\b|\bstruct\b|\benum\b|\bunion\b", " ", s)
        s = s.replace("&", "*")
        return re.sub(r"\s+", "", s)

    def is_placeholder(self, name: str) -> bool:
        """True only when the size is KNOWN and tiny.

        Some entries report their length as `variable` rather than a number (function
        definitions, flexible arrays). Treating an unknown size as 0 would reject those as
        stubs, so absence of a size is explicitly not evidence of one.
        """
        if name in BUILTIN:
            return False
        n = self.size.get(name)
        return n is not None and n <= PLACEHOLDER_MAX_BYTES

    def resolve(self, token: str, loose: bool = False) -> tuple[str | None, int, str]:
        """Map one C++ arg to (ghidra type, pointer depth, match kind).

        C++ references become pointers: Ghidra has no reference type, and in this ABI
        `Foo&` and `Foo*` are the same thing.
        """
        t = token.strip()
        if t in ("...", ""):
            return None, 0, "none"
        stars = t.count("*") + t.count("&")
        t = t.replace("*", " ").replace("&", " ")
        t = re.sub(r"\bconst\b|\bvolatile\b|\bstruct\b|\bclass\b|\benum\b|\bunion\b", " ", t)
        t = re.sub(r"\[[^\]]*\]", " ", t)
        t = re.sub(r"\s+", " ", t).strip()
        if not t:
            return None, 0, "none"

        t = BUILTIN_ALIAS.get(t, t)
        if t in BUILTIN:
            return t, stars, "builtin"
        if t in self.exact and not self.is_placeholder(t):
            return t, stars, "exact"

        hit = self.by_norm.get(self._canon(t))
        if hit and not self.is_placeholder(hit):
            return hit, stars, "normalized"

        bare = re.sub(r"<.*>", "", t).strip()
        if loose and bare in self.exact and not self.is_placeholder(bare):
            return bare, stars, "template"
        return None, stars, "unresolved"


def parse_decompiled_head(code: str) -> tuple[int, str] | None:
    """Return (parameter count, return type) from a decompiled signature line.

    The return type matters as much as the arity. A demangled name carries no return type,
    and setting a prototype REPLACES it -- so emitting a fixed `undefined8` would throw away
    whatever the decompiler worked out (`bool`, `longlong *`, `undefined1 *` ...). Observed
    in a review sample: most functions already have something better than undefined8. So we
    read it here and put it back unchanged.
    """
    head = code.split("{", 1)[0]
    head = re.sub(r"/\*.*?\*/", " ", head, flags=re.S)      # drop WARNING banners
    head = re.sub(r"\s+", " ", head).strip()
    m = re.search(r"\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*$", head)
    if not m:
        return None
    inner = m.group(1).strip()
    arity = 0 if inner in ("", "void") else len(split_top_level(inner))

    # everything before the function name is the return type
    decl = head[: m.start()].strip()
    parts = decl.rsplit(" ", 1)
    ret = parts[0].strip() if len(parts) == 2 else ""
    if parts and len(parts) == 2 and parts[1].startswith("*"):
        ret = (parts[0] + " *").strip()
    ret = re.sub(r"\s+", " ", ret)
    # A bare identifier means the decompiler gave no return type at all.
    if not ret or ret in ("__thiscall", "__fastcall", "__cdecl", "__stdcall"):
        ret = "undefined8"
    return arity, ret


# ---------------------------------------------------------------- phases


def cache_path(args, name: str) -> str:
    return os.path.join(args.cache_dir, name)


def phase_fetch(args) -> None:
    os.makedirs(args.cache_dir, exist_ok=True)
    print("fetching function list ...")
    funcs = json.loads(_get(f"{args.url}/list_functions", timeout=900))["functions"]
    with open(cache_path(args, "functions.json"), "w", encoding="utf-8") as fh:
        json.dump(funcs, fh)
    print(f"  {len(funcs):,} functions")

    print("fetching data types ...")
    types = json.loads(_get(f"{args.url}/list_data_types?limit=200000", timeout=900))["data_types"]
    with open(cache_path(args, "types.json"), "w", encoding="utf-8") as fh:
        json.dump(types, fh)
    print(f"  {len(types):,} data types")


def load_candidates(args):
    """Functions whose name carries a signature, with types resolved."""
    with open(cache_path(args, "functions.json"), encoding="utf-8") as fh:
        funcs = json.load(fh)
    with open(cache_path(args, "types.json"), encoding="utf-8") as fh:
        index = TypeIndex(json.load(fh))

    out = []
    for f in funcs:
        name = f.get("name", "")
        if name.startswith("FUN_") or "(" not in name:
            continue
        m = SIG_RE.match(name)
        if not m:
            continue
        cls, member = split_qualifier(m.group("qual"))
        raw_args = [a for a in split_top_level(m.group("args")) if a.strip() not in ("", "void")]
        resolved = [index.resolve(a, loose=args.loose) for a in raw_args]
        cls_type = None
        if cls:
            # Try the FULL templated name first. Stripping <...> straight away lands on the
            # bare template, which is a 1-byte stub -- so BSTArray<Foo,Bar>::Method got
            # `void * this` even though BSTArray<RE::Foo,RE::Bar> exists with a real 24-byte
            # layout. Only fall back to the bare name when the instantiation is absent.
            cls_type, _, _ = index.resolve(cls, loose=args.loose)
            if cls_type is None:
                cls_type, _, _ = index.resolve(re.sub(r"<.*>", "", cls).strip(), loose=args.loose)
        out.append({
            "address": f["address"],
            "name": name,
            "cls": cls,
            "cls_type": cls_type,
            "member": member,
            "args": raw_args,
            "resolved": resolved,
            "n_args": len(raw_args),
        })
    return out, index


def phase_probe(args) -> None:
    """Learn this-ness by decompiling. Slow; resumable; safe to interrupt."""
    cands, _ = load_candidates(args)
    path = cache_path(args, "arity.json")
    known: dict[str, int] = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            known = json.load(fh)
        print(f"resuming: {len(known):,} already probed")

    # An entry cached before return-type capture is an int, not a record. Those still need
    # re-probing: the return type is not recoverable from the arity alone.
    def needs_probe(addr: str) -> bool:
        v = known.get(addr)
        return v is None or isinstance(v, int)

    todo = [c for c in cands if needs_probe(c["address"])]
    if args.from_plan:
        plan_file = cache_path(args, "plan.json")
        if not os.path.exists(plan_file):
            raise SystemExit("--from-plan needs plan.json; run `report` first.")
        with open(plan_file, encoding="utf-8") as fh:
            wanted = {row["address"] for row in json.load(fh)}
        todo = [c for c in todo if c["address"] in wanted]
        print(f"restricted to the {len(wanted):,} addresses already in the plan")
    if args.only_resolvable:
        todo = [c for c in todo if all(r[0] for r in c["resolved"])]
    if args.limit:
        todo = todo[: args.limit]
    print(f"probing {len(todo):,} of {len(cands):,} candidates "
          f"(~{len(todo) * 0.35 / 60:.0f} min at 350 ms each)")

    start = time.time()
    dropped = 0
    unparsed = 0
    for i in range(0, len(todo), args.batch):
        chunk = todo[i:i + args.batch]
        q = ",".join("0x" + c["address"] for c in chunk)
        try:
            body = json.loads(_get(f"{args.url}/decompile_function?functions={q}", timeout=900))
        except Exception as exc:                       # noqa: BLE001 - report and continue
            print(f"  batch at {i} failed: {exc}")
            continue

        # /decompile_function silently caps a batch at DECOMPILE_BATCH_CAP and drops the
        # tail with no error -- ask for 25 and exactly 20 come back. Never trust the
        # response to cover the request: re-fetch anything missing one at a time, so a
        # future change to the cap degrades speed rather than coverage.
        missing = [c for c in chunk if ("0x" + c["address"]) not in body and c["address"] not in body]
        for c in missing:
            dropped += 1
            try:
                single = json.loads(_get(f"{args.url}/decompile_function?address=0x{c['address']}", timeout=300))
                body["0x" + c["address"]] = single.get("decompiled", single)
            except Exception:                          # noqa: BLE001
                pass

        for c in chunk:
            entry = body.get("0x" + c["address"], body.get(c["address"]))
            code = entry.get("decompiled") if isinstance(entry, dict) else entry
            parsed = parse_decompiled_head(code) if isinstance(code, str) else None
            if parsed is None:
                unparsed += 1
            else:
                known[c["address"]] = {"arity": parsed[0], "ret": parsed[1]}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(known, fh)
        done = i + len(chunk)
        rate = done / max(time.time() - start, 1e-6)
        print(f"  {done:,}/{len(todo):,}  ({rate:.1f}/s, "
              f"{(len(todo) - done) / max(rate, 1e-6) / 60:.0f} min left)", flush=True)

    if dropped:
        print(f"  note: {dropped:,} were dropped from batch responses and re-fetched singly "
              f"(server caps a batch at {DECOMPILE_BATCH_CAP})")
    if unparsed:
        print(f"  note: {unparsed:,} decompiled but their signature line did not parse -- "
              f"these stay unprobed and will be skipped as Tier 3")
    print(f"probed {len(known):,} total -> {path}")


def probe_entry(arity: dict, address: str) -> tuple[int, str] | None:
    """Read one probe record, tolerating the older arity-only cache format."""
    v = arity.get(address)
    if v is None:
        return None
    if isinstance(v, int):                    # pre-return-type cache
        return v, "undefined8"
    return v.get("arity"), v.get("ret", "undefined8")


def classify(c: dict, arity: dict) -> tuple[str, str]:
    """Return (tier, reason). Tier 1 = safe to apply, 3 = skip."""
    rec = probe_entry(arity, c["address"])
    inferred = rec[0] if rec else None
    all_ok = all(r[0] for r in c["resolved"])
    some_ok = any(r[0] for r in c["resolved"]) or c["n_args"] == 0

    if c["cls"] is None:
        this_kind = "none"                       # free function: no this-pointer
    elif inferred is None:
        return "3", "not probed"
    elif inferred == c["n_args"] + 1:
        this_kind = "this"                       # decisive: an extra register param
    elif inferred > c["n_args"] + 1:
        return "3", "inferred arity exceeds args+1"
    else:
        return "3", "ambiguous this-ness (static, or unused arg)"

    if all_ok:
        return "1", this_kind
    if some_ok:
        return "2", this_kind
    return "3", "no argument type resolves"


def build_prototype(c: dict, this_kind: str, fill_unresolved: bool,
                    ret: str = "undefined8") -> str | None:
    """Compose a prototype Ghidra's parser will accept.

    `ret` is the decompiler's OWN current return type, carried through unchanged. The name
    carries no return type, and applying a prototype replaces whatever is there -- so a
    hardcoded `undefined8` would silently downgrade functions the decompiler had already
    typed as `bool`, `longlong *`, `undefined1 *` and so on.
    """
    params: list[str] = []
    if this_kind == "this":
        this_type = c["cls_type"] or "void"
        params.append(f"{this_type} * this")
    for i, (tok, res) in enumerate(zip(c["args"], c["resolved"])):
        ty, stars = res[0], res[1]
        if ty is None:
            if not fill_unresolved:
                return None
            # Unknown aggregate -> an opaque pointer. `void *` is honest; a wrong named
            # struct would make the decompiler confidently misreport field offsets.
            ty, stars = "void", max(stars, 1)
        params.append(f"{ty} {'*' * stars} a_{i}".replace("  ", " "))
    inner = ", ".join(params) if params else "void"
    return f"{ret} {sanitize_identifier(c['member'])}({inner})"


def phase_report(args) -> None:
    cands, _ = load_candidates(args)
    arity: dict[str, int] = {}
    p = cache_path(args, "arity.json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as fh:
            arity = json.load(fh)

    tiers = Counter()
    reasons = Counter()
    plan = []
    for c in cands:
        tier, reason = classify(c, arity)
        tiers[tier] += 1
        if tier == "3":
            reasons[reason] += 1
            continue
        rec = probe_entry(arity, c["address"])
        proto = build_prototype(c, reason, fill_unresolved=(tier == "2"),
                                ret=(rec[1] if rec else "undefined8"))
        if proto is None:
            tiers[tier] -= 1
            tiers["3"] += 1
            reasons["prototype could not be composed"] += 1
            continue
        plan.append({
            "address": c["address"], "name": c["name"], "tier": tier,
            "this": reason, "prototype": proto,
        })

    out = cache_path(args, "plan.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(plan, fh, indent=1)

    kinds = Counter()
    for c in cands:
        for r in c["resolved"]:
            kinds[r[2]] += 1

    print(f"candidates            : {len(cands):,}")
    print(f"  probed for this-ness: {len(arity):,}")
    print()
    print("argument type resolution (all candidates):")
    for k, n in kinds.most_common():
        print(f"    {n:7,}  {k}")
    print()
    print(f"TIER 1 (all args typed) : {tiers['1']:,}")
    print(f"TIER 2 (some args void*): {tiers['2']:,}")
    print(f"TIER 3 (skipped)        : {tiers['3']:,}")
    for r, n in reasons.most_common():
        print(f"    {n:6,}  {r}")
    print()
    print(f"plan written to {out}  ({len(plan):,} prototypes)")
    print()
    print("sample:")
    for row in plan[:12]:
        print(f"  [{row['tier']}] {row['name'][:64]}")
        print(f"       {row['prototype'][:120]}")


def phase_apply(args) -> None:
    with open(cache_path(args, "plan.json"), encoding="utf-8") as fh:
        plan = json.load(fh)
    if args.tier:
        plan = [p for p in plan if p["tier"] == args.tier]
    if args.limit:
        plan = plan[: args.limit]

    if not args.apply:
        print(f"DRY RUN over {len(plan):,} prototypes -- validating only, nothing is written.")
    else:
        print(f"APPLYING {len(plan):,} prototypes. Journal: {cache_path(args, 'journal.jsonl')}")

    ok = bad = failed = 0
    jpath = cache_path(args, "journal.jsonl")
    journal = open(jpath, "a", encoding="utf-8") if args.apply else None
    try:
        for i, row in enumerate(plan):
            q = urllib.parse.urlencode({
                "function_address": "0x" + row["address"],
                "prototype": row["prototype"],
                "calling_convention": args.calling_convention,
            })
            try:
                v = json.loads(_get(f"{args.url}/validate_function_prototype?{q}", timeout=120))
            except Exception as exc:                   # noqa: BLE001
                failed += 1
                continue
            if not v.get("valid"):
                bad += 1
                if bad <= 8:
                    print(f"  INVALID {row['name'][:60]}\n          {row['prototype'][:110]}\n          {v}")
                continue
            ok += 1
            if args.apply:
                try:
                    res = _post(f"{args.url}/set_function_prototype", {
                        "function_address": "0x" + row["address"],
                        "prototype": row["prototype"],
                        "calling_convention": args.calling_convention,
                    }, timeout=120)
                    journal.write(json.dumps({**row, "result": json.loads(res)}) + "\n")
                    # Flush every line. The journal is the ONLY record of what was written
                    # to the database, so buffering it means a crash loses exactly the
                    # information needed to know how far the run got -- which is the one
                    # job it has. Observed: default buffering held ~280 entries back.
                    journal.flush()
                    os.fsync(journal.fileno())
                except Exception as exc:               # noqa: BLE001
                    failed += 1
            if (i + 1) % 250 == 0:
                print(f"  {i + 1:,}/{len(plan):,}  valid={ok:,} invalid={bad:,} errors={failed:,}",
                      flush=True)
    finally:
        if journal:
            journal.close()

    print()
    print(f"validated OK : {ok:,}")
    print(f"rejected     : {bad:,}")
    print(f"errors       : {failed:,}")
    if not args.apply:
        print("\nNothing was written. Re-run with --apply to commit.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("phase", choices=["fetch", "probe", "report", "apply"])
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--cache-dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".proto-cache"))
    ap.add_argument("--limit", type=int, default=0, help="cap how many to process (probe/apply)")
    ap.add_argument("--batch", type=int, default=DECOMPILE_BATCH_CAP,
                    help=f"functions per decompile request (probe); server caps at {DECOMPILE_BATCH_CAP}")
    ap.add_argument("--only-resolvable", action="store_true",
                    help="probe only functions whose arg types all resolve -- the Tier 1 shortlist")
    ap.add_argument("--from-plan", action="store_true",
                    help="probe only addresses already in plan.json (cheap way to top up an "
                         "existing plan without re-probing the whole corpus)")
    ap.add_argument("--tier", choices=["1", "2"], help="restrict apply to one tier")
    ap.add_argument("--loose", action="store_true",
                    help="also accept a templated type's BASE name (BSTSmartPointer for "
                         "BSTSmartPointer<Foo,Bar>). Off by default: those are usually "
                         "1-byte placeholder stubs, and a wrong struct is worse than none.")
    ap.add_argument("--calling-convention", default="__fastcall")
    ap.add_argument("--apply", action="store_true", help="actually write (default is a dry run)")
    args = ap.parse_args()

    os.makedirs(args.cache_dir, exist_ok=True)
    {"fetch": phase_fetch, "probe": phase_probe, "report": phase_report, "apply": phase_apply}[args.phase](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
