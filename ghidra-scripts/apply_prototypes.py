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

    fetch    pull the function list and the data-type index, and     (~20 s)
             stamp the cache with WHICH program they came from
    probe    decompile candidates to learn this-ness -- SLOW,        (~150 min for the full
             ~347 ms/function, resumable, safe to interrupt           corpus; --limit to trim)
    report   tier everything and write the proposed prototypes       (instant)
    apply    validate then set, journalling every outcome            (~50 ms/function)

Dry-run is the default. `apply` requires --apply, and even then validates every prototype
against Ghidra's own parser first.

A plan is bound to the program it was built from and will not be applied to a different one.
The server serves whatever project setup\\36-ghidra-mcp.ps1 last loaded, and an address means
nothing without the program it indexes. --ignore-program-mismatch overrides that.

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


# ---------------------------------------------------------------- which program is this?

# NOTHING ELSE BINDS A PLAN TO A PROGRAM. The cache is a fixed .proto-cache directory with no
# program in its name; a plan row carries only address/name/tier/this/prototype; and
# /set_function_prototype takes an ADDRESS, so it writes into whatever 127.0.0.1:8089 happens
# to be serving at the moment the POST lands. setup\36-ghidra-mcp.ps1 prints "Use -Stop first
# if you need to change the loaded project or program" -- which is the sentence that admits
# the loaded program can differ between the report and the apply. A plan applied to the wrong
# program writes 13,108 prototypes at addresses that mean something else there, and every one
# of them is counted APPLIED, because the server really did apply them.
#
# So `fetch` records who the server said it was, `report` copies that into the plan, and
# `apply` reads it back and compares. The fields are split in two on purpose:
#
#   IDENTITY  must be identical, or the addresses index a different thing. base_address is
#             here because a rebase moves every address in the plan while the program name
#             stays the same; language/compiler/address_size because a plan for one
#             architecture is meaningless on another.
#   DRIFT     legitimately changes as analysis continues in the SAME program. Re-running
#             auto-analysis or importing more names moves function_count and symbol_count
#             without invalidating a single address the plan already holds, so a difference
#             here is reported and never refused on.
PROGRAM_IDENTITY_KEYS = ("program_name", "executable_path", "language", "compiler",
                         "address_size_bits", "base_address")
PROGRAM_DRIFT_KEYS = ("function_count", "symbol_count")


def read_program_fingerprint(url: str) -> dict:
    """Ask the server which program it is serving. Raises SystemExit if it will not say.

    /get_metadata answers a FLAT object -- program_name, executable_path, base_address,
    function_count and the rest -- or {"error":"No program loaded."}; it is not the
    {"data":...} envelope some other endpoints use. setup\\36-ghidra-mcp.ps1 reads the same
    endpoint the same way.

    An answer we cannot read is NOT turned into a fingerprint. Recording {} and then comparing
    {} against {} at apply time would pass every check while proving nothing -- which is
    exactly the false "all clear" this record exists to prevent.
    """
    try:
        meta = json.loads(_get(f"{url}/get_metadata", timeout=120))
    except Exception as exc:                           # noqa: BLE001 - any failure is the same
        raise SystemExit(f"ERROR: {url}/get_metadata did not answer ({exc}), so which program "
                         f"is being served is unknown and nothing can be bound to it.")
    if not isinstance(meta, dict) or not meta.get("program_name"):
        raise SystemExit(f"ERROR: {url}/get_metadata reports no program: {str(meta)[:200]}\n"
                         f"       Start the server with one: "
                         f"setup\\36-ghidra-mcp.ps1 -Start -Program <path in project>")
    fp = {k: meta.get(k) for k in PROGRAM_IDENTITY_KEYS + PROGRAM_DRIFT_KEYS}
    fp["read_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    return fp


def fingerprint_differences(recorded: dict, live: dict) -> list[str]:
    """The identity fields on which the served program disagrees with a recorded one.

    Returns display lines, because a refusal that says only "mismatch" sends the operator
    hunting for which of six fields moved.
    """
    out = []
    for k in PROGRAM_IDENTITY_KEYS:
        was, now = recorded.get(k), live.get(k)
        if was != now:
            out.append(f"    {k}: recorded {was!r}  server {now!r}")
    return out


def verify_served_program(args, recorded: dict | None, source: str,
                          unstamped_is_fatal: bool, refusal: str) -> dict:
    """Refuse to continue against a program that is not the one `recorded` describes.

    `source` names the file the recorded fingerprint came from and `refusal` is what going on
    regardless would actually do wrong, both spelled by the caller: a refusal that says only
    "mismatch" leaves the operator to work out which phase was about to damage what.

    `unstamped_is_fatal` says whether a MISSING fingerprint is itself a refusal. It is for
    `apply`, which writes to a database that took hours to build (and the message below is
    written for that caller). It is not for `probe`, which writes only to a cache you can
    delete -- refusing there would cost a ~150-minute re-probe to protect nothing.

    Returns the live fingerprint, so callers can record what they actually saw.
    """
    live = read_program_fingerprint(args.url)
    label = (f"{live.get('program_name')}  (base {live.get('base_address')}, "
             f"{live.get('function_count')} functions)")

    if recorded is None:
        print(f"program: {label}")
        print(f"  {source} carries no fingerprint of the program it was built from, so there is")
        print("  nothing to compare and no way to tell whether its addresses index THIS program.")
        if unstamped_is_fatal:
            if not args.ignore_program_mismatch:
                raise SystemExit(
                    "  Refusing. Re-run `fetch` then `report` to stamp it -- ~20 s, and it\n"
                    "  rebuilds only functions.json, types.json and plan.json; the probe cache\n"
                    "  (arity.json, the ~150-minute one) is not touched. Or pass\n"
                    "  --ignore-program-mismatch to apply it unchecked.")
            print("  --ignore-program-mismatch given; continuing unchecked.")
        else:
            print("  Continuing: this phase writes only to the cache, never to the database.")
        return live

    diffs = fingerprint_differences(recorded, live)
    if diffs:
        print(f"program: {label}")
        print(f"  This is NOT the program {source} was built from:")
        for d in diffs:
            print(d)
        if not args.ignore_program_mismatch:
            raise SystemExit(f"  Refusing: {refusal}\n"
                             f"  Pass --ignore-program-mismatch if you know better.")
        print("  --ignore-program-mismatch given; continuing anyway.")
        return live

    print(f"program: {label} -- matches {source}, stamped {recorded.get('read_at', 'unknown')}")
    drift = [f"{k} {recorded.get(k)} -> {live.get(k)}"
             for k in PROGRAM_DRIFT_KEYS if recorded.get(k) != live.get(k)]
    if drift:
        print(f"  it has been analysed further since ({', '.join(drift)}). Not a refusal: adding")
        print("  functions or symbols does not move an address the plan already holds.")
    return live


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


# Names Ghidra's SIGNATURE PARSER cannot resolve, and what to use instead.
#
# This is not about missing types -- it is about AMBIGUOUS ones. Importing CommonLibF4
# created a second definition of several primitives, so the program holds both `/bool` and
# `/CommonLibF4/bool`, both `/wchar_t` (2 bytes) and `/CommonLibF4/wchar_t` (1 byte, a
# stub). Faced with two, the parser refuses rather than guessing -- which is the right call,
# since picking `/CommonLibF4/int` (1 byte) over `/int` (4 bytes) would silently truncate
# every int parameter in the program.
#
# The trap is that `bool` is exactly what Ghidra's own decompiler reports as an inferred
# return type, so echoing its inference straight back fails. Measured: 1,904 of 2,027 apply
# failures were `bool` or `bool *`.
#
# A qualified path does NOT help -- "/bool" fails the same way. Verified against the live
# program: bool FAIL, /bool FAIL, byte OK, uchar OK, undefined1 OK, wchar_t FAIL,
# wchar16 OK, __int64 FAIL, longlong OK, ulonglong OK.
#
# Where an exact-width equivalent exists it is used (no information lost). For `bool` there
# is no unambiguous boolean, so it maps to undefined1 -- Ghidra treats `undefined*` as
# "this many bytes, please infer", which lets the decompiler recover bool-ness itself
# rather than being pinned to a wrong concrete type.
PARSER_SAFE = {
    "bool": "undefined1",
    "wchar_t": "wchar16",
    "__int64": "longlong",
    "unsigned __int64": "ulonglong",
    "unsigned___int64": "ulonglong",
    "__int32": "int",
    "__int16": "short",
    "__int8": "char",
}


def parser_safe(type_name: str) -> str:
    """Rewrite a type name into one Ghidra's signature parser will accept."""
    t = type_name.strip()
    m = re.match(r"^(.*?)(\s*\**)$", t)
    base, ptr = (m.group(1).strip(), m.group(2).replace(" ", "")) if m else (t, "")
    fixed = PARSER_SAFE.get(base, base)
    return (fixed + " " + ptr).strip() if ptr else fixed


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


def read_cached_fingerprint(args) -> dict | None:
    """The program `fetch` recorded for this cache directory, or None if it never did.

    None means "unstamped", which is a different claim from "matches" and is reported as such
    everywhere it is used -- a cache built before this script recorded a program cannot be
    quietly assumed to be a cache of the right one.
    """
    p = cache_path(args, "program.json")
    if not os.path.exists(p):
        return None
    try:
        with open(p, encoding="utf-8") as fh:
            fp = json.load(fh)
    except ValueError as exc:
        print(f"  note: {p} will not parse ({exc}); treating this cache as unstamped.")
        return None
    return fp if isinstance(fp, dict) else None


def load_plan(args) -> tuple[list, dict | None]:
    """Read plan.json, tolerating the pre-fingerprint shape.

    `report` used to write a bare JSON LIST of rows and now writes
    {"program": <fingerprint>, "generated": ..., "rows": [...]}, so the plan carries the
    program it was built from. A list on disk is therefore an OLD plan: it is read normally,
    and its missing fingerprint is reported as MISSING rather than being read as "nothing
    differs" -- an unverifiable plan and a verified one must not look alike.
    """
    with open(cache_path(args, "plan.json"), encoding="utf-8") as fh:
        doc = json.load(fh)
    if isinstance(doc, list):
        return doc, None
    return doc.get("rows", []), doc.get("program")


def phase_fetch(args) -> None:
    os.makedirs(args.cache_dir, exist_ok=True)

    # Stamp the cache with the program it is a cache OF, before anything is pulled into it.
    # Refuse to re-fetch over another program's cache: functions.json and types.json would be
    # overwritten while arity.json (the ~150-minute probe cache) and plan.json stayed keyed to
    # the OLD program's addresses, and `report` would then tier one program's functions using
    # another program's decompiled arities without a word.
    previous = read_cached_fingerprint(args)
    fp = read_program_fingerprint(args.url)
    if previous is not None:
        diffs = fingerprint_differences(previous, fp)
        if diffs and not args.ignore_program_mismatch:
            raise SystemExit(
                f"ERROR: {args.cache_dir} was fetched from a different program:\n"
                + "\n".join(diffs) + "\n"
                "       Fetching here would leave the probe cache and any plan keyed to the\n"
                "       old program's addresses. Use --cache-dir <dir> for this program, or\n"
                "       --ignore-program-mismatch to overwrite this one.")
        if diffs:
            print("--ignore-program-mismatch given; overwriting a cache of a different program.")
    with open(cache_path(args, "program.json"), "w", encoding="utf-8") as fh:
        json.dump(fp, fh, indent=1)
    print(f"program: {fp.get('program_name')}  (base {fp.get('base_address')}, "
          f"{fp.get('function_count')} functions per /get_metadata)")

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
    # arity.json is keyed by ADDRESS and merged with whatever is already there, so probing
    # against a different program than the one this cache was fetched from silently mixes two
    # programs' decompiler arities into one file -- and `report` then decides this-ness, the
    # one decision that shifts every parameter when it is wrong, from the wrong program's
    # registers. Checked before the ~150-minute loop starts rather than after it.
    verify_served_program(
        args, read_cached_fingerprint(args), "program.json", unstamped_is_fatal=False,
        refusal="this cache would be topped up with a different program's decompiled\n"
                "  arities, keyed by address, and `report` would then decide this-ness from\n"
                "  them. Use --cache-dir <dir> for this program, or re-run `fetch` here.")
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
        wanted = {row["address"] for row in load_plan(args)[0]}
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
        params.append(f"{parser_safe(ty)} {'*' * stars} a_{i}".replace("  ", " "))
    inner = ", ".join(params) if params else "void"
    return f"{parser_safe(ret)} {sanitize_identifier(c['member'])}({inner})"


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

    # The plan carries the program it was built from. `report` is deliberately offline -- it
    # is the one phase that needs no server -- so it copies the fingerprint `fetch` recorded
    # rather than asking again; an address in this plan came from that fetch, not from
    # whatever happens to be loaded now.
    fp = read_cached_fingerprint(args)
    out = cache_path(args, "plan.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"program": fp, "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   "rows": plan}, fh, indent=1)

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
    if fp is None:
        print("  NOTE: this cache carries no program fingerprint, so nothing binds the plan to")
        print("        the program it was built from and `apply` will refuse it. Re-run `fetch`")
        print("        then `report` to stamp it (~20 s; the probe cache is not touched).")
    else:
        print(f"  built from {fp.get('program_name')} (base {fp.get('base_address')}), "
              f"fetched {fp.get('read_at', 'unknown')}")
    print()
    print("sample:")
    for row in plan[:12]:
        print(f"  [{row['tier']}] {row['name'][:64]}")
        print(f"       {row['prototype'][:120]}")


# What a journal line says happened to ONE planned row. --retry-failed retries everything that
# is not "applied", which is the only honest reading of the set: "applied" is the sole outcome
# the server confirmed reached the database.
#
#   applied            /set_function_prototype answered status=success
#   rejected-on-apply  it answered, and refused -- usually "Can't resolve datatype"
#   invalid            /validate_function_prototype refused it; no write was attempted
#   error-validate     the validate GET raised; nothing was attempted
#   stale-row          the address no longer carries the function the prototype came from
#   unknown            the apply POST raised, or answered something unreadable -- the write MAY
#                      have landed. A POST that times out after Ghidra has already committed
#                      the transaction is indistinguishable from one that never arrived, so it
#                      is recorded as unknown rather than flattened into a failure. Retrying it
#                      is safe: setting the same prototype twice is idempotent.
OUTCOME_APPLIED = "applied"

# More than this share of rows naming a different function is not per-row drift -- it is a plan
# built against a different STATE of the same program, and applying the remainder would write a
# mostly-wrong plan while reporting a tidy APPLIED count for the minority that happened to still
# match. The number is a judgement, not a measurement: re-analysis moves a handful of functions,
# while a re-import of names moves most of them. --ignore-program-mismatch overrides it.
STALE_ROW_REFUSAL_FRACTION = 0.25


def phase_apply(args) -> None:
    plan, plan_fp = load_plan(args)

    # WHICH PROGRAM, before a single POST -- see the section at the top of this file. A dry run
    # is held to the same check on purpose: it exists to PREDICT what an apply would do to the
    # served program, and a validation report about a different program is worse than none.
    live_fp = verify_served_program(
        args, plan_fp, "plan.json", unstamped_is_fatal=True,
        refusal="every address in that plan indexes the program it was built from, so\n"
                "  applying it here would write prototypes into whatever THIS program holds at\n"
                "  those addresses -- and the server would report every one of them as applied.\n"
                "  Re-run `fetch` and `report` against this program (~20 s).")

    if args.retry_failed:
        # Re-run only what the journal RECORDS as not applied. Uses the CURRENT plan, so a fix
        # to type mapping or this-detection is picked up; re-applying a success would be
        # harmless but wastes ~250 ms each, and there are usually far more of those.
        #
        # This set is only ever as complete as the journal, which is why every outcome is
        # written to it now. A prototype rejected at VALIDATION used to leave no line at all,
        # so the very fix this flag exists to retry -- a type mapping that makes it valid --
        # could never reach it: the retry run printed "retrying 0 that did not apply" and an
        # all-zero summary over hundreds of functions that had never been written.
        jpath = cache_path(args, "journal.jsonl")
        if not os.path.exists(jpath):
            raise SystemExit("--retry-failed needs journal.jsonl; nothing has been applied yet.")
        last: dict[str, str] = {}
        pre_outcome = 0
        with open(jpath, encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                addr = rec.get("address")
                if not addr:
                    continue                           # a run header, not a row
                outcome = rec.get("outcome")
                if outcome is None:
                    # A line from a journal written before outcomes were recorded. Its
                    # result.status still says whether it applied, so it is read rather than
                    # discarded -- but a journal of that vintage is SILENT about rows that
                    # failed validation or errored, and that silence is indistinguishable from
                    # "never attempted". Counted here and reported below rather than papered
                    # over, because it changes what this retry set can possibly contain.
                    pre_outcome += 1
                    outcome = (OUTCOME_APPLIED
                               if (rec.get("result") or {}).get("status") == "success"
                               else "rejected-on-apply")
                last[addr] = outcome                   # a later line supersedes an earlier one
        not_applied = {a: o for a, o in last.items() if o != OUTCOME_APPLIED}
        planned = {p["address"] for p in plan}
        plan = [p for p in plan if p["address"] in not_applied]
        print(f"retrying {len(plan):,} that the journal records as not applied")
        for outcome, n in Counter(not_applied[p["address"]] for p in plan).most_common():
            print(f"    {n:6,}  {outcome}")
        unseen = len(planned - set(last))
        if unseen:
            print(f"  note: {unseen:,} plan rows appear in NO journal line -- never attempted:")
            print("        an interrupted run, or an earlier --tier/--limit. --retry-failed does")
            print("        not pick those up; a plain `apply --apply` run does.")
        dropped = len(set(not_applied) - planned)
        if dropped:
            print(f"  note: {dropped:,} more are recorded as not applied but are no longer in the")
            print("        plan -- a later `report` moved them to Tier 3, say. Not retried here.")
        if pre_outcome:
            print(f"  note: {pre_outcome:,} journal lines predate per-outcome recording. Applied")
            print("        vs not-applied still reads out of them, but rows that failed VALIDATION")
            print("        were not journalled at all then, so they land in the 'never attempted'")
            print("        count above instead of in this retry set. A plain run sweeps them up.")
    if args.tier:
        plan = [p for p in plan if p["tier"] == args.tier]
    if args.limit:
        plan = plan[: args.limit]

    # ROW-LEVEL binding. The fingerprint above catches "a different program is loaded"; it
    # cannot catch the RIGHT program re-analysed since the plan was built, where a function was
    # renamed, deleted, or its entry point moved. /set_function_prototype takes an address, so
    # that row would be written over whatever now sits there and reported as applied.
    #
    # /validate_function_prototype cannot answer this -- it returns {"valid":...} and an error
    # string, never the function's name. /get_function_by_address can, but costs an extra round
    # trip per row: ~13,100 of them, doubling a ~50 ms/function run. One /list_functions (the
    # same unpaginated call `fetch` makes, ~20 s for 216,891 functions) answers it for every row
    # at once, so that is what this does.
    current_names: dict[str, str] = {}
    row_check = True
    try:
        listed = json.loads(_get(f"{args.url}/list_functions", timeout=900))["functions"]
        current_names = {f["address"]: f.get("name", "") for f in listed}
    except Exception as exc:                           # noqa: BLE001 - report and carry on
        row_check = False
        print(f"WARNING: /list_functions did not answer ({exc}), so NO row was checked against")
        print("         the function its prototype was derived from. The program-level")
        print("         fingerprint above did match, so this run is still bound to the right")
        print("         program -- but a function renamed or removed since the plan was built")
        print("         will be written at its old address without notice.")

    stale: dict[str, tuple[str, str | None]] = {}
    if row_check:
        for row in plan:
            now = current_names.get(row["address"])
            if now != row["name"]:
                stale[row["address"]] = (row["name"], now)
        print(f"rows   : {len(plan) - len(stale):,} of {len(plan):,} still carry the function "
              f"their prototype was derived from")
        for addr, (was, now) in list(stale.items())[:5]:
            print(f"    {addr}  plan: {was[:70]}")
            print(f"    {' ' * len(addr)}   now: "
                  f"{'<no function at that address>' if now is None else now[:70]}")
        if stale and len(stale) > len(plan) * STALE_ROW_REFUSAL_FRACTION \
                and not args.ignore_program_mismatch:
            raise SystemExit(
                f"  Refusing: {len(stale):,} of {len(plan):,} rows name a function that is no\n"
                f"  longer at that address. That is not drift, it is a plan built against a\n"
                f"  different state of this program -- re-run `fetch` and `report` (~20 s) to\n"
                f"  rebuild it, or pass --ignore-program-mismatch to apply the rest anyway.")
        if stale:
            print(f"    {len(stale):,} will be SKIPPED and journalled as stale-row, not applied.")

    if not args.apply:
        print(f"DRY RUN over {len(plan):,} prototypes -- validating only, nothing is written.")
    else:
        print(f"APPLYING {len(plan):,} prototypes. Journal: {cache_path(args, 'journal.jsonl')}")

    ok = bad = failed = 0
    applied = rejected_on_apply = unknown = skipped_stale = 0
    apply_errors: Counter = Counter()
    jpath = cache_path(args, "journal.jsonl")
    journal = open(jpath, "a", encoding="utf-8") if args.apply else None

    # EVERY OUTCOME GOES THROUGH HERE. The journal used to be written only after the apply POST
    # returned and its body parsed, so three of the six ways a row can end -- a validate GET
    # that raised, a prototype the validator rejected, an apply POST that raised or answered
    # unreadably -- left no line at all. A record that is the ONLY record of what happened has
    # to record what happened; --retry-failed reads nothing else.
    #
    # The shape stays readable both ways. An old reader looks at result.status: "applied" lines
    # carry the server's success payload and read as applied, and every other outcome either
    # carries a payload without a status (the validator's {"valid":false}) or none at all, so it
    # reads as not-applied -- which is what it is. Nothing here needs the old journals rewritten.
    #
    # Server answers go in "result", things this script observed go in "detail", so a line never
    # implies the server said something it did not.
    def record(row: dict, outcome: str, result=None, detail=None) -> None:
        if journal is None:
            return
        line = {**row, "outcome": outcome}
        if result is not None:
            line["result"] = result
        if detail is not None:
            line["detail"] = detail
        journal.write(json.dumps(line) + "\n")
        # Flush every line. The journal is the ONLY record of what was written to the database,
        # so buffering it means a crash loses exactly the information needed to know how far
        # the run got -- which is the one job it has. Observed: default buffering held ~280
        # entries back.
        journal.flush()
        os.fsync(journal.fileno())

    try:
        if journal:
            # One header line per run: the rows after it were written to THIS program, at this
            # moment, with the row check either on or off. Readers skip any line without an
            # "address" (the retry loader above does), so journals that only ever held rows
            # still read exactly as before.
            journal.write(json.dumps({
                "event": "apply_run", "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "program": live_fp, "rows": len(plan), "row_name_check": row_check,
                "ignore_program_mismatch": bool(args.ignore_program_mismatch),
            }) + "\n")
            journal.flush()
        for i, row in enumerate(plan):
            if row["address"] in stale:
                skipped_stale += 1
                was, now = stale[row["address"]]
                record(row, "stale-row", detail={"planned_name": was, "current_name": now})
                continue
            q = urllib.parse.urlencode({
                "function_address": "0x" + row["address"],
                "prototype": row["prototype"],
                "calling_convention": args.calling_convention,
            })
            try:
                v = json.loads(_get(f"{args.url}/validate_function_prototype?{q}", timeout=120))
            except Exception as exc:                   # noqa: BLE001
                failed += 1
                record(row, "error-validate", detail={"error": f"{type(exc).__name__}: {exc}"})
                continue
            if not v.get("valid"):
                bad += 1
                if bad <= 8:
                    print(f"  INVALID {row['name'][:60]}\n          {row['prototype'][:110]}\n          {v}")
                # Journalled even though nothing was written: this row did not apply, and
                # --retry-failed exists precisely to re-validate it after the type-mapping fix.
                record(row, "invalid", result=v)
                continue
            ok += 1
            if args.apply:
                try:
                    res = _post(f"{args.url}/set_function_prototype", {
                        "function_address": "0x" + row["address"],
                        "prototype": row["prototype"],
                        "calling_convention": args.calling_convention,
                    }, timeout=120)
                except Exception as exc:               # noqa: BLE001
                    # UNKNOWN, not failed. The POST may have been applied and the answer lost.
                    unknown += 1
                    record(row, "unknown", detail={"error": f"{type(exc).__name__}: {exc}"})
                    continue
                try:
                    parsed_res = json.loads(res)
                    if not isinstance(parsed_res, dict):
                        raise ValueError("answer is not a JSON object")
                except ValueError as exc:
                    unknown += 1
                    record(row, "unknown",
                           detail={"error": f"unreadable answer ({exc})", "body": res[:200]})
                    continue
                # VALIDATION IS NOT A PREDICTION OF APPLICATION. They take different
                # resolution paths: /validate_function_prototype answered {"valid":true}
                # for 2,027 prototypes that /set_function_prototype then rejected with
                # "Can't resolve datatype". Counting only validation reported a clean run
                # while 15.5% of the writes had silently failed -- so the APPLY result is
                # what gets counted here.
                if parsed_res.get("status") == "success":
                    applied += 1
                    record(row, OUTCOME_APPLIED, result=parsed_res)
                else:
                    rejected_on_apply += 1
                    reason = str(parsed_res.get("error", "unknown"))
                    apply_errors[re.sub(r".*resolve (?:return type|datatype): ", "", reason)[:60]] += 1
                    if rejected_on_apply <= 5:
                        print(f"  APPLY FAILED {row['name'][:56]}\n          {reason[:120]}")
                    record(row, "rejected-on-apply", result=parsed_res)
            if (i + 1) % 250 == 0:
                extra = f" APPLIED={applied:,} apply-failed={rejected_on_apply:,}" if args.apply else ""
                if unknown:
                    extra += f" unknown={unknown:,}"
                print(f"  {i + 1:,}/{len(plan):,}  valid={ok:,} invalid={bad:,} errors={failed:,}{extra}",
                      flush=True)
    finally:
        if journal:
            journal.close()

    print()
    if skipped_stale:
        print(f"skipped stale: {skipped_stale:,}  (the address no longer carries that function)")
    print(f"validated OK : {ok:,}")
    print(f"rejected     : {bad:,}")
    print(f"errors       : {failed:,}")
    if args.apply:
        print(f"APPLIED      : {applied:,}")
        print(f"apply-failed : {rejected_on_apply:,}")
        print(f"unknown      : {unknown:,}")
        for reason, n in apply_errors.most_common(10):
            print(f"    {n:6,}  {reason}")
        if rejected_on_apply:
            print("\nThose functions were NOT changed. Their prototypes validated but could not")
            print("be applied -- the two use different type-resolution paths.")
        if unknown:
            print("\nThe unknown ones may or may not have been written: their POST raised or came")
            print("back unreadable, and a request that times out after Ghidra committed the")
            print("transaction looks exactly like one that never arrived. --retry-failed re-applies")
            print("them, which is harmless -- setting the same prototype twice changes nothing.")
    else:
        print("\nNothing was written. Re-run with --apply to commit.")
        print("NOTE: validating is not the same as applying. Some prototypes that validate")
        print("      are still rejected on apply; only --apply reports that.")

    # Every row of this run ended in exactly one of those buckets. If the arithmetic does not
    # close, this script's own bookkeeping is wrong and none of the numbers above can be relied
    # on -- which is the failure that put 2,027 silent write failures behind a clean summary in
    # the first place, so it is asserted rather than assumed.
    accounted = (applied + rejected_on_apply + unknown if args.apply else ok) \
        + bad + failed + skipped_stale
    if accounted != len(plan):
        print(f"\nWARNING: {len(plan):,} rows went through this run but {accounted:,} are")
        print("         accounted for above. The counters do not add up, which is a bug in this")
        print("         script's bookkeeping, not a fact about the program.")


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
    ap.add_argument("--retry-failed", action="store_true",
                    help="apply only the entries the journal shows did not apply")
    ap.add_argument("--ignore-program-mismatch", action="store_true",
                    help="proceed even though the served program is not the one the cache or "
                         "plan was built from. Overrides the four REFUSALS -- fetching over "
                         "another program's cache, probing against one, applying a plan whose "
                         "fingerprint differs or is missing, and applying one where most rows "
                         "name a function that has moved. For the operator who knows the "
                         "difference is harmless: a long job refusing with no way past it is "
                         "its own failure mode. It does NOT force an individual stale row: a "
                         "row whose address no longer carries the function its prototype was "
                         "derived from is skipped either way, because writing that prototype "
                         "over whatever is there now is the corruption, not the mismatch. "
                         "Re-run `fetch` and `report` (~20 s) to rebuild those rows against "
                         "the current names. The mismatch is still printed, and still "
                         "journalled on the run header.")
    args = ap.parse_args()

    os.makedirs(args.cache_dir, exist_ok=True)
    {"fetch": phase_fetch, "probe": phase_probe, "report": phase_report, "apply": phase_apply}[args.phase](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
