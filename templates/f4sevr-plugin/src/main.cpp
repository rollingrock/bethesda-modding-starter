#include "Settings/Settings.h"

void InitializeLog()
{
	auto path = logger::log_directory();
	const auto gamepath = REL::Module::IsVR() ? "Fallout4VR/F4SE" : "Fallout4/F4SE";
	if (!path.value().generic_string().ends_with(gamepath)) {
		// handle bug where game directory is missing
		path = path.value().parent_path().append(gamepath);
	}

	*path /= fmt::format("{}.log"sv, "starterplugin"sv);
	auto sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(path->string(), true);

	const auto level = spdlog::level::trace;

	auto log = std::make_shared<spdlog::logger>("global log"s, std::move(sink));
	log->set_level(level);
	log->flush_on(level);

	spdlog::set_default_logger(std::move(log));
	spdlog::set_pattern("[%Y-%m-%d %T.%e][%-16s:%-4#][%L]: %v"s);
}

extern "C" DLLEXPORT bool F4SEAPI F4SEPlugin_Query(const F4SE::QueryInterface* a_f4se, F4SE::PluginInfo* a_info)
{
	a_info->infoVersion = F4SE::PluginInfo::kVersion;
	a_info->name = Version::PROJECT.data();
	a_info->version = Version::MAJOR;

	if (a_f4se->IsEditor()) {
		logger::critical("Loaded in editor, marking as incompatible"sv);
		return false;
	}

	// CommonLibF4 dispatches between three runtimes, so gate against the right minimum for
	// whichever one loaded us. A two-way IsF4()/else test gets this wrong: on pre-NG Fallout 4
	// IsF4() is true and comparing against RUNTIME_LATEST (1.10.984, the Next-Gen build)
	// rejects a perfectly supported 1.10.163.
	const auto ver = a_f4se->RuntimeVersion();
	const auto minimum = REL::Module::IsVR()  ? F4SE::RUNTIME_LATEST_VR :  // 1.2.72
	                     REL::Module::IsNG()  ? F4SE::RUNTIME_1_10_984  :  // Next-Gen
	                                            F4SE::RUNTIME_1_10_163;    // pre-NG flat
	if (ver < minimum) {
		logger::critical(FMT_STRING("Unsupported runtime version {}"), ver.string());
		return false;
	}

	return true;
}

// F4SE 0.7.0 replaced the Query/Load handshake with a declarative version record, and by
// 0.7.9 -- the build for Fallout 4 1.11.240 -- the old one is GONE: the string
// "F4SEPlugin_Query" does not occur anywhere in f4se_1_11_240.dll. F4SEVR 1.2.72 is the
// mirror image: it resolves Query and Load and has never heard of F4SEPlugin_Version.
// ONE DLL SERVES BOTH GAMES, so it exports BOTH handshakes and each extender ignores the
// one it does not look for. Export only Query and flat Fallout 4 rejects the plugin before
// a line of its code runs, logging the line f4se.log shows for any versionless DLL:
//     plugin <name>.dll (00000000  00000000) no version data 0 (handle 0)
extern "C" DLLEXPORT constinit auto F4SEPlugin_Version = []() noexcept {
	F4SE::PluginVersionData data{};

	data.PluginVersion(REL::Version{ static_cast<std::uint16_t>(Version::MAJOR),
		static_cast<std::uint16_t>(Version::MINOR),
		static_cast<std::uint16_t>(Version::PATCH), 0 });
	data.PluginName(Version::PROJECT);

	// Set these bits directly rather than through UsesAddressLibrary()/IsLayoutDependent().
	// Those helpers hardcode 1 << 1 -- the 1.10.980-era address library -- and a plugin that
	// offers only that bit is not claiming the Anniversary (1.11.137+) library this runtime
	// actually wants.
	//   1 << 1 = address library / struct layout for the 1.10.980 family (Next-Gen)
	//   1 << 2 = address library / struct layout for the 1.11.137 family (Anniversary)
	// Declaring both is what a CommonLibF4 plugin IS: every offset it resolves goes through
	// Data\F4SE\Plugins\version-<runtime>.bin, and CommonLibF4 picks that filename from the
	// version of the binary that actually loaded it -- see REL/IDDB.cpp.
	data.addressIndependence = (1u << 1) | (1u << 2);
	data.structureIndependence = (1u << 1) | (1u << 2);

	// compatibleVersions is deliberately left empty, which means "any runtime". That is the
	// right default for an address-library plugin: the ids resolve to whatever the installed
	// database says, so a new game build works without rebuilding you.
	//
	// If yours reaches into struct FIELDS you have only verified on one build, pin them
	// instead, and F4SE refuses to load you anywhere else rather than letting you read
	// garbage. Construct the version rather than naming a constant --
	//
	//     data.CompatibleVersions({ REL::Version{ 1, 11, 240, 0 } });
	//
	// because CommonLibF4's F4SE::RUNTIME_* constants stop at RUNTIME_1_10_984 and there is
	// no RUNTIME_1_11_240 to name. That gap is the same one behind the two bits set above.

	return data;
}();

extern "C" DLLEXPORT bool F4SEAPI F4SEPlugin_Load(const F4SE::LoadInterface* a_f4se)
{
	InitializeLog();
	Settings::load();
	F4SE::Init(a_f4se, false);

	// One allocation for ALL hook stubs (14 bytes each) — never per-hook, see the
	// write_thunk_call note in PCH.h. Raise if you add more than ~18 hooks.
	F4SE::AllocTrampoline(256);

	logger::info("{} v{}.{}.{} {} {} is loading"sv, Version::PROJECT, Version::MAJOR, Version::MINOR, Version::PATCH, __DATE__, __TIME__);
	const auto runtimeVer = REL::Module::get().version();
	logger::info("Fallout 4 v{}.{}.{}"sv, runtimeVer[0], runtimeVer[1], runtimeVer[2]);
	logger::info("enableExampleFeature = {}"sv, *Settings::enableExampleFeature);

	// Install hooks here, AFTER the AllocTrampoline call above. Pattern:
	//
	//   struct MyHook
	//   {
	//       static void thunk(RE::SomeType* a_this)
	//       {
	//           // ... your code ...
	//           func(a_this);  // call the original
	//       }
	//       static inline REL::Relocation<decltype(thunk)> func;
	//   };
	//
	//   pstl::write_thunk_call<MyHook>(REL::Offset(0x140XXXXXX - 0x140000000).address());

	logger::info("{} loaded"sv, Version::PROJECT);
	return true;
}
