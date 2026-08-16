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
