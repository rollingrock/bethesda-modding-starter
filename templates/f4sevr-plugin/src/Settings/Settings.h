#pragma once

namespace Settings
{
	template <class T>
	class Setting
	{
	public:
		using value_type = T;

		Setting(
			std::string_view a_group,
			std::string_view a_key,
			value_type a_default) noexcept :
			_group(a_group),
			_key(a_key),
			_value(a_default)
		{}

		[[nodiscard]] auto group() const noexcept -> std::string_view { return this->_group; }
		[[nodiscard]] auto key() const noexcept -> std::string_view { return this->_key; }

		template <class Self>
		[[nodiscard]] auto&& get(this Self&& a_self) noexcept
		{
			return std::forward<Self>(a_self)._value;
		}

		template <class Self>
		[[nodiscard]] auto&& operator*(this Self&& a_self) noexcept
		{
			return std::forward<Self>(a_self).get();
		}

	private:
		std::string_view _group;
		std::string_view _key;
		value_type _value;
	};

	using bSetting = Setting<bool>;
	using iSetting = Setting<std::int64_t>;
	using sSetting = Setting<std::string>;

#define MAKE_SETTING(a_type, a_group, a_key, a_default) \
	inline auto a_key = a_type(a_group##sv, #a_key##sv, a_default)

	// Add one line per setting; expose tunables here instead of hardcoding them.
	MAKE_SETTING(bSetting, "starterplugin", enableExampleFeature, true);
	MAKE_SETTING(iSetting, "starterplugin", exampleNumber, std::int64_t(42));
	MAKE_SETTING(sSetting, "starterplugin", exampleName, std::string("hello"));

#undef MAKE_SETTING

	inline std::vector<
		std::variant<
			std::reference_wrapper<bSetting>,
			std::reference_wrapper<iSetting>,
			std::reference_wrapper<sSetting>>>
		settings;

	inline void load()
	{
		// A missing or malformed TOML is never fatal — the plugin runs on defaults.
		toml::table config;
		try {
			config = toml::parse_file("Data/F4SE/Plugins/starterplugin.toml"sv);
		} catch (const std::exception& e) {
			logger::warn("config not loaded ({}); using defaults"sv, e.what());
			return;
		}

#define LOAD(a_setting)                                                              \
	settings.push_back(std::ref(a_setting));                                         \
	if (const auto tweak = config[a_setting.group()][a_setting.key()]; tweak) {      \
		if (const auto value = tweak.as<decltype(a_setting)::value_type>(); value) { \
			*a_setting = value->get();                                               \
		} else {                                                                     \
			logger::warn(                                                            \
				"setting '{}.{}' is not of the correct type; keeping default"sv,     \
				a_setting.group(),                                                   \
				a_setting.key());                                                    \
		}                                                                            \
	}

		LOAD(enableExampleFeature);
		LOAD(exampleNumber);
		LOAD(exampleName);

#undef LOAD
	}
}
