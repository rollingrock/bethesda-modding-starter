cmake_minimum_required(VERSION 3.23)
set(NAME "starterplugin")
set(VERSION 0.1.0)

# ---- Options ----
option(COPY_BUILD "Copy the build output to the Fallout directory." FALSE)

# VR is this template's default target. The `vr` preset sets this to true explicitly;
# the flat preset sets it false. CommonLibF4 is NG-style, so the same tree builds both.
option(BUILD_FALLOUTVR "Build against the Fallout 4 VR runtime (defines FALLOUTVR)." ON)

# ---- Cache build vars ----
macro(set_from_environment VARIABLE)
	if(NOT DEFINED ${VARIABLE} AND DEFINED ENV{${VARIABLE}})
		set(${VARIABLE} $ENV{${VARIABLE}})
	endif()
endmacro()

macro(find_commonlib_path)
	if(CommonLibName AND NOT ${CommonLibName} STREQUAL "")
		# Check extern
		find_path(CommonLibPath
			CommonLibF4/include/REL/Relocation.h
			PATHS external/${CommonLibName}
			extern/${CommonLibName})

		if(${CommonLibPath} STREQUAL "CommonLibPath-NOTFOUND")
			# Check path
			set_from_environment(${CommonLibName}Path)
			set(CommonLibPath ${${CommonLibName}Path})
		endif()
	endif()
endmacro()

set_from_environment(VCPKG_ROOT)

add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
set(CommonLibName "CommonLibF4")

# alandtse/CommonLibF4 dispatches at runtime: ENABLE_FALLOUT_F4/_NG/_VR are all ON by
# default, so ONE DLL serves pre-NG Fallout 4, the Next-Gen update and Fallout 4 VR and
# picks between them at load time via REL::Module. There is no FALLOUTVR define to set --
# BUILD_FALLOUTVR here only chooses which install this project deploys to and which build
# directory it uses.
set(F4SE_SUPPORT_XBYAK ON CACHE BOOL "" FORCE)   # PCH.h includes xbyak; the lib gates it
set(BUILD_TESTS OFF CACHE BOOL "" FORCE)         # do not build CommonLibF4's Catch2 suite

if(BUILD_FALLOUTVR)
	set_from_environment(FalloutVRPath)
	set(FalloutPath ${FalloutVRPath})
	set(FalloutVersion "Fallout VR")
else()
	set_from_environment(Fallout4Path)
	set(FalloutPath ${Fallout4Path})
	set(FalloutVersion "Fallout 4")
endif()

if(BACKWARDS_COMPATIBLE)
	add_compile_definitions(BACKWARDS_COMPATIBLE)
endif()

find_commonlib_path()
message(
	STATUS
	"Building ${NAME} ${VERSION} for ${FalloutVersion} at ${FalloutPath} with ${CommonLibName} at ${CommonLibPath}."
)

if(DEFINED VCPKG_ROOT)
	set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
	set(VCPKG_TARGET_TRIPLET "x64-windows-static" CACHE STRING "")
else()
	message(
		WARNING
		"Variable VCPKG_ROOT is not set. Continuing without vcpkg."
	)
endif()

set(Boost_USE_STATIC_RUNTIME OFF CACHE BOOL "")

# ---- Project ----
project(
	${NAME}
	VERSION ${VERSION}
	LANGUAGES CXX
)

configure_file(
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/Version.h.in
	${CMAKE_CURRENT_BINARY_DIR}/include/Version.h
	@ONLY
)

configure_file(
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.rc.in
	${CMAKE_CURRENT_BINARY_DIR}/version.rc
	@ONLY
)

# ---- Include guards ----
if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
	message(
		FATAL_ERROR
		"In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there."
	)
endif()

# ---- Globals ----
# NOTE: F4SE_SUPPORT_XBYAK is NOT defined here. CommonLibF4 exports it PUBLIC as
# F4SE_SUPPORT_XBYAK=1 when its option is ON (set above); defining a bare copy here too
# would be a macro redefinition, which /WX turns into a build error.

if(MSVC)
	if(NOT ${CMAKE_GENERATOR} STREQUAL "Ninja")
		add_compile_options(
			/MP # Build with Multiple Processes
		)
	endif()
endif()

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_DEBUG OFF)

set(Boost_USE_STATIC_LIBS ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>" CACHE STRING "")

# ---- Dependencies ----
if(DEFINED CommonLibPath AND NOT ${CommonLibPath} STREQUAL "" AND IS_DIRECTORY ${CommonLibPath})
	add_subdirectory(${CommonLibPath} ${CommonLibName})
else()
	message(
		FATAL_ERROR
		"Variable ${CommonLibName}Path is not set."
	)
endif()

find_package(robin_hood CONFIG REQUIRED)

# ---- Add source files ----
include(cmake/headerlist.cmake)
include(cmake/sourcelist.cmake)

source_group(
	TREE
	${CMAKE_CURRENT_SOURCE_DIR}
	FILES
	${headers}
	${sources}
)

source_group(
	TREE
	${CMAKE_CURRENT_BINARY_DIR}
	FILES
	${CMAKE_CURRENT_BINARY_DIR}/include/Version.h
)

# ---- Create DLL ----
add_library(
	${PROJECT_NAME}
	SHARED
	${headers}
	${sources}
	${CMAKE_CURRENT_BINARY_DIR}/include/Version.h
	${CMAKE_CURRENT_BINARY_DIR}/version.rc
	.clang-format
)

target_compile_features(
	${PROJECT_NAME}
	PRIVATE
	cxx_std_23
)

target_compile_definitions(
	${PROJECT_NAME}
	PRIVATE
	_UNICODE
)

target_include_directories(
	${PROJECT_NAME}
	PRIVATE
	${CMAKE_CURRENT_BINARY_DIR}/include
	${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(
	${PROJECT_NAME}
	PRIVATE
	${CommonLibName}::${CommonLibName}
	robin_hood::robin_hood
)

target_precompile_headers(
	${PROJECT_NAME}
	PRIVATE
	src/PCH.h
)

if(MSVC)
	target_compile_options(
		${PROJECT_NAME}
		PRIVATE
		/sdl # Enable Additional Security Checks
		/utf-8 # Set Source and Executable character sets to UTF-8
		/Zi # Debug Information Format

		/permissive- # Standards conformance

		/Zc:alignedNew # C++17 over-aligned allocation
		/Zc:auto # Deduce Variable Type
		/Zc:char8_t
		/Zc:__cplusplus # Enable updated __cplusplus macro
		/Zc:externC
		/Zc:externConstexpr # Enable extern constexpr variables
		/Zc:forScope # Force Conformance in for Loop Scope
		/Zc:hiddenFriend
		/Zc:implicitNoexcept # Implicit Exception Specifiers
		/Zc:lambda
		/Zc:noexceptTypes # C++17 noexcept rules
		/Zc:preprocessor # Enable preprocessor conformance mode
		/Zc:referenceBinding # Enforce reference binding rules
		/Zc:rvalueCast # Enforce type conversion rules
		/Zc:sizedDealloc # Enable Global Sized Deallocation Functions
		/Zc:strictStrings # Disable string literal type conversion
		/Zc:ternary # Enforce conditional operator rules
		/Zc:threadSafeInit # Thread-safe Local Static Initialization
		/Zc:tlsGuards
		/Zc:trigraphs # Trigraphs Substitution
		/Zc:wchar_t # wchar_t Is Native Type

		/external:anglebrackets
		/external:W0

		/W4 # Warning level
		/WX # Warning level (warnings are errors)

		/wd4702
		/wd4267
		/wd4456
		/wd4189
		/wd4244
		/wd4834
		/wd4189
		/wd4505

		"$<$<CONFIG:DEBUG>:>"
		"$<$<CONFIG:RELEASE>:/Zc:inline;/JMC-;/Ob3>"
	)

	target_link_options(
		${PROJECT_NAME}
		PRIVATE
		/WX # Treat Linker Warnings as Errors

		"$<$<CONFIG:DEBUG>:/INCREMENTAL;/OPT:NOREF;/OPT:NOICF>"
		"$<$<CONFIG:RELEASE>:/INCREMENTAL:NO;/OPT:REF;/OPT:ICF;/DEBUG:FULL>"
	)

	# fix a warning with /Ob2 being overridden with /Ob3
	string(REPLACE "/Ob2" "/Ob3" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
endif()

# ---- Post build ----
if(COPY_BUILD)
	if(DEFINED FalloutPath)
		string(REGEX REPLACE "[/\\][Dd][Aa][Tt][Aa][/\\]?$" "" FalloutPath "${FalloutPath}") # remove " /data " if exists; cmake regex doesn't have /i
		add_custom_command(
			TARGET ${PROJECT_NAME}
			POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${FalloutPath}/Data/F4SE/Plugins/
			COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_PDB_FILE:${PROJECT_NAME}> ${FalloutPath}/Data/F4SE/Plugins/
		)
	else()
		message(
			WARNING
			"Variable ${FalloutPath} is not defined. Skipping post-build copy command."
		)
	endif()
endif()

# Deploy straight into an MO2 mod folder (point MO2_INSTALL_PATH at
# <mo2>/mods/<yourmod>/F4SE/Plugins — see CMakeUserPresets.json.template).
# Preferred over COPY_BUILD for MO2 users: the real game Data dir stays clean.
# Only the DLL/PDB are copied; config files are deployed by hand so a rebuild
# never clobbers values you are live-tuning in the mod folder.
if(DEFINED MO2_INSTALL_PATH AND NOT "${MO2_INSTALL_PATH}" STREQUAL "")
	# Check the path at CONFIGURE time, because the POST_BUILD deploy below is incapable of
	# failing: `cmake -E make_directory` deep-creates ANY path it is handed and returns 0. The
	# unedited C:/MO2/... placeholder from CMakeUserPresets.json.template, a typo, or an
	# instance-mode MO2 (whose real mods live under %LOCALAPPDATA%/ModOrganizer/<game>/mods)
	# therefore all built green with the DLL sitting in a freshly invented tree no MO2 instance
	# ever reads -- no plugin, no F4SE log, no error anywhere. The COPY_BUILD arm above gets
	# this for free by creating nothing; this arm has to check for itself.
	#
	# Which ancestor must already exist is narrower than it looks. MO2_INSTALL_PATH is
	# documented and generated as <mo2>/mods/<yourmod>/F4SE/Plugins, and for a new mod neither
	# the F4SE/Plugins leaf nor <yourmod> exists yet -- creating those is exactly what the
	# make_directory below is for. The mods root above them is MO2's own; if THAT is missing
	# the path is simply not pointing at an MO2 install. So strip a trailing F4SE/Plugins
	# (character class by character class, since cmake regex has no /i and people write
	# F4SE/plugins) and require the parent of whatever is left.
	file(TO_CMAKE_PATH "${MO2_INSTALL_PATH}" MO2_DEPLOY_PATH)
	string(REGEX REPLACE "/+$" "" MO2_DEPLOY_PATH "${MO2_DEPLOY_PATH}")
	string(REGEX REPLACE "/[Ff]4[Ss][Ee]/[Pp][Ll][Uu][Gg][Ii][Nn][Ss]$" "" MO2_MOD_DIR "${MO2_DEPLOY_PATH}")
	get_filename_component(MO2_MODS_ROOT "${MO2_MOD_DIR}" DIRECTORY)

	if(NOT IS_DIRECTORY "${MO2_MODS_ROOT}")
		message(
			FATAL_ERROR
			"MO2_INSTALL_PATH is set to \"${MO2_INSTALL_PATH}\", but the folder that would have "
			"to hold the mod -- \"${MO2_MODS_ROOT}\" -- is not an existing folder, so this build "
			"would copy the DLL into a tree no MO2 instance reads. MO2_INSTALL_PATH must point "
			"at <mo2>/mods/<yourmod>/F4SE/Plugins, where <mo2>/mods is the mods folder MO2 "
			"already uses (MO2 > Settings > Paths; an instance-mode MO2 keeps it under "
			"%LOCALAPPDATA%/ModOrganizer/<game>/mods). Fix it in CMakeUserPresets.json and "
			"configure again."
		)
	endif()

	add_custom_command(
		TARGET ${PROJECT_NAME}
		POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E make_directory "${MO2_INSTALL_PATH}"
		COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> "${MO2_INSTALL_PATH}"
		COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_PDB_FILE:${PROJECT_NAME}> "${MO2_INSTALL_PATH}"
	)
endif()

# ---- Create Package ----
if(PACKAGE)
	set(ZIP_DIR "${CMAKE_CURRENT_BINARY_DIR}/zip")
	add_custom_target(build-time-make-directory ALL
		COMMAND ${CMAKE_COMMAND} -E make_directory "${ZIP_DIR}"
		"${ZIP_DIR}/F4SE/Plugins/"
	)

	message("Will copy mod into ${ZIP_DIR}.")
	add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> "${ZIP_DIR}/F4SE/Plugins/"
	)

	if(${CMAKE_BUILD_TYPE} STREQUAL Debug OR ${CMAKE_BUILD_TYPE} STREQUAL RelWithDebInfo OR ${CMAKE_BUILD_TYPE} STREQUAL Release)
		add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
			COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_PDB_FILE:${PROJECT_NAME}> "${ZIP_DIR}/F4SE/Plugins/")
	endif()

	set(TARGET_ZIP "${PROJECT_NAME}_${PROJECT_VERSION}.7z")
	message("Will zip ${ZIP_DIR} to ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_ZIP}.")
	ADD_CUSTOM_COMMAND(
		TARGET ${PROJECT_NAME}
		POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E tar cf ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_ZIP} --format=7zip -- .
		WORKING_DIRECTORY ${ZIP_DIR}
	)
endif()
