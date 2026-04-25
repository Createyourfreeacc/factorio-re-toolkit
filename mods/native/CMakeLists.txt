cmake_minimum_required(VERSION 3.20)
project(factorio_native_hooks CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Zydis: x86-64 length disassembler, used by the detour engine to safely
# relocate function prologues that contain RIP-relative operands.
include(FetchContent)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  zydis
  GIT_REPOSITORY https://github.com/zyantific/zydis.git
  GIT_TAG        v4.1.0
  GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(zydis)

# Symbol table for the engine binary, generated from nm output by scripts/gen_symbols.py
set(FACTORIO_BINARY "${CMAKE_SOURCE_DIR}/../../../factorio/bin/x64/factorio" CACHE FILEPATH
    "Path to the factorio engine binary. Default expects this layout:
       <workspace>/factorio-re-toolkit/mods/native/  (this CMakeLists.txt)
       <workspace>/factorio/bin/x64/factorio         (the target binary)
     Override with -DFACTORIO_BINARY=<absolute-path> if your layout differs.")
set(GENERATED_SYMBOLS "${CMAKE_BINARY_DIR}/generated/factorio_symbols.cpp")

add_custom_command(
  OUTPUT  ${GENERATED_SYMBOLS}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/generated
  COMMAND python3 ${CMAKE_SOURCE_DIR}/scripts/gen_symbols.py
          --binary ${FACTORIO_BINARY}
          --output ${GENERATED_SYMBOLS}
          --filter ${CMAKE_SOURCE_DIR}/scripts/symbol_filter.txt
  DEPENDS ${CMAKE_SOURCE_DIR}/scripts/gen_symbols.py
          ${CMAKE_SOURCE_DIR}/scripts/symbol_filter.txt
  COMMENT "Generating engine symbol table"
  VERBATIM)

file(GLOB_RECURSE HOOK_SOURCES CONFIGURE_DEPENDS "src/hooks/*.cpp")

add_library(factorio_hooks SHARED
  src/detour.cpp
  src/hook_manager.cpp
  src/loader.cpp
  src/log.cpp
  ${GENERATED_SYMBOLS}
  ${HOOK_SOURCES})

target_include_directories(factorio_hooks PRIVATE src)
target_compile_options(factorio_hooks PRIVATE
  -Wall -Wextra -Wno-unused-parameter -fvisibility=hidden -O2 -g)
target_link_libraries(factorio_hooks PRIVATE dl Zydis)

# Strip on release; keep symbols for debugging by default.
set_target_properties(factorio_hooks PROPERTIES
  OUTPUT_NAME "factorio_hooks"
  PREFIX "lib")

# Offline test for the detour engine (no Factorio launch needed).
add_executable(detour_test src/detour.cpp src/log.cpp src/detour_test.cpp)
target_include_directories(detour_test PRIVATE src)
target_compile_options(detour_test PRIVATE -Wall -Wextra -O1 -g)
target_link_libraries(detour_test PRIVATE Zydis)

enable_testing()
add_test(NAME detour_test COMMAND detour_test)
