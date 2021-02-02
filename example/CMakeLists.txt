cmake_minimum_required(VERSION 3.16)

if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
      CACHE STRING "")
endif()

project(example
  VERSION 1.0
  DESCRIPTION "An act example project."
  LANGUAGES CXX)

add_library(cutil SHARED
    "lib/cutil/dllexport.h"
    "lib/cutil/lib.cpp"
     )

set_target_properties(cutil PROPERTIES
    OUTPUT_NAME "example_cutil"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS OFF)

find_package(unofficial-sodium CONFIG REQUIRED)
target_link_libraries(cutil PRIVATE unofficial-sodium::sodium)

configure_file(lib/cutil/version.h.in version.h)
file(GENERATE OUTPUT libname.txt CONTENT $<TARGET_FILE_NAME:cutil>)

if(MSVC)
  add_compile_definitions(WINVER=0x0A00 _WIN32_WINNT=0x0A00)
endif()

# CMake knows how to find TCL
find_package(TCL)
find_package(TclStub)
add_compile_definitions(USE_TCL_STUBS)

target_include_directories(cutil
  PRIVATE
  "${CMAKE_CURRENT_BINARY_DIR}"
  "${TCL_INCLUDE_PATH}")

target_link_libraries(cutil
    PRIVATE
    ${TCL_STUB_LIBRARY})

if(MSVC)
    # because tclStubLib.obj uses link time optimisation
    set_target_properties(cutil PROPERTIES LINK_FLAGS "/LTCG /INCREMENTAL:no")
endif()
