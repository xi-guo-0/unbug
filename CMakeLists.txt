cmake_minimum_required(VERSION 3.21)

project(unbug LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(FetchContent)
include(ExternalProject)

set(LIBUNWIND_INSTALL_DIR ${CMAKE_BINARY_DIR}/libunwind-install)

set(UNBUG_DWARF_SUPPORTED OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  set(UNBUG_DWARF_SUPPORTED ON)
endif()

option(UNBUG_ENABLE_DWARF "Enable DWARF-backed source information in stack traces" OFF)

if(UNBUG_ENABLE_DWARF AND NOT UNBUG_DWARF_SUPPORTED)
  message(WARNING
    "UNBUG_ENABLE_DWARF is only supported on x86_64 Linux; disabling option")
  set(UNBUG_ENABLE_DWARF OFF)
endif()

if(CMAKE_CROSSCOMPILING)
  if(QNXNTO)
    set(CROSS_COMPILE_PREFIX "${CMAKE_SYSTEM_PROCESSOR}-unknown-nto-qnx7.1.0")
    set(CROSS_COMPILE_CC "${CMAKE_C_COMPILER}")
    set(CROSS_COMPILE_CXX "${CMAKE_CXX_COMPILER}")
    set(CROSS_COMPILE_FLAGS "--host=${CROSS_COMPILE_PREFIX}")
  elseif(ANDROID)
    message(STATUS "Building for Android")
    message(STATUS "ANDROID_ABI: ${ANDROID_ABI}")
    message(STATUS "ANDROID_NDK: ${ANDROID_NDK}")
    message(STATUS "ANDROID_PLATFORM: ${ANDROID_PLATFORM}")
    message(STATUS "ANDROID_STL: ${ANDROID_STL}")

    if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
      set(NDK_HOST_TAG "linux-x86_64")
    elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
      set(NDK_HOST_TAG "darwin-x86_64")
    elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
      set(NDK_HOST_TAG "windows-x86_64")
    else()
      message(
        FATAL_ERROR
        "Unsupported host system for Android NDK: ${CMAKE_HOST_SYSTEM_NAME}")
    endif()

    if(ANDROID_ABI STREQUAL "arm64-v8a")
      set(LIBUNWIND_HOST "aarch64-linux-android")
    elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
      set(LIBUNWIND_HOST "arm-linux-androideabi")
    elseif(ANDROID_ABI STREQUAL "x86_64")
      set(LIBUNWIND_HOST "x86_64-linux-android")
    elseif(ANDROID_ABI STREQUAL "x86")
      set(LIBUNWIND_HOST "i686-linux-android")
    else()
      message(FATAL_ERROR "Unsupported Android ABI: ${ANDROID_ABI}")
    endif()

    string(REGEX REPLACE "android-" "" ANDROID_API_LEVEL "${ANDROID_PLATFORM}")
    set(ANDROID_CC
      "${ANDROID_NDK}/toolchains/llvm/prebuilt/${NDK_HOST_TAG}/bin/${LIBUNWIND_HOST}${ANDROID_API_LEVEL}-clang"
    )
    set(ANDROID_CXX
      "${ANDROID_NDK}/toolchains/llvm/prebuilt/${NDK_HOST_TAG}/bin/${LIBUNWIND_HOST}${ANDROID_API_LEVEL}-clang++"
    )
    set(ANDROID_CFLAGS "-fPIC -D__ANDROID_API__=${ANDROID_API_LEVEL}")
    set(ANDROID_CXXFLAGS "${ANDROID_CFLAGS}")

    set(CROSS_COMPILE_PREFIX "${CMAKE_SYSTEM_PROCESSOR}-linux-android")
    set(CROSS_COMPILE_CC "${ANDROID_CC}")
    set(CROSS_COMPILE_CXX "${ANDROID_CXX}")
    set(CROSS_COMPILE_FLAGS "--host=${CROSS_COMPILE_PREFIX}")
  endif()
endif()

if(ANDROID)
  set(LIBUNWIND_VERSION "v1.7.2")
else()
  set(LIBUNWIND_VERSION "v1.8.1")
endif()

set(LIBUNWIND_URL
  "https://github.com/libunwind/libunwind/archive/refs/tags/${LIBUNWIND_VERSION}.zip"
)

ExternalProject_Add(
  libunwind
  URL ${LIBUNWIND_URL}
  PREFIX ${CMAKE_BINARY_DIR}/libunwind
  INSTALL_DIR ${LIBUNWIND_INSTALL_DIR}
  CONFIGURE_COMMAND
  cd <SOURCE_DIR> && autoreconf -fiv && ./configure --prefix=<INSTALL_DIR>
  --disable-shared --enable-static --disable-tests --disable-coredump
  --disable-minidebuginfo ${CROSS_COMPILE_FLAGS} CC=${CROSS_COMPILE_CC}
  CXX=${CROSS_COMPILE_CXX} CFLAGS=-fPIC CXXFLAGS=-fPIC
  BUILD_IN_SOURCE 1
  BUILD_COMMAND make
  INSTALL_COMMAND make install)

add_library(${CMAKE_PROJECT_NAME} SHARED ${CMAKE_PROJECT_NAME}.cpp)

target_include_directories(${CMAKE_PROJECT_NAME}
  PRIVATE ${LIBUNWIND_INSTALL_DIR}/include)
target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE
  ${LIBUNWIND_INSTALL_DIR}/lib)

if(UNBUG_ENABLE_DWARF)
  target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE UNBUG_ENABLE_DWARF)
endif()

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
  target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE unwind unwind-x86_64)
elseif(QNXNTO)
  target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE unwind unwind-aarch64
    lzma)
elseif(ANDROID)
  target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE unwind unwind-aarch64 z)
endif()

if(UNBUG_ENABLE_DWARF)
  target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE dw elf)
endif()

add_dependencies(${CMAKE_PROJECT_NAME} libunwind)

add_executable(test test.cpp)
target_compile_options(test PUBLIC -g -fno-omit-frame-pointer -rdynamic)
