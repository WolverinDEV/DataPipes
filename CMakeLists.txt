cmake_minimum_required(VERSION 3.9)
project(DataPipes CXX)

# Custom CMake modules
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/modules")
if(NOT WIN32)
    add_compile_options("-Wall")
endif()

option(WEBRTC_SUPPORT   "Enable/disable support for all WebRTC components (required usrsctp, nice and glib)." ON)
option(BUILD_STATIC     "Enable/disable static build." ON)
option(BUILD_SHARED     "Enable/disable static build." ON)
option(BUILD_EXAMPLES   "Enable/disable the example builds." ON)
option(EXPORT_OLD_LIBRARY_NAMES "If enabled the old library exports from the old cmake file will be exported as well" OFF)

set(MAJOR_VERSION 1)
set(MINOR_VERSION 1)
set(PATCH_VERSION 0)
set(PROJECT_VERSION ${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION})


# Sctp
find_package(UsrSCTP)
if (UsrSCTP_FOUND)
    set(WITH_UsrSCTP ON)
endif ()

#Crypto library (OpenSSL or BoringSSL)
find_package(Crypto REQUIRED)
include_directories(BEFORE SYSTEM ${Crypto_INCLUDE_DIR})
link_libraries (${Crypto_LIBRARIES})

if(CRYPTO_TYPE STREQUAL "openssl")
    if(Crypto_BORINGSSL)
        message(FATAL_ERROR "Used to use OpenSSL, but found BoringSSL (${Crypto_INCLUDE_DIR}).\nConcider to set the OpenSSL root in Crypto_ROOT_DIR")
    elseif(NOT Crypto_OPENSSL)
        message(FATAL_ERROR "Used to use OpenSSL, but haven't found OpenSSL.\nConcider to set the OpenSSL root in Crypto_ROOT_DIR")
    endif()
elseif(CRYPTO_TYPE STREQUAL "boringssl")
    if(Crypto_OPENSSL)
        message(FATAL_ERROR "Used to use BoringSSL, but found OpenSSL (${Crypto_INCLUDE_DIR}).\nConcider to set the BoringSSL root in Crypto_ROOT_DIR")
    elseif(NOT Crypto_BORINGSSL)
        message(FATAL_ERROR "Used to use BoringSSL, but haven't found BoringSSL.\nConcider to set the BoringSSL root in Crypto_ROOT_DIR")
    endif()
elseif(CRYPTO_TYPE)
    message(FATAL_ERROR "Unknown CRYPTO_TYPE. Availible types: openssl | boringssl")
endif()

if(Crypto_OPENSSL)
	message("Using OpenSSL")
elseif(Crypto_BORINGSSL)
	add_definitions(-DUSE_BORINGSSL)
	message("Using BoringSSL")
else()
	message(FATAL_ERROR "Failed to detect crypto library type!")
endif()

include(cmake/sources.cmake)

# WebRTC part
message("WebRTC support: ${WEBRTC_SUPPORT}")
if (WEBRTC_SUPPORT)
    set(WITH_RTC ON)

    include(cmake/rtc-libraries.cmake)
endif ()

include(cmake/targets.cmake)

if(BUILD_EXAMPLES)
    include(cmake/examples.cmake)
endif()

if (EXPORT_OLD_LIBRARY_NAMES)
    if(BUILD_SHARED)
        add_library(DataPipes-Shared ALIAS DataPipes__shared)
    endif()
    if(BUILD_STATIC)
        add_library(DataPipes-Static ALIAS DataPipes__shared)
    endif()
endif ()