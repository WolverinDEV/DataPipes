cmake_minimum_required(VERSION 3.9)
project(plugin CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_VERBOSE_MAKEFILE ON)

# Custom CMake modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/Modules")

option(BUILD_STATIC "Build static library" ON)
option(BUILD_SHARED "Build shared library" ON)
option(BUILD_WEBRTC "Build the WebRTC package" ON)

add_definitions(-DLOG_LEVEL=0) #FIXME!

# Using static library linking
macro(configure_msvc_runtime)
    if(MSVC)
        # Default to statically-linked runtime.
        if("${MSVC_RUNTIME}" STREQUAL "")
            set(MSVC_RUNTIME "static")
        endif()

        # Set compiler options.
        set(variables
                CMAKE_C_FLAGS_DEBUG
                CMAKE_C_FLAGS_MINSIZEREL
                CMAKE_C_FLAGS_RELEASE
                CMAKE_C_FLAGS_RELWITHDEBINFO
                CMAKE_CXX_FLAGS_DEBUG
                CMAKE_CXX_FLAGS_MINSIZEREL
                CMAKE_CXX_FLAGS_RELEASE
                CMAKE_CXX_FLAGS_RELWITHDEBINFO
        )
        if(${MSVC_RUNTIME} STREQUAL "static")
            foreach(variable ${variables})
                if(${variable} MATCHES "/MD")
                    string(REGEX REPLACE "/MD" "/MT" ${variable} "${${variable}}")
                endif()
            endforeach()
        else()
            foreach(variable ${variables})
                if(${variable} MATCHES "/MT")
                    string(REGEX REPLACE "/MT" "/MD" ${variable} "${${variable}}")
                endif()
            endforeach()
        endif()
    endif()
endmacro()
configure_msvc_runtime()


set(HEADER_FILES
        #General definitions
        include/pipeline.h
        include/errors.h

        #The pipes
        include/ssl.h
        include/ws.h
        include/sctp.h
        include/tls.h
        include/buffer.h
        include/allocator.h

        #Helpers
        include/misc/http.h
        include/misc/endianness.h
        include/misc/logger.h
)

set(SOURCE_FILES
        src/pipeline.cpp

        src/ssl/ssl.cpp
        src/ssl/ssl_bio.cpp

        src/ws.cpp

        src/buffer.cpp
        src/allocator.cpp

        src/http/http.cpp

        src/tls.cpp
)
if (NOT WIN32)
    message("We're not on windows")
    set(SOURCE_FILES ${SOURCE_FILES} src/allocator_paged.cpp)
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

if(BUILD_STATIC)
    add_library(DataPipes__core__static STATIC ${SOURCE_FILES})
    install(TARGETS DataPipes__core__static DESTINATION lib)
    set_target_properties(DataPipes__core__static PROPERTIES OUTPUT_NAME DataPipes)
    target_compile_definitions(DataPipes__core__static PRIVATE DEFINE_LOG_HELPERS)
endif()

if(BUILD_SHARED)
    add_library(DataPipes__core__shared SHARED ${SOURCE_FILES})
    install(TARGETS DataPipes__core__shared DESTINATION lib)
    set_target_properties(DataPipes__core__shared PROPERTIES OUTPUT_NAME DataPipes)
    target_compile_definitions(DataPipes__core__shared PRIVATE DEFINE_LOG_HELPERS)
endif()

if(BUILD_WEBRTC)
    # Find packages
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    find_package(LibNice REQUIRED)
    find_package(UsrSCTP REQUIRED)

    #spdtransform library
    if (NOT sdptransform_ROOT_DIR)
        set(sdptransform_ROOT_DIR "${CMAKE_SOURCE_DIR}/libraries/sdptransform/out/")
    endif ()
    find_package(sdptransform REQUIRED)

    # When supplying a prebuild (may static) version of glib2.0
    if (NOT GLIB_PREBUILD_LIBRARIES OR NOT GLIB_PREBUILD_FLAGS)
        execute_process(
                COMMAND bash -c "pkg-config --cflags glib-2.0"
                OUTPUT_VARIABLE GLIB_FLAGS
        )
        string(REPLACE "\t" " " GLIB_FLAGS "${GLIB_FLAGS}")
        string(REPLACE "\n" "" GLIB_FLAGS "${GLIB_FLAGS}")
        message("Got GLIB cflags ${GLIB_FLAGS}")

        execute_process(
                COMMAND bash -c "pkg-config --libs glib-2.0"
                OUTPUT_VARIABLE GLIB_LIBRARIES
        )
        string(REPLACE "\t" " " GLIB_LIBRARIES "${GLIB_LIBRARIES}")
        string(REPLACE "\n" "" GLIB_LIBRARIES "${GLIB_LIBRARIES}")
        message("Got GLIB libraries ${GLIB_LIBRARIES}")
    else()
        set(GLIB_FLAGS "${GLIB_PREBUILD_FLAGS}")
        set(GLIB_LIBRARIES "${GLIB_PREBUILD_LIBRARIES}")
    endif()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GLIB_FLAGS}")

    set(RTC_HEADER_FILES
            include/rtc/Stream.h
            include/rtc/NiceWrapper.h
            include/rtc/PeerConnection.h
            include/rtc/ApplicationStream.h
            include/rtc/AudioStream.h
            include/rtc/MergedStream.h
    )


    set(RTC_SOURCE_FILES
            src/sctp.cpp

            src/rtc/Stream.cpp
            src/rtc/AudioStream.cpp
            src/rtc/ApplicationChannel.cpp
            src/rtc/NiceWrapper.cpp
            src/rtc/PeerConnection.cpp
            src/rtc/MergedStream.cpp
    )

    if(BUILD_STATIC)
        add_library(DataPipes__rtc__static STATIC ${SOURCE_FILES} ${RTC_SOURCE_FILES})
        install(TARGETS DataPipes__rtc__static DESTINATION lib)
        set_target_properties(DataPipes__rtc__static PROPERTIES OUTPUT_NAME DataPipes-RTC)
        target_compile_definitions(DataPipes__rtc__static PRIVATE DEFINE_LOG_HELPERS)

        target_link_libraries(
                DataPipes__rtc__static
                LibNice::LibNice
                #SctpLab::UsrSCTP
                usrsctp.a
                sdptransform::static
                #srtp
                ${CMAKE_SOURCE_DIR}/libraries/srtp/build/libsrtp2.a
                stdc++fs.a
                ${GLIB_LIBRARIES}
        )
    endif()

    if(BUILD_SHARED)
        add_library(DataPipes__rtc__shared SHARED ${SOURCE_FILES} ${RTC_SOURCE_FILES})
        install(TARGETS DataPipes__rtc__shared DESTINATION lib)
        set_target_properties(DataPipes__rtc__shared PROPERTIES OUTPUT_NAME DataPipes-RTC)
        target_compile_definitions(DataPipes__rtc__shared PRIVATE DEFINE_LOG_HELPERS)

        target_link_libraries(
                DataPipes__rtc__shared
                LibNice::LibNice
                #SctpLab::UsrSCTP
                usrsctp.a
                sdptransform::static
                #srtp
                ${CMAKE_SOURCE_DIR}/libraries/srtp/build/libsrtp2.a
                stdc++fs.a
                ${GLIB_LIBRARIES}
        )
    endif()
endif()

install(DIRECTORY include/ DESTINATION include/pipes)

if(BUILD_TESTS)
    set(TEST_LIBRARIES
            DataPipes-Static
            LibNice::LibNice
            #SctpLab::UsrSCTP
            usrsctp.a
            sdptransform
            #srtp
            ${CMAKE_SOURCE_DIR}/libraries/srtp/build/libsrtp2.a
            stdc++fs.a

            DataPipes-Shared
            event
            event_pthreads
            #/home/wolverindev/clib/boringssl/build/ssl/libssl.so
            #/home/wolverindev/clib/boringssl/build/crypto/libcrypto.so
            /home/wolverindev/TeaSpeak/libraries/boringssl/build/ssl/libssl.so
            /home/wolverindev/TeaSpeak/libraries/boringssl/build/crypto/libcrypto.so
            pthread
            asound
            opus
    )



    function(resolve_event)
        set(LIBEVENT_STATIC_LINK TRUE)
        find_package(Libevent 2.2 REQUIRED COMPONENTS core)
    endfunction()
    resolve_event()

    add_executable(DataPipes-Test-rtc-data test/rtc/rtc_test_data.cpp test/utils/socket.cpp test/json/jsoncpp.cpp)
    target_link_libraries(DataPipes-Test-rtc-data
            libevent::core
            DataPipes__rtc__static
            LibNice::LibNice
            ${GLIB_LIBRARIES}
    )

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")

    add_executable(DataPipes-Test-SSL test/ssl_pipeline_server.cpp test/utils/socket.cpp)
    target_link_libraries(DataPipes-Test-SSL ${TEST_LIBRARIES})

    add_executable(DataPipes-Test-WS test/ws_pipeline.cpp test/utils/socket.cpp)
    target_link_libraries(DataPipes-Test-WS ${TEST_LIBRARIES})

    add_executable(DataPipes-Test-rtc-data test/rtc/rtc_test_data.cpp test/utils/socket.cpp test/json/jsoncpp.cpp)
    target_link_libraries(DataPipes-Test-rtc-data ${TEST_LIBRARIES})

    add_executable(DataPipes-Test-rtc-audio test/rtc/rtc_test_audio.cpp test/utils/socket.cpp test/json/jsoncpp.cpp)
    target_link_libraries(DataPipes-Test-rtc-audio ${TEST_LIBRARIES})

    add_executable(DataPipes-Test-buffers include/buffer.h src/buffer.cpp src/allocator.cpp test/buffer.cpp)

    add_executable(DataPipes-Test-video test/video.cpp test/video/ivfenc.cpp)
    target_link_libraries(DataPipes-Test-video ${TEST_LIBRARIES} vpx)
endif()