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

list(APPEND SOURCE_FILES
        src/ws.cpp
        src/tls.cpp
        src/pipeline.cpp
        src/buffer.cpp
        src/allocator_paged.cpp
        src/allocator.cpp

        src/ssl/ssl.cpp
        src/ssl/ssl_bio.cpp

        src/http/http.cpp
)

list(APPEND PUBLIC_HEADER_DIRECTORIES
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:$<INSTALL_PREFIX>/include>
)

list(APPEND LIBRARIES_PRIVATE)
list(APPEND PUBLIC_COMPILER_DEFINITIONS)

# Sctp
find_package(UsrSCTP)
if (UsrSCTP_FOUND)
    message("Building with UsrSCTP support")

    list(APPEND SOURCE_FILES src/sctp.cpp)
    list(APPEND LIBRARIES_PRIVATE SctpLab::UsrSCTP)
endif ()



# WebRTC part
message("WebRTC support: ${WEBRTC_SUPPORT}")
if (WEBRTC_SUPPORT)
    find_package(sdptransform REQUIRED)
    find_package(LibNice REQUIRED)
    find_package(SRTP REQUIRED)
    find_package(UsrSCTP REQUIRED)

    list(APPEND SOURCE_FILES
            src/rtc/ApplicationChannel.cpp
            src/rtc/AudioStream.cpp
            src/rtc/DTLSPipe.cpp
            src/rtc/NiceWrapper.cpp
            src/rtc/PeerConnection.cpp
            src/rtc/Protocol.cpp
            src/rtc/RtpStream.cpp
            src/rtc/Stream.cpp
            src/rtc/VideoStream.cpp
    )

    list(APPEND LIBRARIES_PRIVATE sdptransform LibNice::LibNice SctpLab::UsrSCTP)

    if(${SRTP_VERSION} EQUAL 1)
        list(APPEND PUBLIC_COMPILER_DEFINITIONS -DSRTP_VERSION_1)
        list(APPEND LIBRARIES_PRIVATE srtp)
    elseif(${SRTP_VERSION} EQUAL 2)
        list(APPEND PUBLIC_COMPILER_DEFINITIONS -DSRTP_VERSION_2)
        list(APPEND LIBRARIES_PRIVATE srtp2)
    else()
        message(FATAL_ERROR "Invalid SRTP version (${SRTP_VERSION})")
    endif()
endif ()

if(BUILD_STATIC OR BUILD_EXAMPLES) # The examples require DataPipes__static
    add_library(DataPipes__static STATIC ${SOURCE_FILES})
    target_compile_definitions(DataPipes__static PRIVATE -DDEFINE_LOG_HELPERS)
    target_compile_definitions(DataPipes__static PUBLIC ${PUBLIC_COMPILER_DEFINITIONS})
    target_include_directories(DataPipes__static PUBLIC ${PUBLIC_HEADER_DIRECTORIES})

    target_link_libraries(DataPipes__static PRIVATE ${LIBRARIES_PRIVATE})
    set_target_properties(DataPipes__static PROPERTIES
            EXPORT_NAME DataPipes::static
    )

    add_library(DataPipes::static ALIAS DataPipes__static)
    install(TARGETS DataPipes__static
            EXPORT DataPipes
            ARCHIVE DESTINATION lib
    )
endif()

if(BUILD_SHARED)
    add_library(DataPipes__shared SHARED ${SOURCE_FILES})
    target_compile_definitions(DataPipes__shared PRIVATE -DDEFINE_LOG_HELPERS)
    target_compile_definitions(DataPipes__shared PUBLIC ${PUBLIC_COMPILER_DEFINITIONS})
    target_include_directories(DataPipes__shared PUBLIC ${PUBLIC_HEADER_DIRECTORIES})
    target_link_libraries(DataPipes__shared PRIVATE ${LIBRARIES_PRIVATE})

    set_target_properties(DataPipes__shared PROPERTIES EXPORT_NAME DataPipes::shared)
    add_library(DataPipes::shared ALIAS DataPipes__shared)
    install(TARGETS DataPipes__shared
            EXPORT DataPipes
            LIBRARY DESTINATION lib
    )
endif()
install(DIRECTORY include/ DESTINATION include/)

if(BUILD_EXAMPLES)
    function(create_example)
        cmake_parse_arguments(
                ARGS
                ""
                "NAME"
                "SOURCES;LIBRARIES;DEFINITIONS"
                ${ARGN}
        )
        if (NOT ARGS_NAME)
            message(FATAL_ERROR "Missing example name")
        endif ()

        add_executable(${ARGS_NAME} ${ARGS_SOURCES})
        target_link_libraries(${ARGS_NAME} PRIVATE ${ARGS_LIBRARIES})
        if(ARGS_DEFINITIONS)
            target_compile_definitions(${ARGS_NAME} PRIVATE ${ARGS_DEFINITIONS})
        endif()
    endfunction()

    create_example(
            NAME DataPipes-example-buffer
            SOURCES test/buffer.cpp
            LIBRARIES DataPipes__static
    )

    create_example(
            NAME DataPipes-example-ssl-server
            SOURCES test/utils/socket.cpp test/ssl_pipeline_server.cpp
            LIBRARIES DataPipes__static event event_pthreads crypto ssl pthread
    )

    create_example(
            NAME DataPipes-example-ws-pipeline
            SOURCES test/utils/socket.cpp test/ws_pipeline.cpp
            LIBRARIES DataPipes__static event event_pthreads crypto pthread
    )

    create_example(
            NAME DataPipes-example-rtc-audio
            SOURCES test/utils/socket.cpp test/json/jsoncpp.cpp test/rtc/rtc_test_audio.cpp
            LIBRARIES DataPipes__static event event_pthreads crypto ssl pthread
    )

    find_package(GLIB)
    create_example(
            NAME DataPipes-example-rtc-data
            SOURCES test/utils/socket.cpp test/json/jsoncpp.cpp test/rtc/rtc_test_data.cpp
            LIBRARIES DataPipes__static event event_pthreads crypto ssl pthread
    )
    if(GLIB_FOUND)
        message("Building rtc-data data with custom gio loop")
        target_compile_definitions(DataPipes-example-rtc-data PRIVATE "HAVE_GLIB")
        target_include_directories(DataPipes-example-rtc-data PRIVATE ${GLIB_INCLUDE_DIRS})
        target_link_libraries(DataPipes-example-rtc-data PRIVATE ${GLIB_GOBJECT_LIBRARIES} ${GLIB_LIBRARIES})
    endif()

    create_example(
            NAME DataPipes-example-rtc-video
            SOURCES test/utils/socket.cpp test/json/jsoncpp.cpp test/rtc/video_utils.cpp test/rtc/rtc_test_video.cpp
            LIBRARIES DataPipes__static event event_pthreads vpx crypto ssl pthread
    )
endif()

if (EXPORT_OLD_LIBRARY_NAMES)
    if(BUILD_SHARED)
        add_library(DataPipes-Shared ALIAS DataPipes__shared)
    endif()
    if(BUILD_STATIC)
        add_library(DataPipes-Static ALIAS DataPipes__shared)
    endif()
endif ()

# Setup generate variables
string(TOUPPER ${PROJECT_NAME} PROJECT_NAME_UPPERCASE)
string(TOLOWER ${PROJECT_NAME} PROJECT_NAME_LOWERCASE)

set(INSTALL_CMAKE_DIRECTORY "${CMAKE_INSTALL_PREFIX}/lib/CMake/${PROJECT_NAME}/")
install(EXPORT "${PROJECT_NAME}" DESTINATION "${INSTALL_CMAKE_DIRECTORY}" FILE ${PROJECT_NAME}Targets.cmake)

# Create the <package>Config.cmake.in
configure_file(${CMAKE_SOURCE_DIR}/cmake/config/Config.cmake.in
        "${PROJECT_BINARY_DIR}/cmake-config/${PROJECT_NAME}Config.cmake" @ONLY)

# Create the <package>ConfigVersion.cmake.in
configure_file(${CMAKE_SOURCE_DIR}/cmake/config/ConfigVersion.cmake.in
        "${PROJECT_BINARY_DIR}/cmake-config/${PROJECT_NAME}ConfigVersion.cmake" @ONLY)

# Install <package>Config.cmake and <package>ConfigVersion.cmake files
install(FILES
        "${PROJECT_BINARY_DIR}/cmake-config/${PROJECT_NAME}Config.cmake"
        "${PROJECT_BINARY_DIR}/cmake-config/${PROJECT_NAME}ConfigVersion.cmake"
        DESTINATION "${INSTALL_CMAKE_DIRECTORY}" COMPONENT dev)