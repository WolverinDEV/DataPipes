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

function(resolve_event)
    set(LIBEVENT_STATIC_LINK TRUE)
    find_package(Libevent 2.2 REQUIRED COMPONENTS core)
endfunction()
resolve_event()

create_example(
        NAME DataPipes-example-buffer
        SOURCES ../test/buffer.cpp
        LIBRARIES  DataPipes__static
)

create_example(
        NAME DataPipes-example-ssl-server
        SOURCES ../test/utils/socket.cpp ../test/ssl_pipeline_server.cpp
        LIBRARIES  DataPipes__static crypto ssl pthread libevent::core
)

create_example(
        NAME DataPipes-example-ws-pipeline
        SOURCES ../test/utils/socket.cpp ../test/ws_pipeline.cpp
        LIBRARIES  DataPipes__static crypto pthread libevent::core
)

create_example(
        NAME DataPipes-example-rtc-audio
        SOURCES ../test/utils/socket.cpp ../test/json/jsoncpp.cpp ../test/rtc/rtc_test_audio.cpp ../test/utils/rtc_server.cpp
        LIBRARIES  DataPipes__static crypto ssl pthread libevent::core libevent::pthreads opus
)

find_package(GLIB)
create_example(
        NAME DataPipes-example-rtc-data
        SOURCES ../test/utils/socket.cpp ../test/json/jsoncpp.cpp ../test/rtc/rtc_test_data.cpp ../test/utils/rtc_server.cpp
        LIBRARIES  DataPipes__static crypto ssl pthread libevent::core libevent::pthreads
)
if(GLIB_FOUND)
    message("Building rtc-data data with custom gio loop")
    target_compile_definitions(DataPipes-example-rtc-data PRIVATE "HAVE_GLIB")
    target_include_directories(DataPipes-example-rtc-data PRIVATE ${GLIB_INCLUDE_DIRS})
    target_link_libraries(DataPipes-example-rtc-data PRIVATE ${GLIB_GOBJECT_LIBRARIES} ${GLIB_LIBRARIES})
endif()

create_example(
        NAME DataPipes-example-rtc-video
        SOURCES ../test/utils/socket.cpp ../test/json/jsoncpp.cpp ../test/rtc/video_utils.cpp ../test/rtc/rtc_test_video.cpp
        LIBRARIES  DataPipes__static vpx crypto ssl pthread libevent::core
)