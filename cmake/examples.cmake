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
        LIBRARIES  DataPipes-Core-Static
)

function(resolve_event)
    set(LIBEVENT_STATIC_LINK TRUE)
    find_package(Libevent 2.2 QUIET COMPONENTS core)
    set(Libevent_FOUND ${Libevent_FOUND} PARENT_SCOPE)
endfunction()
resolve_event()

if (Libevent_FOUND)
    create_example(
            NAME DataPipes-example-ssl-server
            SOURCES test/utils/socket.cpp test/ssl_pipeline_server.cpp
            LIBRARIES  DataPipes-Rtc-Static crypto ssl pthread libevent::core
    )

    create_example(
            NAME DataPipes-example-ws-pipeline
            SOURCES test/utils/socket.cpp test/ws_pipeline.cpp
            LIBRARIES  DataPipes-Rtc-Static crypto pthread libevent::core
    )
else()
    message("Skipping WS examples because of missing libevent")
endif ()