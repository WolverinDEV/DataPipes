# Build targets

list(APPEND PRIVATE_COMPILER_DEFINITIONS -DDEFINE_LOG_HELPERS)

function(create_target)
    cmake_parse_arguments(ARGS "" "NAME;EXPORTED_NAME;TYPE" "SOURCE_FILES" ${ARGN})

    add_library(${ARGS_NAME} ${ARGS_TYPE} ${ARGS_SOURCE_FILES})
    target_compile_definitions(${ARGS_NAME} PRIVATE ${PRIVATE_COMPILER_DEFINITIONS})
    target_compile_definitions(${ARGS_NAME} PUBLIC ${PUBLIC_COMPILER_DEFINITIONS})
    target_include_directories(${ARGS_NAME} PUBLIC ${PUBLIC_INCLUDE_DIRECTORIES})

    target_link_libraries(${ARGS_NAME} PRIVATE ${LIBRARIES_PRIVATE})
    set_target_properties(${ARGS_NAME} PROPERTIES
            EXPORT_NAME ${ARGS_EXPORTED_NAME}
    )

    add_library(${ARGS_EXPORTED_NAME} ALIAS ${ARGS_NAME})
    install(TARGETS ${ARGS_NAME}
            EXPORT DataPipes
            ARCHIVE DESTINATION lib
            LIBRARY DESTINATION lib
    )
endfunction()

# "Core" builds
if(BUILD_STATIC OR BUILD_EXAMPLES) # The examples require DataPipes__static
    create_target(
            NAME DataPipes-Core-Static
            EXPORTED_NAME DataPipes::core::static
            TYPE STATIC
            SOURCE_FILES ${SOURCE_FILES}
    )
endif()

if(BUILD_SHARED)
    create_target(
            NAME DataPipes-Core-Shared
            EXPORTED_NAME DataPipes::core::shared
            TYPE SHARED
            SOURCE_FILES ${SOURCE_FILES}
    )
endif()

install(DIRECTORY include/ DESTINATION include/)