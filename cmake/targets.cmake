# Build targets

list(APPEND PRIVATE_COMPILER_DEFINITIONS -DDEFINE_LOG_HELPERS)
# "Core" builds
if(BUILD_STATIC OR BUILD_EXAMPLES) # The examples require DataPipes__static
    message("BUILD DP STATIC")
    add_library(DataPipes__static STATIC ${SOURCE_FILES} ${RTC_SOURCE_FILES})
    target_compile_definitions(DataPipes__static PRIVATE ${PRIVATE_COMPILER_DEFINITIONS})
    target_compile_definitions(DataPipes__static PUBLIC ${PUBLIC_COMPILER_DEFINITIONS})
    target_include_directories(DataPipes__static PUBLIC ${PUBLIC_INCLUDE_DIRECTORIES})

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
    add_library(DataPipes__shared SHARED ${SOURCE_FILES} ${RTC_SOURCE_FILES})
    target_compile_definitions(DataPipes__shared PRIVATE ${PRIVATE_COMPILER_DEFINITIONS})
    target_compile_definitions(DataPipes__shared PUBLIC ${PUBLIC_COMPILER_DEFINITIONS})
    target_include_directories(DataPipes__shared PUBLIC ${PUBLIC_INCLUDE_DIRECTORIES})
    target_link_libraries(DataPipes__shared PRIVATE ${LIBRARIES_PRIVATE})

    set_target_properties(DataPipes__shared PROPERTIES EXPORT_NAME DataPipes::shared)
    add_library(DataPipes::shared ALIAS DataPipes__shared)
    install(TARGETS DataPipes__shared
            EXPORT DataPipes
            LIBRARY DESTINATION lib
    )
endif()