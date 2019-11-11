# Used for TeaSpeak
if (LIBNICE_PREBUILD_PATH AND GLIBC_PREBUILD_PATH)
    add_library(LibNice__LibNice INTERFACE)
    target_include_directories(LibNice__LibNice INTERFACE ${CMAKE_SOURCE_DIR}/${GLIBC_PREBUILD_PATH}/include/)
    target_include_directories(LibNice__LibNice INTERFACE ${CMAKE_SOURCE_DIR}/${GLIBC_PREBUILD_PATH}/lib/x86_64-linux-gnu/glib-2.0/include)
    target_include_directories(LibNice__LibNice INTERFACE ${CMAKE_SOURCE_DIR}/${GLIBC_PREBUILD_PATH}/lib/i386-linux-gnu/glib-2.0/include)

    target_include_directories(LibNice__LibNice INTERFACE ${CMAKE_SOURCE_DIR}/${LIBNICE_PREBUILD_PATH}/include)
    target_link_libraries(LibNice__LibNice INTERFACE ${CMAKE_SOURCE_DIR}/${LIBNICE_PREBUILD_PATH}/lib/libnice.so.10)

    add_library(LibNice::LibNice ALIAS LibNice__LibNice)
endif ()

if (NOT TARGET LibNice::LibNice)
    find_package(PkgConfig)
    pkg_check_modules(PC_LIBNICE nice)
    set(LIBNICE_DEFINITIONS ${PC_LIBNICE_CFLAGS_OTHER})

    find_path(LIBNICE_INCLUDE_DIR nice/agent.h
            HINTS ${PC_LIBNICE_INCLUDEDIR} ${PC_LIBNICE_INCLUDE_DIRS}
            PATH_SUFFICES libnice)
    find_library(LIBNICE_LIBRARY NAMES nice libnice
            HINTS ${PC_LIBNICE_LIBDIR} ${PC_LIBNICE_LIBRARY_DIRS})

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(Libnice DEFAULT_MSG
            LIBNICE_LIBRARY LIBNICE_INCLUDE_DIR)
    mark_as_advanced(LIBNICE_INCLUDE_DIR LIBNICE_LIBRARY)

    set(LIBNICE_LIBRARIES ${LIBNICE_LIBRARY})
    set(LIBNICE_INCLUDE_DIRS ${LIBNICE_INCLUDE_DIR})

    find_package(GLIB REQUIRED COMPONENTS gio gobject gmodule gthread)

    list(APPEND LIBNICE_INCLUDE_DIRS ${GLIB_INCLUDE_DIRS})
    list(APPEND LIBNICE_LIBRARIES ${GLIB_GOBJECT_LIBRARIES} ${GLIB_LIBRARIES})

    if (LIBNICE_FOUND)
        add_library(LibNice::LibNice UNKNOWN IMPORTED)
        set_target_properties(LibNice::LibNice PROPERTIES
                IMPORTED_LOCATION "${LIBNICE_LIBRARY}"
                INTERFACE_COMPILE_DEFINITIONS "_REENTRANT"
                INTERFACE_INCLUDE_DIRECTORIES "${LIBNICE_INCLUDE_DIRS}"
                INTERFACE_LINK_LIBRARIES "${LIBNICE_LIBRARIES}"
                IMPORTED_LINK_INTERFACE_LANGUAGES "C")
    endif ()
endif ()
