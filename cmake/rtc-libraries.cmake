# glib
# When supplying a prebuild (may static) version of glib2.0
if (NOT GLIB_PREBUILD_LIBRARIES OR NOT GLIB_PREBUILD_INCLUDES)
    find_package(GLIB REQUIRED)
    list(APPEND LIBRARIES_PRIVATE ${GLIB_GIO_LIBRARIES})
else()
    list(APPEND LIBRARIES_PRIVATE ${GLIB_PREBUILD_LIBRARIES})
    list(APPEND PUBLIC_INCLUDE_DIRECTORIES ${GLIB_PREBUILD_INCLUDES})
endif()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GLIB_FLAGS}")

# sdptransform
set(BUNDLED_SDPTRANSFORM ON)
if (BUNDLED_SDPTRANSFORM)
    add_subdirectory(libraries/sdptransform)

    list(APPEND PUBLIC_INCLUDE_DIRECTORIES libraries/sdptransform/include)
    list(APPEND PUBLIC_COMPILER_DEFINITIONS -DSDPTRANSFORM_INTERNAL)
    list(APPEND LIBRARIES_PRIVATE sdptransform)
else()
    find_package(sdptransform REQUIRED)

    list(APPEND LIBRARIES_PRIVATE sdptransform)
endif ()

# SRTP
set(BUNDLED_SRTP ON)
if (BUNDLED_SRTP)
    function(bundled_srtp)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
        add_subdirectory(libraries/srtp)
    endfunction()
    bundled_srtp()

    list(APPEND PUBLIC_COMPILER_DEFINITIONS -DSRTP_BUNDLED)
    list(APPEND LIBRARIES_PRIVATE srtp2)
else()
    find_package(SRTP REQUIRED)

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

# UsrSCTP
set(BUNDLED_UsrSCTP ON)
if (BUNDLED_UsrSCTP)
    function(bundled_usrsctp)
        set(sctp_build_programs OFF CACHE BOOL "X")
        set(sctp_debug OFF CACHE BOOL "X")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-error=format-truncation=")
        add_subdirectory(libraries/usrsctp)
    endfunction()
    bundled_usrsctp()

    list(APPEND LIBRARIES_PRIVATE usrsctp-static)
else()
    find_package(UsrSCTP REQUIRED)
    list(APPEND LIBRARIES_PRIVATE SctpLab::UsrSCTP)
endif ()

# Libnice
find_package(LibNice REQUIRED)
list(APPEND LIBRARIES_PRIVATE LibNice::LibNice)