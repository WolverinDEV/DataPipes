# - Try to find opus include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(opus)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  sdptransform_ROOT_DIR          Set this variable to the root installation of
#                            opus if the module has problems finding the
#                            proper installation path.
#
# Variables defined by this module:
#
#  sdptransform_FOUND             System has opus, include and library dirs found
#  sdptransform_INCLUDE_DIR       The opus include directories.
#  sdptransform_LIBRARIES_STATIC  The opus libraries.
#  sdptransform_LIBRARIES_SHARED  The opus libraries.

include(FindPackageHandleStandardArgs)

message("Dir: ${sdptransform_ROOT_DIR}")
function(resolve_sdptransform)
    find_path(sdptransform_INCLUDE_DIR
        NAMES sdptransform/sdptransform.hpp sdptransform/json.hpp
        HINTS ${sdptransform_ROOT_DIR} ${sdptransform_ROOT_DIR}/include/
    )

    if (NOT TARGET sdptransform::static)
        find_library(sdptransform_LIBRARIES_STATIC
            NAMES libsdptransform.a sdptransform.lib
            HINTS ${sdptransform_ROOT_DIR} ${sdptransform_ROOT_DIR}/lib
        )

        if(sdptransform_LIBRARIES_STATIC)
            add_library(sdptransform::static SHARED IMPORTED)
            set_target_properties(sdptransform::static PROPERTIES
                IMPORTED_LOCATION ${sdptransform_LIBRARIES_STATIC}
                INTERFACE_INCLUDE_DIRECTORIES ${sdptransform_INCLUDE_DIR}
            )
        endif()
    endif ()

    if (NOT TARGET sdptransform::shared)
        find_library(sdptransform_LIBRARIES_SHARED
                NAMES sdptransform.so sdptransform.dll
                HINTS ${sdptransform_ROOT_DIR} ${sdptransform_ROOT_DIR}/lib
        )

        if(sdptransform_LIBRARIES_SHARED)
            add_library(sdptransform::shared SHARED IMPORTED)
            set_target_properties(sdptransform::shared PROPERTIES
                    IMPORTED_LOCATION ${sdptransform_LIBRARIES_SHARED}
                    INTERFACE_INCLUDE_DIRECTORIES ${sdptransform_INCLUDE_DIR}
            )
        endif()
    endif ()

    find_package_handle_standard_args(sdptransform DEFAULT_MSG
            sdptransform_INCLUDE_DIR
    )
endfunction()
resolve_sdptransform()