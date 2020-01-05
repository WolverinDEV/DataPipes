if (NOT TARGET sdptransform)
    include(FindPackageHandleStandardArgs)
    find_path(SDPTRANSFORM_INCLUDE_DIR NAMES sdptransform.hpp PATH_SUFFICES sdptransform)
    find_library(SDPTRANSFORM_LIBRARY NAMES sdptransform)
    find_package_handle_standard_args(Sdptransform DEFAULT_MSG SDPTRANSFORM_INCLUDE_DIR SDPTRANSFORM_LIBRARY)

    add_library(Sdptransform INTERFACE IMPORTED)
    set_target_properties(Sdptransform PROPERTIES
            INTERFACE_LINK_LIBRARIES "${SDPTRANSFORM_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${SDPTRANSFORM_INCLUDE_DIR}")
endif ()
