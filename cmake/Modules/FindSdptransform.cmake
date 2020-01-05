if (NOT TARGET Sdptransform)
    include(FindPackageHandleStandardArgs)
    find_path(SDPTRANSFORM_INCLUDE_DIR NAMES sdptransform.hpp PATH_SUFFICES sdptransform)
    find_library(SDPTRANSFORM_LIBRARY NAMES sdptransform)
    find_package_handle_standard_args(Sdptransform DEFAULT_MSG SDPTRANSFORM_INCLUDE_DIR SDPTRANSFORM_LIBRARY)


    add_library(Sdptransform INTERFACE)
    target_include_directories(Sdptransform INTERFACE ${SDPTRANSFORM_INCLUDE_DIR})
    target_link_libraries(Sdptransform INTERFACE ${SDPTRANSFORM_LIBRARY})
endif ()
