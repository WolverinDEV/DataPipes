# Basic library sources
list(APPEND SOURCE_FILES
        src/ws.cpp
        src/tls.cpp
        src/pipeline.cpp
        src/buffer.cpp
        src/allocator.cpp

        src/ssl/ssl.cpp
        src/ssl/ssl_bio.cpp

        src/http/http.cpp
)

if (NOT WIN32)
    message("We're not on windows")
    list(APPEND SOURCE_FILES src/allocator_paged.cpp)
endif ()

list(APPEND PUBLIC_INCLUDE_DIRECTORIES include)