cmake_minimum_required(VERSION 3.9)
project(plugin CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
#set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 14)

set(HEADER_FILES
        include/pipeline.h
        include/errors.h

        include/ssl.h

        include/http.h
        include/endianness.h
        include/ws.h
)

set(SOURCE_FILES
        src/pipeline.cpp

        src/ssl/ssl.cpp
        src/ssl/ssl_bio.cpp

        src/ws/ws.cpp

        src/http/http.cpp
)

add_library(DataPipes ${HEADER_FILES} ${SOURCE_FILES})

add_definitions(-DUSE_BORINGSSL)
include_directories(/home/wolverindev/clib/boringssl/include)

set(TEST_LIBRARIES
        DataPipes
        event
        event_pthreads
        /home/wolverindev/clib/boringssl/build/ssl/libssl.so
        /home/wolverindev/clib/boringssl/build/crypto/libcrypto.so
        pthread
)

add_executable(DataPipes-Test-SSL test/ssl_pipeline.cpp test/utils/socket.cpp)
target_link_libraries(DataPipes-Test-SSL ${TEST_LIBRARIES})

add_executable(DataPipes-Test-WS test/ws_pipeline.cpp test/utils/socket.cpp)
target_link_libraries(DataPipes-Test-WS ${TEST_LIBRARIES})