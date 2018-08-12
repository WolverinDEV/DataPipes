cmake_minimum_required(VERSION 3.9)
project(plugin CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
#set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 14)

set(CMAKE_MACOSX_RPATH 1)
# Custom CMake modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/Modules")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

# Find packages
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
#find_package(OpenSSL REQUIRED)
find_package(LibNice REQUIRED)
find_package(UsrSCTP REQUIRED)

add_definitions(-DLOG_LEVEL=0) #FIXME!

set(HEADER_FILES
		#General definitions
        include/pipeline.h
        include/errors.h

		#The pipes
        include/ssl.h
		include/ws.h
		include/sctp.h
		include/dtls.h

		#Helpers
		include/misc/http.h
		include/misc/endianness.h
		include/misc/logger.h

		#WebRTC
		include/rtc/NiceWrapper.h
		include/rtc/PeerConnection.h
)

set(SOURCE_FILES
        src/pipeline.cpp

        src/ssl/ssl.cpp
        src/ssl/ssl_bio.cpp

		src/ws.cpp

        src/http/http.cpp

		src/sctp.cpp

		src/rtc/NiceWrapper.cpp
		src/rtc/PeerConnection.cpp
		src/dtls.cpp
)

add_library(DataPipes SHARED ${HEADER_FILES} ${SOURCE_FILES})
install(TARGETS DataPipes DESTINATION lib)
install(DIRECTORY include/ DESTINATION include/pipes)

target_link_libraries(
        DataPipes
        PUBLIC
        LibNice::LibNice
        #SctpLab::UsrSCTP
        usrsctp.a
)


add_definitions(-DUSE_BORINGSSL)
include_directories(/home/wolverindev/clib/boringssl/include)

option(BUILD_TESTS ON "Build test cases")
if(BUILD_TESTS)
	set(TEST_LIBRARIES
       		DataPipes
        	event
        	event_pthreads
        	#/home/wolverindev/clib/boringssl/build/ssl/libssl.so
        	#/home/wolverindev/clib/boringssl/build/crypto/libcrypto.so
		/home/wolverindev/TeaSpeak/libraries/boringssl/build/ssl/libssl.so
		/home/wolverindev/TeaSpeak/libraries/boringssl/build/crypto/libcrypto.so
		pthread
	)

	add_executable(DataPipes-Test-SSL test/ssl_pipeline_server.cpp test/utils/socket.cpp)
	target_link_libraries(DataPipes-Test-SSL ${TEST_LIBRARIES})

	add_executable(DataPipes-Test-WS test/ws_pipeline.cpp test/utils/socket.cpp)
	target_link_libraries(DataPipes-Test-WS ${TEST_LIBRARIES})

	add_executable(DataPipes-Test-rtc test/rtc/rtc_test.cpp test/utils/socket.cpp test/json/jsoncpp.cpp)
	target_link_libraries(DataPipes-Test-rtc ${TEST_LIBRARIES})
endif()
