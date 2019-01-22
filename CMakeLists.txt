cmake_minimum_required(VERSION 3.9)
project(plugin CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_VERBOSE_MAKEFILE ON)

# Custom CMake modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/Modules")
#set(CMAKE_CXX_COMPILER "c++")

# Find packages
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
#find_package(OpenSSL REQUIRED)
find_package(LibNice REQUIRED)
find_package(UsrSCTP REQUIRED)

include_directories(libraries/sdptransform/include)

add_definitions(-DLOG_LEVEL=0) #FIXME!


set(HEADER_FILES
		#General definitions
		include/pipeline.h
		include/errors.h

		#The pipes
		include/ssl.h
		include/ws.h
		include/sctp.h
		include/tls.h
		include/buffer.h
		include/allocator.h

		#Helpers
		include/misc/http.h
		include/misc/endianness.h
		include/misc/logger.h
)

set(SOURCE_FILES
		src/pipeline.cpp

		src/ssl/ssl.cpp
		src/ssl/ssl_bio.cpp

		src/ws.cpp

		src/buffer.cpp
		src/allocator.cpp

		src/http/http.cpp

		src/tls.cpp
)

option(BUILD_WEBRTC "Build the WebRTC package" ON)
if(BUILD_WEBRTC)
	execute_process(
			COMMAND bash -c "pkg-config --cflags --libs glib-2.0"
			OUTPUT_VARIABLE GLIB_FLAGS
	)
    string(REPLACE "\t" " " GLIB_FLAGS "${GLIB_FLAGS}")
	string(REPLACE "\n" "" GLIB_FLAGS "${GLIB_FLAGS}")

	message("Got GLIB include directories ${GLIB_FLAGS}")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GLIB_FLAGS}")

	set(HEADER_FILES ${HEADER_FILES}
			#WebRTC
			include/rtc/Stream.h
			include/rtc/NiceWrapper.h
			include/rtc/PeerConnection.h
			include/rtc/ApplicationStream.h
			include/rtc/AudioStream.h
			include/rtc/MergedStream.h
	)


	set(SOURCE_FILES ${SOURCE_FILES}
			src/sctp.cpp

			src/rtc/Stream.cpp
			src/rtc/AudioStream.cpp
			src/rtc/ApplicationChannel.cpp
			src/rtc/NiceWrapper.cpp
			src/rtc/PeerConnection.cpp
			src/rtc/MergedStream.cpp
	)
endif()

add_library(DataPipes-Static STATIC ${HEADER_FILES} ${SOURCE_FILES})
add_library(DataPipes SHARED ${HEADER_FILES} ${SOURCE_FILES})
install(TARGETS DataPipes DESTINATION lib)
install(DIRECTORY include/ DESTINATION include/pipes)
set_target_properties(DataPipes-Static PROPERTIES OUTPUT_NAME DataPipes)

target_link_libraries(
		DataPipes
		LibNice::LibNice
		#SctpLab::UsrSCTP
		usrsctp.a
		sdptransform
		#srtp
		${CMAKE_SOURCE_DIR}/libraries/srtp/build/libsrtp2.a
		stdc++fs.a
)


add_definitions(-DUSE_BORINGSSL)
include_directories(/home/wolverindev/clib/boringssl/include)

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
			asound
			opus
	)

	add_executable(DataPipes-Test-SSL test/ssl_pipeline_server.cpp test/utils/socket.cpp)
	target_link_libraries(DataPipes-Test-SSL ${TEST_LIBRARIES})

	add_executable(DataPipes-Test-WS test/ws_pipeline.cpp test/utils/socket.cpp)
	target_link_libraries(DataPipes-Test-WS ${TEST_LIBRARIES})

	add_executable(DataPipes-Test-rtc-data test/rtc/rtc_test_data.cpp test/utils/socket.cpp test/json/jsoncpp.cpp)
	target_link_libraries(DataPipes-Test-rtc-data ${TEST_LIBRARIES})

	add_executable(DataPipes-Test-rtc-audio test/rtc/rtc_test_audio.cpp test/utils/socket.cpp test/json/jsoncpp.cpp)
	target_link_libraries(DataPipes-Test-rtc-audio ${TEST_LIBRARIES})

	add_executable(DataPipes-Test-buffers test/buffer.cpp)
	target_link_libraries(DataPipes-Test-buffers ${TEST_LIBRARIES})
endif()