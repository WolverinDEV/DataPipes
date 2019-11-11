cmake_minimum_required(VERSION 3.9)
project(plugin CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_VERBOSE_MAKEFILE ON)

# Custom CMake modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/Modules")
#set(CMAKE_CXX_COMPILER "c++")

include_directories(libraries/sdptransform/include)

add_definitions(-DLOG_LEVEL=0) #FIXME!

option(BUILD_WEBRTC "Build the WebRTC package" ON)

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
if (NOT WIN32)
	message("We're not on windows (${WIN32}")
	set(SOURCE_FILES ${SOURCE_FILES} src/allocator_paged.cpp)
endif ()

#Crypto librarie (OpenSSL or BoringSSL)
find_package(Crypto REQUIRED)
include_directories(BEFORE SYSTEM ${Crypto_INCLUDE_DIR})
link_libraries (${Crypto_LIBRARIES})

if(CRYPTO_TYPE STREQUAL "openssl" AND NOT Crypto_OPENSSL)
	if(Crypto_BORINGSSL)
		message(FATAL_ERROR "Used to use OpenSSL, but found BoringSSL (${Crypto_INCLUDE_DIR}).\nConcider to set the OpenSSL root in Crypto_ROOT_DIR")
	elseif(NOT Crypto_OPENSSL)
		message(FATAL_ERROR "Used to use OpenSSL, but haven't found OpenSSL.\nConcider to set the OpenSSL root in Crypto_ROOT_DIR")
	endif()
elseif(CRYPTO_TYPE STREQUAL "boringssl")
	if(Crypto_OPENSSL)
		message(FATAL_ERROR "Used to use BoringSSL, but found OpenSSL (${Crypto_INCLUDE_DIR}).\nConcider to set the BoringSSL root in Crypto_ROOT_DIR")
	elseif(NOT Crypto_BORINGSSL)
		message(FATAL_ERROR "Used to use BoringSSL, but haven't found BoringSSL.\nConcider to set the BoringSSL root in Crypto_ROOT_DIR")
	endif()
elseif(CRYPTO_TYPE)
	message(FATAL_ERROR "Unknown CRYPTO_TYPE. Availible types: openssl | boringssl")
endif()

if(Crypto_OPENSSL)
	message("Using OpenSSL")
elseif(Crypto_BORINGSSL)
	add_definitions(-DUSE_BORINGSSL)
	message("Using BoringSSL")
else()
	message(FATAL_ERROR "Failed to detect crypto library type!")
endif()

if(BUILD_WEBRTC)
	# Find packages
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	find_package(Threads REQUIRED)
	find_package(LibNice REQUIRED)
	find_package(UsrSCTP REQUIRED)

	if (NOT GLIBC_PREBUILD_PATH)
		execute_process(
				COMMAND bash -c "pkg-config --cflags --libs glib-2.0"
				OUTPUT_VARIABLE GLIB_FLAGS
		)
		string(REPLACE "\t" " " GLIB_FLAGS "${GLIB_FLAGS}")
		string(REPLACE "\n" "" GLIB_FLAGS "${GLIB_FLAGS}")

		message("Got GLIB include directories ${GLIB_FLAGS}")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${GLIB_FLAGS}")
	endif ()

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

option(BUILD_STATIC "Build static library" ON)
option(BUILD_SHARED "Build shared library" ON)

macro(configure_msvc_runtime)
	if(MSVC)
		# Default to statically-linked runtime.
		if("${MSVC_RUNTIME}" STREQUAL "")
			set(MSVC_RUNTIME "static")
		endif()
		add_compile_options(/EHsc) # Enable unwind semantics

		# Set compiler options.
		set(variables
				CMAKE_C_FLAGS_DEBUG
				CMAKE_C_FLAGS_MINSIZEREL
				CMAKE_C_FLAGS_RELEASE
				CMAKE_C_FLAGS_RELWITHDEBINFO
				CMAKE_CXX_FLAGS_DEBUG
				CMAKE_CXX_FLAGS_MINSIZEREL
				CMAKE_CXX_FLAGS_RELEASE
				CMAKE_CXX_FLAGS_RELWITHDEBINFO
				)
		if(${MSVC_RUNTIME} STREQUAL "static")
			foreach(variable ${variables})
				if(${variable} MATCHES "/MD")
					string(REGEX REPLACE "/MD" "/MT" ${variable} "${${variable}}")
				endif()
			endforeach()
		else()
			foreach(variable ${variables})
				if(${variable} MATCHES "/MT")
					string(REGEX REPLACE "/MT" "/MD" ${variable} "${${variable}}")
				endif()
			endforeach()
		endif()
	endif()
endmacro()
configure_msvc_runtime()

if(BUILD_STATIC)
	add_library(DataPipes-Static STATIC ${HEADER_FILES} ${SOURCE_FILES})
	install(TARGETS DataPipes-Static DESTINATION lib)
	set_target_properties(DataPipes-Static PROPERTIES OUTPUT_NAME DataPipes)
endif()
if(BUILD_SHARED)
	add_library(DataPipes-Shared SHARED ${HEADER_FILES} ${SOURCE_FILES})
	install(TARGETS DataPipes-Shared DESTINATION lib)
	set_target_properties(DataPipes-Shared PROPERTIES OUTPUT_NAME DataPipes)
endif()
install(DIRECTORY include/ DESTINATION include/pipes)

if(BUILD_WEBRTC)
	target_link_libraries(
			DataPipes-Shared
			LibNice::LibNice
			#SctpLab::UsrSCTP
			usrsctp.a
			sdptransform
			#srtp
			${CMAKE_SOURCE_DIR}/libraries/srtp/build/libsrtp2.a
			stdc++fs.a
	)
endif()

if(BUILD_TESTS)
	set(TEST_LIBRARIES
			DataPipes-Static
			LibNice::LibNice
			#SctpLab::UsrSCTP
			usrsctp.a
			sdptransform
			#srtp
			${CMAKE_SOURCE_DIR}/libraries/srtp/build/libsrtp2.a
			stdc++fs.a

			DataPipes-Shared
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


	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")

	add_executable(DataPipes-Test-SSL test/ssl_pipeline_server.cpp test/utils/socket.cpp)
	target_link_libraries(DataPipes-Test-SSL ${TEST_LIBRARIES})

	add_executable(DataPipes-Test-WS test/ws_pipeline.cpp test/utils/socket.cpp)
	target_link_libraries(DataPipes-Test-WS ${TEST_LIBRARIES})

	add_executable(DataPipes-Test-rtc-data test/rtc/rtc_test_data.cpp test/utils/socket.cpp test/json/jsoncpp.cpp)
	target_link_libraries(DataPipes-Test-rtc-data ${TEST_LIBRARIES})

	add_executable(DataPipes-Test-rtc-audio test/rtc/rtc_test_audio.cpp test/utils/socket.cpp test/json/jsoncpp.cpp)
	target_link_libraries(DataPipes-Test-rtc-audio ${TEST_LIBRARIES})

	add_executable(DataPipes-Test-buffers include/buffer.h src/buffer.cpp src/allocator.cpp test/buffer.cpp)

	add_executable(DataPipes-Test-video test/video.cpp test/video/ivfenc.cpp)
	target_link_libraries(DataPipes-Test-video ${TEST_LIBRARIES} vpx)
endif()