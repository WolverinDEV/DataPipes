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

# Sctp sources
if (WITH_UsrSCTP)
    message("Building with UsrSCTP support")

    list(APPEND SOURCE_FILES src/sctp.cpp)
    list(APPEND LIBRARIES_PRIVATE SctpLab::UsrSCTP)
endif ()

# RTC files
list(APPEND RTC_SOURCE_FILES
        src/rtc/ApplicationChannel.cpp
        src/rtc/AudioStream.cpp
        src/rtc/DTLSPipe.cpp
        src/rtc/NiceWrapper.cpp
        src/rtc/PeerConnection.cpp
        src/rtc/Protocol.cpp
        src/rtc/RtpStream.cpp
        src/rtc/Stream.cpp
        src/rtc/VideoStream.cpp
)