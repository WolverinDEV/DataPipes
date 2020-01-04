#pragma once

#include <map>
#include <atomic>
#include <vector>
#ifdef LEGACY_SRTP
    #include <srtp/srtp.h>
#else
    #include <srtp2/srtp.h>
#endif
#include "Stream.h"
#include "Protocol.h"
#include "RtpStream.h"

namespace rtc {
    namespace codec { }

    class VideoStream : public RTPStream {
        public:
            VideoStream(PeerConnection* /* owner */, StreamId /* channel id */, const std::shared_ptr<Configuration>& /* configuration */);
            virtual ~VideoStream();

            StreamType type() const override;
        private:
        protected:
            std::string sdp_media_type() const override;
    };

}