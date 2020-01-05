#pragma once

#include "./Stream.h"
#include "./Protocol.h"
#include "./RtpStream.h"

#include <map>
#include <atomic>
#include <vector>

namespace rtc {
    namespace codec { }

    class VideoStream : public RTPStream {
        public:
            VideoStream(PeerConnection* /* owner */, NiceStreamId /* channel id */, const std::shared_ptr<Configuration>& /* configuration */);
            virtual ~VideoStream();

            StreamType type() const override;
        private:
        protected:
            std::string sdp_media_type() const override;
    };

}