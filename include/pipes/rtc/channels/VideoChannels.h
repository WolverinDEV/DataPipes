#pragma once

#include "Channel.h"
#include "pipes/rtc/Protocol.h"
#include "MediaChannel.h"

#include <map>
#include <atomic>
#include <vector>

namespace rtc {
    namespace codec { }

    class VideoChannel : public MediaStream {
        public:
            VideoChannel(PeerConnection* /* owner */, NiceStreamId /* channel id */, const std::shared_ptr<Configuration>& /* configuration */);
            ~VideoChannel() override;

            [[nodiscard]] StreamType type() const override;
        private:
        protected:
            [[nodiscard]] std::string sdp_media_type() const override;
    };

}