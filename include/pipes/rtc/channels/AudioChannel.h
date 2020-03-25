#pragma once

#include <map>
#include <atomic>
#include <vector>
#include "pipes/buffer.h"
#include "Channel.h"
#include "pipes/rtc/Protocol.h"
#include "MediaChannel.h"

namespace rtc {
	class AudioChannel : public MediaStream {
		public:
			AudioChannel(PeerConnection* /* owner */, NiceStreamId /* channel id */, const std::shared_ptr<Configuration>& /* configuration */);
			virtual ~AudioChannel();

			StreamType type() const override;
		private:
		protected:
			std::string sdp_media_type() const override;
	};

}