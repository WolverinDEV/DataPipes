#pragma once

#include <map>
#include <atomic>
#include <vector>
#include <srtp2/srtp.h>
#include "Stream.h"
#include "Protocol.h"
#include "RtpStream.h"

namespace rtc {
	namespace codec {
		struct OpusAudio : public Codec {
			uint16_t sample_rate = 0;
			std::string encoding;

			bool write_sdp(std::ostringstream& /* ss */) override;
			bool local_supported() const override;
		};
	}

	class AudioStream : public RTPStream {
		public:
			AudioStream(PeerConnection* /* owner */, StreamId /* channel id */, const std::shared_ptr<Configuration>& /* configuration */);
			virtual ~AudioStream();

			StreamType type() const override;

		private:
		protected:
			std::string sdp_media_type() const override;
	};

}