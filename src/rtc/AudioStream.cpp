#include <sstream>
#include "json.hpp"
#include "include/rtc/AudioStream.h"

#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"

using namespace std;
using namespace std::chrono;
using namespace rtc;
using namespace rtc::codec;

bool OpusAudio::write_sdp(std::ostringstream &sdp) {
	sdp << "a=rtpmap:" << (uint32_t) this->id << " opus/" << this->sample_rate << "/2\r\n"; //We want opus music 48kHz
	sdp << "a=fmtp:" << (uint32_t) this->id << " maxplaybackrate=16000; stereo=0; sprop-stereo=0; useinbandfec=1\r\n"; //Some opus specs
	return true;
}

bool OpusAudio::local_supported() const { return true; }

AudioStream::AudioStream(rtc::PeerConnection *owner, rtc::StreamId id, const std::shared_ptr<rtc::AudioStream::Configuration> &config) : RTPStream(owner, id, config) { }

AudioStream::~AudioStream() { }

string AudioStream::sdp_media_type() const {
	return "audio";
}

StreamType AudioStream::type() const {
	return CHANTYPE_AUDIO;
}
