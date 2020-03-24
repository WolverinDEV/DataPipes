#include "pipes/rtc/AudioStream.h"
#include "pipes/misc/logger.h"

#include <sstream>

using namespace std;
using namespace std::chrono;
using namespace rtc;
using namespace rtc::codec;

AudioStream::AudioStream(rtc::PeerConnection *owner, rtc::NiceStreamId id, const std::shared_ptr<rtc::AudioStream::Configuration> &config) : RTPStream(owner, id, config) { }

AudioStream::~AudioStream() { }

string AudioStream::sdp_media_type() const {
	return "audio";
}

StreamType AudioStream::type() const {
	return CHANTYPE_AUDIO;
}
