#include <sstream>
#include "json.hpp"
#include "include/rtc/AudioStream.h"

#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"

using namespace std;
using namespace std::chrono;
using namespace rtc;
using namespace rtc::codec;

AudioStream::AudioStream(rtc::PeerConnection *owner, rtc::StreamId id, const std::shared_ptr<rtc::AudioStream::Configuration> &config) : RTPStream(owner, id, config) { }

AudioStream::~AudioStream() { }

string AudioStream::sdp_media_type() const {
	return "audio";
}

StreamType AudioStream::type() const {
	return CHANTYPE_AUDIO;
}
