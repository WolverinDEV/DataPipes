#include "pipes/rtc/channels/AudioChannel.h"
#include "pipes/misc/logger.h"

#include <sstream>

using namespace std;
using namespace std::chrono;
using namespace rtc;
using namespace rtc::codec;

AudioChannel::AudioChannel(rtc::PeerConnection *owner, rtc::NiceStreamId id, const std::shared_ptr<rtc::AudioChannel::Configuration> &config) : MediaChannelHandler(owner, id, config) { }

AudioChannel::~AudioChannel() = default;

string AudioChannel::sdp_media_type() const {
	return "audio";
}

StreamType AudioChannel::type() const {
	return CHANTYPE_AUDIO;
}
