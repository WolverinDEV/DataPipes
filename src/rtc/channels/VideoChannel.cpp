#include "pipes/rtc/channels/VideoChannel.h"
#include "pipes/misc/logger.h"

#include <sstream>

using namespace std;
using namespace std::chrono;
using namespace rtc;
using namespace rtc::codec;

VideoChannel::VideoChannel(rtc::PeerConnection *owner, rtc::NiceStreamId id, const std::shared_ptr<rtc::VideoChannel::Configuration> &config) : MediaChannelHandler(owner, id, config) { }

VideoChannel::~VideoChannel() { }

string VideoChannel::sdp_media_type() const {
	return "video";
}

StreamType VideoChannel::type() const {
	return CHANTYPE_VIDEO;
}