#include "pipes/rtc/VideoStream.h"
#include "pipes/misc/logger.h"

#include <sstream>

using namespace std;
using namespace std::chrono;
using namespace rtc;
using namespace rtc::codec;

VideoStream::VideoStream(rtc::PeerConnection *owner, rtc::NiceStreamId id, const std::shared_ptr<rtc::VideoStream::Configuration> &config) : RTPStream(owner, id, config) { }

VideoStream::~VideoStream() { }

string VideoStream::sdp_media_type() const {
	return "video";
}

StreamType VideoStream::type() const {
	return CHANTYPE_VIDEO;
}