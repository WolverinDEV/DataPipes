#include <sstream>
#include "json.hpp"
#include "include/rtc/VideoStream.h"

#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"

using namespace std;
using namespace std::chrono;
using namespace rtc;
using namespace rtc::codec;

VideoStream::VideoStream(rtc::PeerConnection *owner, rtc::StreamId id, const std::shared_ptr<rtc::VideoStream::Configuration> &config) : RTPStream(owner, id, config) { }

VideoStream::~VideoStream() { }

string VideoStream::sdp_media_type() const {
	return "video";
}

StreamType VideoStream::type() const {
	return CHANTYPE_VIDEO;
}
