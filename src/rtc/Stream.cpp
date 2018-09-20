#include <include/rtc/PeerConnection.h>
#include "include/misc/endianness.h"
#include "include/rtc/Stream.h"

#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"

using namespace std;
using namespace rtc;

Stream::Stream(rtc::PeerConnection *_owner, rtc::StreamId _stream_id) : _owner(_owner), _stream_id(_stream_id) {}

void Stream::send_data(const std::string &data) {
	assert(this->_owner);
	assert(this->_owner->nice);
	assert(this->_stream_id > 0);

	this->_owner->nice->send_data(this->_stream_id, 1, data);
}