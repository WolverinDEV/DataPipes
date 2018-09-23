#include <assert.h>
#include "include/rtc/PeerConnection.h"
#include "include/misc/endianness.h"
#include "include/rtc/Stream.h"

#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"

using namespace std;
using namespace rtc;

Stream::Stream(rtc::PeerConnection *_owner, rtc::StreamId _stream_id) : _owner(_owner), _stream_id(_stream_id) {}

void Stream::send_data(const std::string &data) {
	assert(this->_owner);
	assert(this->_stream_id > 0);

	if(!this->fail_buffer.empty() && !this->resend_buffer()) { //First try to resend everything to keep the order
		this->fail_buffer.push_back(data);
		return;
	}

	auto& nice = this->_owner->nice;
	if(!nice) return;

	if(!nice->send_data(this->_stream_id, 1, data) && this->buffer_fails)
		this->fail_buffer.push_back(data);
}

bool Stream::resend_buffer() {
	assert(this->_owner);
	assert(this->_stream_id > 0);

	auto& nice = this->_owner->nice;
	if(!nice) return false;

	while(!this->fail_buffer.empty()) {
		if(!nice->send_data(this->_stream_id, 1, this->fail_buffer.front())) return false;
		this->fail_buffer.pop_front();
	}
	return true;
}