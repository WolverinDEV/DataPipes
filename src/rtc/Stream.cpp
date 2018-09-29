#include <cassert>
#include "include/rtc/PeerConnection.h"
#include "include/rtc/MergedStream.h"
#include "include/rtc/Stream.h"

#define DEFINE_LOG_HELPERS
#include "include/misc/logger.h"

using namespace std;
using namespace rtc;

Stream::Stream(rtc::PeerConnection *_owner, rtc::StreamId _stream_id) : _owner(_owner), _stream_id(_stream_id) {}

void Stream::send_data(const pipes::buffer_view&data) {
	if(!this->_owner) return; //Should never happen
	assert(this->_stream_id > 0);

	if(!this->fail_buffer.empty() && !this->resend_buffer()) { //First try to resend everything to keep the order
		this->fail_buffer.push_back(data.own_buffer());
		return;
	}

	auto& nice = this->_owner->nice;
	if(!nice) return;

	if(!nice->send_data(this->_stream_id, 1, data) && this->buffer_fails)
		this->fail_buffer.push_back(data.own_buffer());
}

void Stream::send_data_merged(const pipes::buffer_view&data, bool dtls) {
	if(!this->_owner) return; //Should never happen
	if(!this->_owner->merged_stream) return; //Should never happen
	assert(this->_stream_id == 0);

	if(dtls)
		this->_owner->merged_stream->send_data_dtls(data);
	else
		this->_owner->merged_stream->send_data(data);
}

bool Stream::resend_buffer() {
	if(this->_stream_id == 0) {
		if(!this->_owner) return false;
		if(!this->_owner->merged_stream) return false;

		return this->_owner->merged_stream->resend_buffer();
	}
	if(!this->_owner) return false; //Should never happen

	auto& nice = this->_owner->nice;
	if(!nice) return false;

	while(!this->fail_buffer.empty()) {
		if(!nice->send_data(this->_stream_id, 1, this->fail_buffer.front())) return false;
		this->fail_buffer.pop_front();
	}
	return true;
}