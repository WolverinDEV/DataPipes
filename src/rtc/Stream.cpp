#include <cassert>
#include "include/rtc/PeerConnection.h"
#include "include/rtc/MergedStream.h"
#include "include/rtc/Stream.h"
#include "include/misc/logger.h"

using namespace std;
using namespace rtc;

Stream::Stream(rtc::PeerConnection *_owner, rtc::StreamId _stream_id) : _owner(_owner), _stream_id(_stream_id) {}

void Stream::send_data(const pipes::buffer_view&data) {
	shared_lock owner_lock(this->_owner_lock);
	if(!this->_owner) return; //Should never happen
	if(this->_stream_id == 0) __throw_logic_error("stream is a merges stream");

	if(!this->fail_buffer.empty() && !this->resend_buffer(false)) { //First try to resend everything to keep the order
		this->fail_buffer.push_back(data.own_buffer());
		return;
	}

	shared_lock stream_lock(this->_owner->stream_lock);
	if(!this->_owner->nice) return;

	if(!this->_owner->nice->send_data(this->_stream_id, 1, data) && this->buffer_fails) {
		lock_guard buffer_lock(this->fail_buffer_lock);
		this->fail_buffer.push_back(data.own_buffer());
	}
}

void Stream::send_data_merged(const pipes::buffer_view&data, bool dtls) {
	shared_lock owner_lock(this->_owner_lock);
	if(!this->_owner) return; //Should never happen
	if(this->_stream_id != 0) __throw_logic_error("stream isn't a merges stream");

	shared_lock stream_lock(this->_owner->stream_lock);
	if(!this->_owner->merged_stream) return; //Should never happen

	if(dtls)
		this->_owner->merged_stream->send_data_dtls(data);
	else
		this->_owner->merged_stream->send_data(data);
}

bool Stream::resend_buffer(bool lock) {
	if(lock) {
		shared_lock owner_lock(this->_owner_lock);
		return this->resend_buffer(false);
	}

	if(!this->_owner) return false; //Should never happen
	shared_lock stream_lock(this->_owner->stream_lock);

	if(this->_stream_id == 0) {
		if(!this->_owner->merged_stream) return false;
		return this->_owner->merged_stream->resend_buffer(false);
	}

	if(!this->_owner->nice) return false;

	{
		lock_guard buffer_lock(this->fail_buffer_lock);
		while(!this->fail_buffer.empty()) {
			if(!this->_owner->nice->send_data(this->_stream_id, 1, this->fail_buffer.front())) return false;
			this->fail_buffer.pop_front();
		}}
	return true;
}