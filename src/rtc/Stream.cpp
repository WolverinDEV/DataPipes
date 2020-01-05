#include "pipes/rtc/Stream.h"
#include "pipes/rtc/PeerConnection.h"
#include "pipes/rtc/DTLSPipe.h"
#include "pipes/misc/logger.h"

#include <cassert>

using namespace std;
using namespace rtc;

Stream::Stream(rtc::PeerConnection *_owner, rtc::NiceStreamId _nice_stream_id) : _owner{_owner}, _nice_stream_id{_nice_stream_id} {}

void Stream::send_data(const pipes::buffer_view &data, bool dtls_encrypt) {
	std::shared_lock owner_lock(this->_owner_lock);
	if(!this->_owner) return; /* peer walked away */
	if(this->_nice_stream_id == 0) __throw_logic_error("missing nice stream id");

    std::shared_lock stream_lock(this->_owner->stream_lock);
	for(const auto& stream : this->_owner->dtls_streams) {
	    if(stream->nice_stream_id() == this->_nice_stream_id) {
	        stream->send_data(data, dtls_encrypt);
	        return;
	    }
	}

    __throw_logic_error("missing dtls pipe");
}