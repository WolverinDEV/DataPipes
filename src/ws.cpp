#include "pipes/ws.h"
#include "pipes/errors.h"
#include "pipes/misc/logger.h"
#include "pipes/misc/endianness.h"

#include <iostream>
#include <cstring>
#include <openssl/sha.h>

using namespace std;
using namespace pipes;

WebSocket::WebSocket() : Pipeline("WebSocket") {}
WebSocket::~WebSocket() {}

void WebSocket::initialize() {
    this->state = WebSocketState::HANDSCHAKE;
}


ProcessResult WebSocket::process_data_in() {
    if(this->state == WebSocketState::UNINIZALISIZED)
        return PROCESS_RESULT_INVALID_STATE;

    if(this->state == WebSocketState::HANDSCHAKE) {
        auto result = this->process_handshake();
        if(result == PERROR_OK) return ProcessResult::PROCESS_RESULT_OK;
        if(result == PERROR_NO_DATA) return ProcessResult::PROCESS_RESULT_NEED_DATA;

        this->state = WebSocketState::UNINIZALISIZED;
        this->_callback_error(result, "Handshake failed!");
        return ProcessResult::PROCESS_RESULT_ERROR;
    } else {
        while(this->process_frame());
        return PROCESS_RESULT_OK;
    }
    return PROCESS_RESULT_ERROR;
}

static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";


static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];
        while((i++ < 3))
            ret += '=';
    }
    return ret;
}

/*
HTTP/1.1 200 OK
Date: Wed, 21 Mar 2018 15:34:05 GMT
Last-Modified: Wed, 01 Sep 2004 13:24:52 GMT
ETag: "277f-3e3073913b100-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Encoding: gzip
Cache-Control: max-age=21600
Expires: Wed, 21 Mar 2018 21:34:05 GMT
P3P: policyref="http://www.w3.org/2014/08/p3p.xml"
Content-Length: 2921
Content-Type: text/html; charset=iso-8859-1
Strict-Transport-Security: max-age=15552000; includeSubdomains; preload
Content-Security-Policy: upgrade-insecure-requests
 */
int WebSocket::process_handshake() {
    {
        size_t chunk_length = 1024;
        buffer chunk(chunk_length);
        while((chunk_length = this->buffer_read_read_bytes((char*) chunk.data_ptr(), chunk_length)) > 0)
            handshake_buffer += chunk.range(0, chunk_length);
    }

    auto header_end = handshake_buffer.find("\r\n\r\n");
    if(header_end < 0) return PERROR_NO_DATA; //Not full header!

    {
        auto overhead = this->handshake_buffer.range(header_end + 4); //TODO drop header here!
        if(overhead.length() > 0) {
            lock_guard<mutex> lock(this->buffer_lock);
            this->read_buffer.push_front(overhead);
        }
    }

    http::HttpRequest header;
    http::HttpResponse response;
    std::string key;
	bool success = false;


    if(!http::parse_request(handshake_buffer.string(), header)) return PERROR_HTTP_INVALID_HEADER;
    //Missing required keys
    if(!header.findHeader("Connection")) {
        response.code = http::code::code(501, "No type");
        callback_invalid_request(header, response);
        goto sendResponse;
    }

    //Firefox: Connection: Keep Alive | Upgrade: websocket
    if(header.findHeader("Connection").values[0] != "Upgrade" && !!header.findHeader("Upgrade") && header.findHeader("Upgrade").values[0] != "websocket") {
        response.code = http::code::code(501, "Invalid type " + header.findHeader("Connection").values[0]);
	    callback_invalid_request(header, response);
        goto sendResponse;
    }

    if(!header.findHeader("Sec-WebSocket-Version")) {
        response.code = http::code::code(400, "Missing websocket version");
	    callback_invalid_request(header, response);
        goto sendResponse;
    }
    if(!header.findHeader("Sec-WebSocket-Key")) {
        response.code = http::code::code(400, "Missing websocket key");
	    callback_invalid_request(header, response);
        goto sendResponse;
    }

    LOG_DEBUG(this->_logger, "WebSocket::process_handshake", "Recived WebSocket handshake!");
    LOG_VERBOSE(this->_logger, "WebSocket::process_handshake", "Version: %s", header.findHeader("Sec-WebSocket-Version").values[0].c_str());
	LOG_VERBOSE(this->_logger, "WebSocket::process_handshake", "Key    : %s", header.findHeader("Sec-WebSocket-Key").values[0].c_str());
    key = header.findHeader("Sec-WebSocket-Key").values[0];
    key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    response.code = http::code::_101;
    response.header.push_back({"Upgrade", {"websocket"}});
    response.header.push_back({"Connection", {"Upgrade"}});

    char keyDigest[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char *>(key.data()), key.length(), reinterpret_cast<unsigned char *>(keyDigest));
    key = base64_encode((uint8_t*) keyDigest, SHA_DIGEST_LENGTH);
    response.header.push_back({"Sec-WebSocket-Accept", {key}});
	success = true;

    sendResponse:
	auto resp = response.build();
    this->_callback_write(buffer_view((void*) resp.data(), resp.length()));

	if(success) {
		this->state = WebSocketState::CONNECTED;
		this->on_connect();
	}
    return ProcessResult::PROCESS_RESULT_OK;
}

#ifdef WIN32
__pragma(pack(push, 1));
#endif
struct WSHead {
    unsigned int len     : 7;
    bool mask   : 1;
    unsigned int opcode  : 4;
    bool rsv3   : 1;
    bool rsv2   : 1;
    bool rsv1   : 1;
    bool fin    : 1;
}
#ifdef WIN32
__pragma(pack(pop));
#else
__attribute__((packed)); //sizeof(WSHead) == 2
#endif

struct WSFrame {
    WSHead head{};
    uint64_t payloadLength = 0;
    uint8_t maskKey[4] = {0, 0, 0, 0};

    buffer data;
};


bool WebSocket::process_frame() {
    if(!this->current_frame) {
        auto available = this->buffer_read_bytes_available();
        if(available < 6) return false;

        this->current_frame.reset(new WSFrame{});
        {
            char header_buffer[2];
            this->buffer_read_read_bytes(header_buffer, 2);

            *(uint16_t*) &this->current_frame->head = be2le16(header_buffer);
        }
        if(this->current_frame->head.len < 126) {
            this->current_frame->payloadLength = this->current_frame->head.len;
        } else if(this->current_frame->head.len == 126) {
            char number_buffer[2];
            this->buffer_read_read_bytes(number_buffer, 2);
            this->current_frame->payloadLength = be2le16(number_buffer);
        } else if(this->current_frame->head.len == 127) {
            char number_buffer[8];
            this->buffer_read_read_bytes(number_buffer, 8);
            this->current_frame->payloadLength = be2le64(number_buffer);
        }

        if(this->current_frame->head.mask)
            this->buffer_read_read_bytes((char*) this->current_frame->maskKey, 4);
    }

    if(this->buffer_read_bytes_available() < this->current_frame->payloadLength) return false; //We need more data

	{
		buffer buffer(this->current_frame->payloadLength);
		auto read = this->buffer_read_read_bytes((char*) buffer.data_ptr(), this->current_frame->payloadLength);

		if(read < this->current_frame->payloadLength) {
			LOG_ERROR(this->_logger, "WebSocket::process_frame", "Failed to read full payload. Only read %i out of %i, but we already ensured the availability of the data!", read, this->current_frame->payloadLength);
			return false;
		}

		this->current_frame->data = std::move(buffer);
	}

    if(this->current_frame->head.mask) {
        for(size_t j = 0; j < this->current_frame->data.length(); j++)
            this->current_frame->data[j] = this->current_frame->data[j] ^ this->current_frame->maskKey[j % 4];
    }
    if(this->current_frame->head.opcode == 0x08) { //Disconnect!
        this->on_disconnect(this->current_frame->data.string());
        this->current_frame.reset();
        return true;
    }

    //TODO handle ping etc

    this->_callback_data(WSMessage{(OpCode) this->current_frame->head.opcode, this->current_frame->data});
    this->current_frame.reset();
    return true;
}

void WebSocket::disconnect(int code, const std::string &reason) {
	buffer buf(2 + reason.length());
	le2be16(code, (char*) buf.data_ptr());
	buf.write((void*) reason.data(), reason.length(), 2);
	this->send({OpCode::CLOSE, buf});
}

ProcessResult WebSocket::process_data_out() {
    WSMessage message;
    {
        lock_guard<mutex> lock(this->buffer_lock);
        if(this->write_buffer.empty()) return PROCESS_RESULT_OK;

        message = std::move(this->write_buffer[0]);
        this->write_buffer.pop_front();
    }
    WSHead head{};
    head.mask = false;
    head.fin = true;
    head.opcode = message.code;

    int lenLen = message.data.length() >= 126 ? message.data.length() >= 0xFFFF ? 8 : 2 : 0;
    if(lenLen == 0) head.len = message.data.length();
    else if(lenLen == 2) head.len = 126;
    else if(lenLen == 8) head.len = 127;

    buffer buffer;
    buffer.resize(sizeof(WSHead) + lenLen + message.data.length()); //Allocate buffer :)

    le2be16(*(uint16_t*) &head, (char*) buffer.data_ptr(), 0);
    if(lenLen == 2)
        le2be16(static_cast<uint16_t>(message.data.length()), (char*) buffer.data_ptr(), sizeof(WSHead));
    else if(lenLen == 8)
        le2be64(message.data.length(), (char*) buffer.data_ptr(), sizeof(WSHead));

    memcpy(&buffer[sizeof(WSHead) + lenLen], message.data.data_ptr(), message.data.length());

    this->_callback_write(buffer);

    return ProcessResult::PROCESS_RESULT_OK;
}
