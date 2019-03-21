#include <netinet/in.h>
#include "include/rtc/Protocol.h"

using namespace rtc;

ssize_t protocol::rtp_payload_offset(const pipes::buffer_view& data, size_t max_length) {
	if(data.length() < 12) return -1;

	auto header = (protocol::rtp_header *) data.data_ptr();
	size_t header_length = 12; /* without variable ssrc and extentions */
	if(header->csrccount > 0)
		header_length += header->csrccount * 4;
	if(header->extension) {
		auto header_extension = (protocol::rtp_header_extension*) &data[header_length];
		auto extension_length = be16toh(header_extension->length);
		header_length += extension_length * 4 + sizeof(protocol::rtp_header_extension);
	}

	return header_length > max_length ? -1 : header_length;
}

int protocol::rtp_header_extension_parse_audio_level(const pipes::buffer_view& buffer, int id, int *level) {
	uint8_t byte = 0;
	if(protocol::rtp_header_extension_find(buffer, id, &byte, NULL, NULL) < 0)
	return -1;
	/* a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level */
	int v = (byte & 0x80) >> 7;
	int value = byte & 0x7F;
	if(level)
		*level = value;
	return 0;
}

/* Static helper to quickly find the extension data */
int protocol::rtp_header_extension_find(const pipes::buffer_view& buffer, int id, uint8_t *byte, uint32_t *word, char **ref) {
	if(buffer.length() < 12)
		return -1;
	auto* rtp = (protocol::rtp_header *) buffer.data_ptr();
	int hlen = 12;
	if(rtp->csrccount)	/* Skip CSRC if needed */
		hlen += rtp->csrccount*4;
	if(rtp->extension) {
		auto ext = (protocol::rtp_header_extension *)(buffer.data_ptr<char>() + hlen);
		int extlen = ntohs(ext->length)*4;
		hlen += 4;
		if(buffer.length() > (hlen + extlen)) {
			/* 1-Byte extension */
			if(ntohs(ext->type) == 0xBEDE) {
				const uint8_t padding = 0x00, reserved = 0xF;
				uint8_t extid = 0, idlen;
				int i = 0;
				while(i < extlen) {
					extid = buffer[hlen+i] >> 4;
					if(extid == reserved) {
						break;
					} else if(extid == padding) {
						i++;
						continue;
					}
					idlen = (buffer[hlen+i] & 0xF)+1;
					if(extid == id) {
						/* Found! */
						if(byte)
							*byte = buffer[hlen+i+1];
						if(word)
							*word = ntohl(*(uint32_t *)(buffer.data_ptr<char>()+hlen+i));
						if(ref)
							*ref = (char*) &buffer[hlen+i];
						return 0;
					}
					i += 1 + idlen;
				}
			}
			hlen += extlen;
		}
	}
	return -1;
}