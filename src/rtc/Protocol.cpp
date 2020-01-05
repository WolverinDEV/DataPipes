#include "pipes/rtc/Protocol.h"

#include <netinet/in.h>

using namespace rtc;

ssize_t protocol::rtp_payload_offset(const pipes::buffer_view& data) {
	if(data.length() < 12) return -1;

	auto header = (protocol::rtp_header *) data.data_ptr();
	size_t header_length = 12; /* without variable ssrc and extentions */
	if(header->csrccount > 0)
		header_length += header->csrccount * 4;
	if(header->extension) {
		auto header_extension = (const protocol::rtp_header_extension*) &data[header_length];
		auto extension_length = be16toh(header_extension->length);
		header_length += extension_length * 4 + sizeof(protocol::rtp_header_extension);
	}

	return header_length;
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

int protocol::rtp_header_extension_count(const pipes::buffer_view &buffer) {
	bool success;
	auto vector = rtp_header_extension_ids(buffer,success);
	return success ? vector.size() : -1;
}

const std::vector<int> protocol::rtp_header_extension_ids(const pipes::buffer_view &buffer, bool &success) {
	static std::vector<int> fail_result;
	static std::vector<int> empty_result;

	auto* rtp = (protocol::rtp_header *) buffer.data_ptr();

	if(buffer.length() < 12) {
		success = false;
		return fail_result;
	}

	if(!rtp->extension) {
		success = true;
		return empty_result;
	}

	int index = 12;
	if(rtp->csrccount)	/* Skip CSRC if needed */
		index += rtp->csrccount * 4;

	auto extensions = (protocol::rtp_header_extension *)(buffer.data_ptr<char>() + index);
	auto extensions_length = ntohs(extensions->length) * 4;
	index += 4; /* rtp_header_extension => 4 bytes */

	if(buffer.length() < (index + extensions_length)) {
		success = false;
		return fail_result;
	}

	/* 1-Byte extension */
	if(ntohs(extensions->type) == 0xBEDE) {
		std::vector<int> result;

		const uint8_t padding = 0x00, reserved = 0xF;
		uint8_t extid, idlen;
		int i = 0;

		while(i < extensions_length) {
			extid = static_cast<uint8_t>((buffer[index + i] >> 4) & 0xF);
			if(extid == reserved) {
				break;
			} else if(extid == padding) {
				i++;
				continue;
			}
			result.push_back(extid);
			idlen = (buffer[index + i] & 0xF) + 1;
			i += 1 + idlen;
		}

		success = true;
		return result;
	}

	success = false;
	return fail_result;
}

/* Static helper to quickly find the extension data */
int protocol::rtp_header_extension_find(const pipes::buffer_view& buffer, int id, uint8_t *byte, uint32_t *word, char **ref) {
	if(buffer.length() < 12)
		return -1;

	auto* rtp = (protocol::rtp_header *) buffer.data_ptr();
	int hlen = 12;

	if(rtp->csrccount)	/* Skip CSRC if needed */
		hlen += rtp->csrccount * 4;

	if(rtp->extension) {
		auto ext = (protocol::rtp_header_extension *)(buffer.data_ptr<char>() + hlen);
		int extlen = ntohs(ext->length) * 4;
		hlen += 4;
		if(buffer.length() > (hlen + extlen)) {
			/* 1-Byte extension */
			if(ntohs(ext->type) == 0xBEDE) {
				const uint8_t padding = 0x00, reserved = 0xF;
				uint8_t extid = 0, idlen;
				int i = 0;
				while(i < extlen) {
					extid = buffer[hlen + i] >> 4;
					if(extid == reserved) {
						break;
					} else if(extid == padding) {
						i++;
						continue;
					}
					idlen = (buffer[hlen+i] & 0xF) + 1;
					if(extid == id) {
						/* Found! */
						if(byte)
							*byte = buffer[hlen + i + 1];
						if(word)
							*word = ntohl(*(uint32_t *)(buffer.data_ptr<char>() + hlen + i));
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