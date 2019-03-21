#pragma once

#include <unistd.h>
#include <cstdint>
#include <vector>
#include "../buffer.h"

namespace rtc {
	/* Most copied from janus */
	namespace protocol {
		/*! \brief RTP Header (http://tools.ietf.org/html/rfc3550#section-5.1) */
		struct rtp_header {
#if __BYTE_ORDER == __BIG_ENDIAN
			uint16_t version:2;
			uint16_t padding:1;
			uint16_t extension:1;
			uint16_t csrccount:4;
			uint16_t markerbit:1;
			uint16_t type:7;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
			uint16_t csrccount:4;
			uint16_t extension:1;
			uint16_t padding:1;
			uint16_t version:2;
			uint16_t type:7;
			uint16_t markerbit:1;
#endif
			uint16_t seq_number;
			uint32_t timestamp;
			uint32_t ssrc;
			uint32_t csrc[0];
		};

		struct rtp_header_extension {
			uint16_t type;
			uint16_t length;
			uint8_t data[0];
		};

		/*! \brief RTCP Packet Types (http://www.networksorcery.com/enp/protocol/rtcp.htm) */
		enum rtcp_type : uint8_t {
			RTCP_FIR = 192,
			RTCP_SR = 200, /* SR, sender report */
			RTCP_RR = 201, /* RR, receiver report */
			RTCP_SDES = 202,
			RTCP_BYE = 203,
			RTCP_APP = 204,
			RTCP_RTPFB = 205,
			RTCP_PSFB = 206,
			RTCP_XR = 207,
		};


/*! \brief RTCP Header (http://tools.ietf.org/html/rfc3550#section-6.1) */
		struct rtcp_header {
#if __BYTE_ORDER == __BIG_ENDIAN
			uint16_t version:2;
			uint16_t padding:1;
			uint16_t rc:5;
			uint16_t type:8;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
			uint16_t rc:5;
			uint16_t padding:1;
			uint16_t version:2;
			uint16_t type:8;
#endif
			uint16_t length:16;

			uint32_t ssrc;
		};
		static_assert(sizeof(rtcp_header) == 8, "invalid rtcp header size");

		//https://android.googlesource.com/platform/external/webrtc/+/bdc0b0d869e9a14bbfafcbb84e294a13383e6fa6/webrtc/modules/rtp_rtcp/source/rtcp_packet.cc
		namespace rtcp {
			inline uint32_t swap_endianness(uint32_t input) {
				return  ((input >> 24) & 0xFF) <<  0 |
						((input >> 16) & 0xFF) <<  8 |
						((input >>  8) & 0xFF) << 16 |
						((input >>  0) & 0xFF) << 24;
			}

			struct sender_report {
				//  Sender report (SR) (RFC 3550).
				//   0                   1                   2                   3
				//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				//  |V=2|P|    RC   |   PT=SR=200   |             length            |
				//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				//  |                         SSRC of sender                        |
				//  +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
				//  |              NTP timestamp, most significant word             |
				//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				//  |             NTP timestamp, least significant word             |
				//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				//  |                         RTP timestamp                         |
				//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				//  |                     sender's packet count                     |
				//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				//  |                      sender's octet count                     |
				//  +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

				static constexpr size_t quad_size = 5;
				static constexpr size_t size = quad_size * 4;
				uint32_t* data_ptr;

				inline uint64_t network_timestamp() { return (uint64_t) swap_endianness(data_ptr[0]) << 32 | swap_endianness(data_ptr[1]); }

				inline sender_report& network_timestamp(uint64_t value) {
					data_ptr[0] = swap_endianness((uint32_t) (value >> 32));
					data_ptr[1] = swap_endianness((uint32_t) (value & 0xFFFF));
					return *this;
				}

				inline uint32_t rtp_timestamp() { return swap_endianness(data_ptr[2]); }

				inline sender_report& rtp_timestamp(uint32_t value) {
					data_ptr[2] = swap_endianness(value);
					return *this;
				}

				inline uint32_t packet_count() {
					return swap_endianness(data_ptr[3]);
				}

				inline sender_report& packet_count(uint32_t value) {
					data_ptr[3] = swap_endianness(value);
					return *this;
				}

				inline uint32_t octet_count() {
					return swap_endianness(data_ptr[4]);
				}

				inline sender_report& octet_count(uint32_t value) {
					data_ptr[4] = swap_endianness(value);
					return *this;
				}
			};

			struct report_block {
				//  Report block (RFC 3550).
				//
				//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				//  +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
				//  |                 SSRC_1 (SSRC of first source)                 |
				//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				//  | fraction lost |       cumulative number of packets lost       |
				//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				//  |           extended highest sequence number received           |
				//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				//  |                      interarrival jitter                      |
				//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				//  |                         last SR (LSR)                         |
				//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				//  |                   delay since last SR (DLSR)                  |
				//  +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

				static constexpr size_t quad_size = 6;
				static constexpr size_t size = quad_size * 4;
				uint32_t* data_ptr;

				inline uint32_t ssrc() { return swap_endianness(data_ptr[0]); }
				inline report_block& ssrc(uint32_t value) {
					data_ptr[0] = swap_endianness(value);
					return *this;
				}

				inline uint8_t fraction_lost() {
					return (uint8_t) (data_ptr[1] >> 24);
				}
				inline report_block& fraction_lost(uint8_t num) {
					data_ptr[1] &= 0xFFFFFF;
					data_ptr[1] |= num;
					return *this;
				}

				inline uint32_t packets_lost() {
					return swap_endianness(data_ptr[1] << 8);
				}
				inline report_block& packets_lost(uint32_t packets) {
					data_ptr[1] &= 0xFF000000;
					data_ptr[1] |= swap_endianness(packets) >> 8;
					return *this;
				}

				inline uint32_t highest_sequence_number() {
					return swap_endianness(data_ptr[2]);
				}
				inline report_block& highest_sequence_number(uint32_t value) {
					data_ptr[2] = swap_endianness(value);
					return *this;
				}

				inline uint32_t interarrival_jitter() {
					return swap_endianness(data_ptr[3]);
				}
				inline report_block& interarrival_jitter(uint32_t value) {
					data_ptr[3] = swap_endianness(value);
					return *this;
				}

				inline uint32_t  last_sender_report() {
					return swap_endianness(data_ptr[4]);
				}
				inline report_block& last_sender_report(uint32_t value) {
					data_ptr[4] = swap_endianness(value);
					return *this;
				}

				inline uint32_t delay_last_sender_report() {
					return swap_endianness(data_ptr[5]);
				}
				inline report_block& delay_last_sender_report(uint32_t value) {
					data_ptr[5] = swap_endianness(value);
					return *this;
				}
			};

			struct receiver_report {
				uint32_t* data_ptr;
				size_t data_length; /* length in bytes! */

				inline size_t report_blocks_count() {
					return data_length / report_block::size;
				}

				inline std::vector<report_block> report_blocks() {
					std::vector<report_block> result{report_blocks_count()};

					for(size_t index = 0; index < result.size(); index++)
						result[index].data_ptr = data_ptr + index * report_block::quad_size;

					return result;
				}
			};
		}

		inline bool is_rtcp(void *buf) {
			auto header = (protocol::rtp_header *) buf;
			return ((header->type >= 64) && (header->type < 96));
		}

		inline bool is_rtp(void *buf) {
			auto header = (protocol::rtp_header *) buf;
			return ((header->type < 64) || (header->type >= 96));
		}

		extern ssize_t rtp_payload_offset(const pipes::buffer_view & /* data */, size_t /* max_length */);

		extern int rtp_header_extension_find(const pipes::buffer_view & /* buffer */, int id, uint8_t *byte, uint32_t *word, char **ref);

		extern int rtp_header_extension_parse_audio_level(const pipes::buffer_view & /* buffer */, int id, int *level);
	}

	struct HeaderExtension {
		bool local = false;

		std::string name;
		uint8_t id;
		std::string direction;
		std::string config;
	};
}