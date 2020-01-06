#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <thread>
#include <cstring>
#include <bitset>

#include <pipes/ssl.h>
#include <pipes/ws.h>
#include <pipes/rtc/PeerConnection.h>
#include <pipes/rtc/ApplicationStream.h>
#include <pipes/rtc/AudioStream.h>
#include <pipes/rtc/VideoStream.h>

#include "./video_utils.h"
#include "../utils/socket.h"
#include "../json/json.h"

#include <vpx/vpx_encoder.h>
#include <vpx/vpx_decoder.h>
#include <vpx/vp8cx.h>
#include <vpx/vp8dx.h>

#ifdef HAVE_GLIB
    #include <glib.h>
#endif

using namespace std;


#define V_FPS 1
#define V_KEYFRAME_INTERVAL 1

#define V_WIDTH  (128 * 16)
#define V_HEIGHT (128 * 16)

struct Color {
	uint8_t r;
	uint8_t g;
	uint8_t b;
};

const static Color c_pattern[6] {
		Color{0xFF, 0, 0},
		Color{0, 0, 0},
		Color{0, 0xFF, 0},
		Color{0, 0, 0},
		Color{0, 0, 0xFF},
		Color{0, 0, 0}
};

static int frame = 0;
static vpx_image_t* vpx_img_generate(vpx_image_t* handle) {
	auto rgb_buffer = new uint8_t[V_WIDTH * V_HEIGHT * 3];
	auto yuv420_buffer = new uint8_t[vutils::codec::I430_size(V_WIDTH, V_HEIGHT)];

	int c_index = frame++;
	{ /* generate RGB image */
		size_t buffer_index = 0;
		for(int d_w = 0; d_w < V_WIDTH; d_w++) {
			for(int d_h = 0; d_h < V_HEIGHT; d_h++) {
				auto& color = c_pattern[c_index % 6];
				rgb_buffer[buffer_index++] = color.r;
                rgb_buffer[buffer_index++] = color.g;
				rgb_buffer[buffer_index++] = color.b;
			}
		}
	}

	vutils::codec::RGBtoI420(rgb_buffer, yuv420_buffer, V_WIDTH, V_HEIGHT);
	handle = vpx_img_wrap(handle, VPX_IMG_FMT_I420, V_WIDTH, V_HEIGHT, 1, (u_char*) yuv420_buffer);

	delete[] (uint8_t*) handle->user_priv;
	handle->user_priv = yuv420_buffer;

	delete[] rgb_buffer;
	return handle;
}



struct Client {
	std::weak_ptr<Socket::Client> connection;
	unique_ptr<pipes::SSL> ssl;
	unique_ptr<pipes::WebSocket> websocket;

	/* WebRTC */
	unique_ptr<rtc::PeerConnection> peer;

	Json::Reader reader;
	Json::StreamWriterBuilder json_writer;

	bool ice_send = false;
};

const std::string currentDateTime() {
	time_t     now = time(0);
	struct tm  tstruct;
	char       buf[80];
	tstruct = *localtime(&now);
	// Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
	// for more information about date/time format
	strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);

	return buf;
}

void log(pipes::Logger::LogLevel level, const std::string& name, const std::string& message, ...) {
	auto max_length = 1024 * 32;
	char buffer[max_length];

	va_list args;
	va_start(args, message);
	max_length = vsnprintf(buffer, max_length, message.c_str(), args);
	va_end(args);

	printf("[%s][%i][%s] %s\n", currentDateTime().c_str(), level, name.c_str(), buffer);
}

auto config = []{
	auto config = make_shared<rtc::PeerConnection::Config>();
	config->nice_config = make_shared<rtc::NiceWrapper::Config>();

	//config->sctp.local_port = 49203; //Currently audio part only!
	//config->nice_config->ice_servers.push_back({"stun.l.google.com", 19302});

	//config->nice_config->ice_pwd = "asdasdasasdasdasdasdasdasddasdasdasd";
	//config->nice_config->ice_ufrag = "asdasd";
#ifdef HAVE_GLIB
	config->nice_config->main_loop = std::shared_ptr<GMainLoop>(g_main_loop_new(nullptr, false), g_main_loop_unref);
	std::thread(g_main_loop_run, config->nice_config->main_loop.get()).detach(); //FIXME
#endif

	config->logger = make_shared<pipes::Logger>();
	config->logger->callback_log = log;

	return config;
}();

#define TEST_CERTIFICATE_PATH "test_certificate.pem"
#define TEST_PRIVATE_KEY_PATH "test_private_key.pem"
std::unique_ptr<pipes::TLSCertificate> certificates;

void initializes_certificates() {
	try {
		certificates = make_unique<pipes::TLSCertificate>(TEST_CERTIFICATE_PATH, TEST_PRIVATE_KEY_PATH, true);
		return;
	} catch(const std::exception& ex) {
		cerr << "Failed to load certificates from file: " << ex.what() << endl;
		cerr << "Generating new one" << endl;
	}

	certificates = pipes::TLSCertificate::generate("TeaSpeak-Test", 356);
	assert(certificates);

	certificates->save_file(TEST_CERTIFICATE_PATH, TEST_PRIVATE_KEY_PATH);
}

void initialize_client(const std::shared_ptr<Socket::Client>& connection) {
	cout << "Got new client" << endl;

	auto client = new Client{};
	client->connection = connection;
	client->websocket = make_unique<pipes::WebSocket>();
	client->peer = make_unique<rtc::PeerConnection>(config);

	{
		client->ssl = make_unique<pipes::SSL>();
		//client->ssl->logger(config->logger);
		client->ssl->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
		client->ssl->direct_process(pipes::PROCESS_DIRECTION_IN, true);

		{
			auto options = make_shared<pipes::SSL::Options>();
			options->context_method = SSLv23_method();
			options->type = pipes::SSL::SERVER;
			options->free_unused_keypairs = true;
			options->enforce_sni = true;

			options->default_keypair(pipes::SSL::Options::KeyPair{certificates->ref_private_key(), certificates->ref_certificate()});
			if(!client->ssl->initialize(options)) {
				cerr << "Failed to initialize client" << endl;
				return; //FIXME Cleanup?
			}
		}

		client->ssl->callback_data([client](const pipes::buffer_view& data) {
			client->websocket->process_incoming_data(data);
		});
		client->ssl->callback_write([client](const pipes::buffer_view& data) {
			auto cl = client->connection.lock();
			if(cl) cl->send(data);
		});
		client->ssl->callback_error([client](int code, const string& message) {
			cerr << "ssl error " << code << " -> " << message << endl;
		});
	}

	{
		client->websocket->initialize();
		client->websocket->logger(config->logger);
		client->websocket->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
		client->websocket->direct_process(pipes::PROCESS_DIRECTION_IN, true);


		client->websocket->callback_error([client](int code, const std::string& reason) {
			//if(cl) cl->disconnect(false);
			cout << "Got error: " << code << " => " << reason << endl;

		});
		client->websocket->callback_write([client](const pipes::buffer_view& data) -> void {
			if(client->ssl)
				client->ssl->send(data);
			else {
				auto cl = client->connection.lock();
				if(cl) cl->send(data);
			}
		});
	}

	{
		client->websocket->callback_data([client](const pipes::WSMessage& message) {
			string error;
			Json::Value root;

			cout << "Got message " << message.data << endl;
			if(client->reader.parse(message.data.string(), root)) {
				std::cout << "Got msg of type: " << root["type"] << endl;
				if (root["type"] == "offer") {
					cout << "Recived offer" << endl;

					if(!client->peer->apply_offer(error, root["msg"]["sdp"].asString())) {
					    std::cerr << "failed to apply offer: " << error << "\n";
					    return;
					}

					{
						Json::Value answer;
						answer["type"] = "answer";
						answer["msg"]["sdp"] = client->peer->generate_answer(false);
						answer["msg"]["type"] = "answer";

						std::cout << "Sending Answer: " << answer << endl;

						pipes::buffer buffer;
						buffer += Json::writeString(client->json_writer, answer);
						client->websocket->send({pipes::OpCode::TEXT, buffer});
					}
				} else if (root["type"] == "candidate") {
					cout << "Apply candidates: " << client->peer->apply_ice_candidates(
							deque<shared_ptr<rtc::IceCandidate>> { make_shared<rtc::IceCandidate>(root["msg"]["candidate"].asString(), root["msg"]["sdpMid"].asString(), root["msg"]["sdpMLineIndex"].asInt()) }
					) << endl;
				} else if (root["type"] == "candidate_finish") {
					//client->peer->gather();
					client->peer->execute_negotiation();
				}
			} else {
				cerr << "Failed to parse json" << endl;
			}
		});
	}

	{
		client->peer->callback_ice_candidate = [client](const rtc::IceCandidate& ice, bool finished) {
			Json::Value jsonCandidate;
			jsonCandidate["type"] = "candidate";
			jsonCandidate["finished"] = finished;
			jsonCandidate["msg"]["candidate"] = ice.candidate;
			jsonCandidate["msg"]["sdpMid"] = ice.sdpMid;
			jsonCandidate["msg"]["sdpMLineIndex"] = ice.sdpMLineIndex;

			cout << "Sending ice candidate " << ice.candidate << " (" << ice.sdpMid << " | " << ice.sdpMLineIndex << "). Last: " << finished << endl;
			//client->websocket->send({pipes::OpCode::TEXT, Json::writeString(client->json_writer, jsonCandidate)});
		};

		client->peer->callback_new_stream = [client](const shared_ptr<rtc::Stream>& stream) {
			if(stream->type() == rtc::CHANTYPE_APPLICATION) {
				auto data_channel = dynamic_pointer_cast<rtc::ApplicationStream>(stream);
				data_channel->callback_datachannel_new = [](const std::shared_ptr<rtc::DataChannel>& channel) {
					weak_ptr<rtc::DataChannel> weak = channel;
					channel->callback_binary = [weak](const pipes::buffer_view& message) {
						auto chan = weak.lock();
						cout << "[DataChannel][" << chan->id() << "|" << chan->lable() << "] Got binary message " << message.length() << endl;
						pipes::buffer buf;
						buf += "Echo (BIN): ";
						buf += message;
						chan->send(buf, rtc::DataChannel::BINARY);
					};
					channel->callback_text = [weak](const pipes::buffer_view& message) {
						auto chan = weak.lock();
						if(message.string() == "close") {
							cout << "[DataChannel][" << chan->id() << "|" << chan->lable() << "] closing channel" << endl;
							chan->close();
						} else {
							cout << "[DataChannel][" << chan->id() << "|" << chan->lable() << "] Got text message " << message.length() << endl;
							pipes::buffer buf;
							buf += "Echo (TEXT): ";
							buf += message;
							//chan->send(buf, rtc::DataChannel::TEXT);
						}
					};
					channel->callback_close = [weak]() {
						auto chan = weak.lock();
						cout << "[DataChannel][" << chan->id() << "|" << chan->lable() << "] got closed" << endl;
					};
				};
			}
			else if(stream->type() == rtc::CHANTYPE_AUDIO) {
				auto astream = dynamic_pointer_cast<rtc::AudioStream>(stream);
				assert(astream);
				{
					auto opus_codec = astream->find_codecs_by_name("opus");
					if(opus_codec.empty()) {
						return; //FIXME disconnect client
					}

					opus_codec[0]->accepted = true; /* we accept the codec opus */
					for(const auto& codec: opus_codec)
						astream->register_local_channel("voice_bridge_" + to_string(codec->id), "client_" + to_string(codec->id), opus_codec.back());
				}
				astream->register_local_extension("urn:ietf:params:rtp-hdrext:ssrc-audio-level");

				weak_ptr<rtc::AudioStream> weak_astream = astream;
				astream->incoming_data_handler = [&, weak_astream](const std::shared_ptr<rtc::Channel>& channel, const pipes::buffer_view& buffer, size_t payload_offset) {
					auto as = weak_astream.lock();
					if(!as) return;

					for(const auto& ext : as->list_extensions(rtc::direction::bidirectional)) {
						if(ext->name == "urn:ietf:params:rtp-hdrext:ssrc-audio-level") {
							int level;
							if(rtc::protocol::rtp_header_extension_parse_audio_level(buffer, ext->id, &level) == 0) {
								//cout << "Audio level " << level << endl;
							}
							break;
						}
					}

					auto buf = buffer.view(payload_offset);
					auto channels = as->list_channels();
					for(const auto& ch : channels)
						if(ch->local)
							as->send_rtp_data(ch, buf, ch->timestamp_last_send += 960); //960 = 20ms opus :)
				};
			}
			else if(stream->type() == rtc::CHANTYPE_VIDEO) {
				auto vstream = dynamic_pointer_cast<rtc::VideoStream>(stream);
				assert(vstream);

				{
					std::shared_ptr<rtc::codec::Codec> channel_codec;
					for(const auto& codec : vstream->list_codecs()) {
						//cout << "Codec: " << codec->codec << " (" << (uint32_t) codec->id << ")" << endl;
						if(!channel_codec && codec->codec == "VP8") {
							cout << "Enable VP8 codec" << endl;
							codec->accepted = true;
							channel_codec = codec;
						}
					}

					/*
					 * 				↵a=rtpmap:96 VP8/90000
									↵a=rtcp-fb:96 goog-remb
									↵a=rtcp-fb:96 transport-cc
									↵a=rtcp-fb:96 ccm fir
									↵a=rtcp-fb:96 nack
									↵a=rtcp-fb:96 nack pli
					 */

                    vstream->register_local_channel("video_response_" + vstream->get_mid(), "video_response_normal", channel_codec);
                    //vstream->register_local_channel("video_response_2" + vstream->get_mid(), "video_response_normal2", channel_codec);
				}

				if(false) {
					for(const auto& extension : vstream->list_extensions(rtc::direction::incoming))
						vstream->register_local_extension(extension->name, extension->direction, extension->config, extension->id);
				}

				struct VPXData {
					vpx_codec_err_t err;

					vpx_codec_iface_t* codec_interface = nullptr;
					vpx_codec_enc_cfg_t codec_enc_config;
					vpx_codec_dec_cfg_t codec_dec_config;

					vpx_image_t vpx_image_handle{};
					vpx_codec_ctx_t codec{};
				};

				auto vpx = new VPXData();

				{
					vpx_img_alloc(&vpx->vpx_image_handle, VPX_IMG_FMT_RGB32, V_WIDTH, V_HEIGHT, 1);
					vpx->vpx_image_handle.user_priv = nullptr;

					/*
					{
						vpx->codec_interface = vpx_codec_vp8_cx();

						vpx->err = vpx_codec_enc_config_default(vpx->codec_interface, &vpx->codec_enc_config, 0);
						assert(vpx->err == VPX_CODEC_OK);

						vpx->codec_enc_config.g_w = V_WIDTH;
						vpx->codec_enc_config.g_h = V_HEIGHT;
						vpx->codec_enc_config.g_timebase.num = 1;
						vpx->codec_enc_config.g_timebase.den = V_FPS;
						vpx->codec_enc_config.rc_target_bitrate = 90000;
						vpx->codec_enc_config.g_error_resilient = (vpx_codec_er_flags_t) VPX_ERROR_RESILIENT_DEFAULT;
					}
					 */
					{
						vpx->codec_dec_config.threads = 1;
						vpx->codec_dec_config.w = V_WIDTH;
						vpx->codec_dec_config.h = V_HEIGHT;
					}

					vpx->codec_interface = vpx_codec_vp8_dx();
					vpx->err = vpx_codec_dec_init(&vpx->codec, vpx->codec_interface, &vpx->codec_dec_config, 0);
					assert(vpx->err == VPX_CODEC_OK);
				}

                auto timestamp_base{chrono::system_clock::now()};
				weak_ptr<rtc::VideoStream> weak_astream = vstream;
				vstream->incoming_data_handler = [weak_astream, timestamp_base, vpx](const std::shared_ptr<rtc::Channel>& channel, const pipes::buffer_view& buffer, size_t payload_offset) {
					auto vs = weak_astream.lock();
					if(!vs) return;

					std::cout << "Received video data on stream " << channel->stream_id << " track " << channel->track_id << "\n";

					auto header = (rtc::protocol::rtp_header*) buffer.data_ptr();
					auto buf = buffer.view(sizeof(rtc::protocol::rtp_header));

					{
						bool success;
						auto vector = rtc::protocol::rtp_header_extension_ids(buffer, success);
						if(!vector.empty()) {
							if(vector.size() == 2 ? !(vector[0] == 2 && vector[1] == 3) : !(vector.size() == 3 && vector[0] == 2 && vector[1] == 3 && vector[2] == 7)) {
								cout << "Extension: ";
								for(int id : vector)
									cout << id << ",";
								cout << endl;
							}
						}
					}
					if(false) {
						for(const auto& extension : vs->list_extensions(rtc::direction::incoming)) {
							if(rtc::protocol::rtp_header_extension_find(buffer, extension->id, nullptr, nullptr, nullptr) == 0)
								cout << "Got extension: " << extension->name << endl;
						}
					}
					if(header->csrccount > 0)
						cout << "CCount: " << header->csrccount << endl;

					for(const auto& ch : vs->list_channels())
						if(ch->local) {
							//vs->send_rtp_data(ch, buffer.view(payload_offset), channel->timestamp_last_receive, false, header->markerbit);
						}

					uint8_t vpx_header_length{1};
                    int16_t picture_id{-1};
                    {
                        uint8_t header_flags{(uint8_t) buffer[payload_offset]};
                        uint8_t extended_bits{0};
                        if(header_flags & (0x01U << 7U)) {
                            extended_bits = buffer[payload_offset + vpx_header_length++];
                        }
                        if(extended_bits & (0x01U << 7U)) {
                            if(buffer[payload_offset + vpx_header_length] & (0x01U << 7U)) {
                                picture_id = buffer.at<uint16_t>(payload_offset + vpx_header_length) & 0x7FFF;
                                vpx_header_length += 2; //Long picture id
                            } else {
                                picture_id = buffer.at<uint8_t>(payload_offset + vpx_header_length) & 0x7F;
                                vpx_header_length++; //Picture id
                            }
                        }
                        if(extended_bits & (0x01U << 6U))
                            vpx_header_length++; //TL0PICIDX present
                        if(extended_bits & (0x01U << 5U) || extended_bits & (0x01U << 4U))
                            vpx_header_length++; //TID present or KEYIDX present
                        std::cout << std::bitset<8>(header_flags) << "|" << std::bitset<8>(extended_bits) << " Picture: " << picture_id << "\n";
                    }

					vpx->err = vpx_codec_decode(&vpx->codec, (uint8_t*) &buffer[payload_offset + vpx_header_length], buffer.length() - payload_offset - vpx_header_length, nullptr, VPX_DL_GOOD_QUALITY);
					cout << "Decode result: " << vpx->err << "/" << vpx_codec_err_to_string(vpx->err) << endl;
					if(vpx->err) {
					    uint32_t sli_payload[2];
                        sli_payload[0] = htonl(channel->ssrc); //IDK what fits in here
                        sli_payload[1] = (picture_id & 0b111111U) << 26U;

					    vs->send_rtcp_data(channel, pipes::buffer_view{(char*) sli_payload, 8}, rtc::protocol::RTCP_PSFB, 2);
					}
				};

#if false /* Create video generator */
				{
					std::thread([weak_astream]{
						vpx_codec_err_t err;

						auto codec_interface = vpx_codec_vp8_cx();
						vpx_codec_enc_cfg_t codec_config;

						vpx_image_t* vpx_image_handle = nullptr;
						vpx_codec_ctx_t vpx_encoder;

						vpx_image_handle = vpx_img_alloc(nullptr, VPX_IMG_FMT_RGB32, V_WIDTH, V_HEIGHT, 1);
						vpx_image_handle->user_priv = nullptr;

						{
							err = vpx_codec_enc_config_default(codec_interface, &codec_config, 0);
							assert(err == VPX_CODEC_OK);

							codec_config.g_w = V_WIDTH;
							codec_config.g_h = V_HEIGHT;
							codec_config.g_timebase.num = 1;
							codec_config.g_timebase.den = V_FPS;
							codec_config.rc_target_bitrate = 90000;
							codec_config.g_error_resilient = (vpx_codec_er_flags_t) VPX_ERROR_RESILIENT_DEFAULT;
						}

						err = vpx_codec_enc_init_ver(&vpx_encoder, codec_interface, &codec_config, 0, VPX_ENCODER_ABI_VERSION);
						assert(err == VPX_CODEC_OK);

						chrono::system_clock::time_point timestamp_base = chrono::system_clock::now(), sleep_base = chrono::system_clock::now();
						int frame_index = 0, flags = 0;

						vpx_codec_err_t res;
						while(true) {
							{
								auto vs = weak_astream.lock();
								if(!vs) break; /* client disconnected */

								vpx_image_handle = vpx_img_generate(vpx_image_handle);
								flags = 0;
								if(frame_index % V_KEYFRAME_INTERVAL == 0)
									flags |= VPX_EFLAG_FORCE_KF;

								{ /* encode and send */
									int got_pkts = 0;
									vpx_codec_iter_t iter = nullptr;
									const vpx_codec_cx_pkt_t *pkt = nullptr;
									res = vpx_codec_encode(&vpx_encoder, vpx_image_handle, frame_index, 1, flags, VPX_DL_REALTIME);
									const auto detail = vpx_codec_error_detail(&vpx_encoder);
									assert(res == VPX_CODEC_OK);

									while ((pkt = vpx_codec_get_cx_data(&vpx_encoder, &iter)) != nullptr) {
										got_pkts = 1;

										if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
                                            const int keyframe = (pkt->data.frame.flags & VPX_FRAME_IS_KEY) != 0;
											uint32_t timestamp = (uint32_t) chrono::duration_cast<chrono::milliseconds>(chrono::system_clock::now() - timestamp_base).count();

											uint8_t snd_buffer[pkt->data.frame.sz + 3];
											snd_buffer[0] = 0b10000000; //Extended header flags, Key frame
											if(keyframe) snd_buffer[0] |= 0b00010000; //Key frame (Non-reference frame)
                                            snd_buffer[1] = 0b10000000; //We've a picture id
                                            snd_buffer[2] = (frame_index * 1000) & 0x7F; //Picture id


                                            const static size_t max{1024};
                                            for(size_t index = 0; index < pkt->data.frame.sz; index += max) {
                                                memcpy(&snd_buffer[3], (char*) pkt->data.frame.buf + index, std::min(pkt->data.frame.sz - index, max));
                                                for(const auto& ch : vs->list_channels(rtc::direction::outgoing)) {
                                                    vs->send_rtp_data(ch, {(char*) snd_buffer, std::min(pkt->data.frame.sz - index, max) + 3}, timestamp, false, index + max >= pkt->data.frame.sz); //Set marker bit only for last entry
                                                }
                                                snd_buffer[0]++;
                                                snd_buffer[0] &= ~0b00010000;
                                            }

											cout << "Size: " << pkt->data.frame.sz << endl;
											for(const auto& ch : vs->list_channels(rtc::direction::outgoing)) {
                                                vs->send_rtp_data(ch, {(char*) snd_buffer, pkt->data.frame.sz + 3}, timestamp, false, 1);
											}

											//printf(keyframe ? "K" : ".");
											//fflush(stdout);
										}
									}
								}

                                std::this_thread::sleep_until(sleep_base += chrono::milliseconds(1000 / V_FPS));
								frame_index++;
							}
						}

						//TODO: Cleanup
						cout << "Video sender canceled" << endl;
					}).detach();
				}
#endif
			} else {
				cerr << "Remote offers invalid stream type! (" << stream->type() << ")" << endl;
				return; //We only want audio here!
			}
		};

		string error;
		if(!client->peer->initialize(error)) {
			cerr << "Failed to initialize client! (" << error << ")" << endl; //TODO error handling?
			return;
		}
	}

	connection->data = client;
}

int main() {
	srand(time(nullptr));
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	initializes_certificates();

	Socket socket{};
	socket.callback_accept = initialize_client;
	socket.callback_read = [](const std::shared_ptr<Socket::Client>& client, const pipes::buffer_view& data) {
		if(client->data) {
			auto ptr_client = (Client*) client->data;
			if(ptr_client->ssl)
				ptr_client->ssl->process_incoming_data(data);
			else
				ptr_client->websocket->process_incoming_data(data);
		}
	};
	socket.callback_disconnect = [](const std::shared_ptr<Socket::Client>& client) {
		cout << "Client disconnected" << endl;
		delete (Client*) client->data;
	};
	socket.start(1111);


	while(true) this_thread::sleep_for(chrono::seconds(100));
	return 0;
}