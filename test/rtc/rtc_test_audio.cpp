#include "include/ssl.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <test/utils/socket.h>
#include <thread>
#include <cstring>
#include <include/ws.h>
#include <include/rtc/PeerConnection.h>
#include <include/rtc/ApplicationStream.h>
#include "include/rtc/AudioStream.h"
#include "test/json/json.h"

using namespace std;

//#define DEBUG_SOUND_LOCAL
#ifdef DEBUG_SOUND_LOCAL
	#include <alsa/asoundlib.h>

	snd_pcm_t *alsa_handle;
	bool init_alsa() {
		if(snd_pcm_open(&alsa_handle, "default", SND_PCM_STREAM_PLAYBACK, 0) < 0) {
			cerr << "Failed to load alsa!" << endl;
			return 0;
		}
		if(snd_pcm_set_params(alsa_handle, SND_PCM_FORMAT_S16_LE, SND_PCM_ACCESS_RW_INTERLEAVED, 2, 48000, 1, 100000) < 0) {
			cerr << "Failed to setup alsa!" << endl;
			return 0;
		}
		return true;
	}

	void alsa_replay(void* data, size_t length) {
		int pcm;
		if (pcm = snd_pcm_writei(alsa_handle, data, length) == -EPIPE) {
			printf("XRUN.\n");
			snd_pcm_prepare(alsa_handle);
		}
	}
#else
	void alsa_replay(void* data, size_t length) {}
	bool init_alsa() { return true; }
#endif

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
	auto max_length = 1024 * 8;
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
	config->nice_config->main_loop = std::shared_ptr<GMainLoop>(g_main_loop_new(nullptr, false), g_main_loop_unref);
	std::thread(g_main_loop_run, config->nice_config->main_loop.get()).detach(); //FIXME

	config->logger = make_shared<pipes::Logger>();
	config->logger->callback_log = log;

	return config;
}();


SSL_CTX* create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

std::string random_string( size_t length )
{
	auto randchar = []() -> char
	{
		const char charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[ rand() % max_index ];
	};
	std::string str(length,0);
	std::generate_n( str.begin(), length, randchar );
	return str;
}

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

void configure_context(SSL_CTX *ctx) {
	assert(SSL_CTX_set_ecdh_auto(ctx, 1));
	if(!certificates)
		initializes_certificates();

	if (SSL_CTX_use_PrivateKey(ctx, certificates->getPrivateKey()) <= 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_certificate(ctx, certificates->getCertificate()) <= 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
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

		auto ctx = create_context();
		configure_context(ctx);
		client->ssl->initialize(shared_ptr<SSL_CTX>(ctx, SSL_CTX_free), pipes::SSL::SERVER);

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

					client->peer->apply_offer(error, root["msg"]["sdp"].asString());

					{
						Json::Value answer;
						answer["type"] = "answer";
						answer["msg"]["sdp"] = client->peer->generate_answer(true);
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
				}
			} else {
				cerr << "Failed to parse json" << endl;
			}
		});
	}

	{
		client->peer->callback_ice_candidate = [client](const rtc::IceCandidate& ice) {
			Json::Value jsonCandidate;
			jsonCandidate["type"] = "candidate";
			jsonCandidate["msg"]["candidate"] = ice.candidate;
			jsonCandidate["msg"]["sdpMid"] = ice.sdpMid;
			jsonCandidate["msg"]["sdpMLineIndex"] = ice.sdpMLineIndex;

			cout << "Sending ice candidate " << ice.candidate << " (" << ice.sdpMid << " | " << ice.sdpMLineIndex << ")" << endl;
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
							chan->send(buf, rtc::DataChannel::TEXT);
						}
					};
					channel->callback_close = [weak]() {
						auto chan = weak.lock();
						cout << "[DataChannel][" << chan->id() << "|" << chan->lable() << "] got closed" << endl;
					};
				};
			} else if(stream->type() == rtc::CHANTYPE_AUDIO) {
				auto astream = dynamic_pointer_cast<rtc::AudioStream>(stream);
				assert(astream);
				{
					auto opus_codec = astream->find_codec_by_name("opus");
					if(opus_codec.empty()) {
						return; //FIXME disconnect client
					}
					for(const auto& codec: opus_codec)
						astream->register_local_channel("voice_bridge_" + to_string(codec->id), "client_" + to_string(codec->id), opus_codec.back());
				}
				astream->register_local_extension("urn:ietf:params:rtp-hdrext:ssrc-audio-level");

				weak_ptr<rtc::AudioStream> weak_astream = astream;
				astream->incoming_data_handler = [&, weak_astream](const std::shared_ptr<rtc::AudioChannel>& channel, const pipes::buffer_view& buffer, size_t payload_offset) {
					auto as = weak_astream.lock();
					if(!as) return;

					for(const auto& ext : as->list_extensions(0x02)) {
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
	init_alsa();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

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