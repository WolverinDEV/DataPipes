#include "include/ssl.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <test/utils/socket.h>
#include <thread>
#include <cstring>
#include <include/ws.h>
#include <include/rtc/PeerConnection.h>
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

std::pair<EVP_PKEY*, X509*> certs{nullptr, nullptr};
std::pair<EVP_PKEY*, X509*> createCerts(pem_password_cb* password) {
	auto key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(EVP_PKEY_new(), ::EVP_PKEY_free);

	auto rsa = RSA_new();
	auto e = std::unique_ptr<BIGNUM, decltype(&BN_free)>(BN_new(), ::BN_free);
	BN_set_word(e.get(), RSA_F4);
	if(!RSA_generate_key_ex(rsa, 2048, e.get(), nullptr)) return {nullptr, nullptr};
	EVP_PKEY_assign_RSA(key.get(), rsa);

	auto cert = X509_new();
	X509_set_pubkey(cert, key.get());

	ASN1_INTEGER_set(X509_get_serialNumber(cert), 3);
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

	X509_NAME* name = X509_get_subject_name(cert);

	//This was an example for TeaSpeak
	X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *) "DE", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *) ("DataPipes Text (" + random_string(12) + ")").c_str(), -1, -1, 0); //We need something random here else some browsers say: SEC_ERROR_REUSED_ISSUER_AND_SERIAL
	X509_NAME_add_entry_by_txt(name, "OU",  MBSTRING_ASC, (unsigned char *) ("DataPipes Text (" + random_string(12) + ")").c_str(), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "emailAddress",  MBSTRING_ASC, (unsigned char *)("contact_" + random_string(12) + "@teaspeak.de").c_str(), -1, -1, 0);

	X509_set_issuer_name(cert, name);
	X509_set_subject_name(cert, name);

	X509_sign(cert, key.get(), EVP_sha512());

	return {key.release(), cert};
};

void configure_context(SSL_CTX *ctx) {
	SSL_CTX_set_ecdh_auto(ctx, 1);
	if(!certs.first || !certs.second)
		certs = createCerts([](char* buffer, int length, int rwflag, void* data) -> int {
			std::string password = "markus";
			memcpy(buffer, password.data(), password.length());
			return password.length();
		});

	PEM_write_X509(stdout, certs.second);

	if (SSL_CTX_use_PrivateKey(ctx, certs.first) <= 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_certificate(ctx, certs.second) <= 0 ) {
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
		client->ssl->logger(config->logger);
		client->ssl->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
		client->ssl->direct_process(pipes::PROCESS_DIRECTION_IN, true);

		auto ctx = create_context();
		configure_context(ctx);
		client->ssl->initialize(shared_ptr<SSL_CTX>(ctx, SSL_CTX_free), pipes::SSL::SERVER);

		client->ssl->callback_data([client](const string& data) {
			client->websocket->process_incoming_data(data);
		});
		client->ssl->callback_write([client](const string& data) {
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
		client->websocket->callback_write([client](const std::string& data) -> void {
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
			if(client->reader.parse(message.data, root)) {
				std::cout << "Got msg of type: " << root["type"] << endl;
				if (root["type"] == "offer") {
					cout << "Recived offer" << endl;

					client->peer->apply_offer(error, root["msg"]["sdp"].asString());

					Json::Value answer;
					answer["type"] = "answer";
					answer["msg"]["sdp"] = client->peer->generate_answer(true);
					answer["msg"]["type"] = "answer";

					std::cout << "Sending Answer: " << answer << endl;

					client->websocket->send({pipes::OpCode::TEXT, Json::writeString(client->json_writer, answer)});
				} else if (root["type"] == "candidate") {
					cout << "Apply candidates: " << client->peer->apply_ice_candidates(
							deque<shared_ptr<rtc::PeerConnection::IceCandidate>> { make_shared<rtc::PeerConnection::IceCandidate>(root["msg"]["candidate"].asString(), root["msg"]["sdpMid"].asString(), root["msg"]["sdpMLineIndex"].asInt()) }
					) << endl;
				}
			} else {
				cerr << "Failed to parse json" << endl;
			}
		});
	}

	{
		client->peer->callback_ice_candidate = [client](const rtc::PeerConnection::IceCandidate& ice) {
			Json::Value jsonCandidate;
			jsonCandidate["type"] = "candidate";
			jsonCandidate["msg"]["candidate"] = ice.candidate;
			jsonCandidate["msg"]["sdpMid"] = ice.sdpMid;
			jsonCandidate["msg"]["sdpMLineIndex"] = ice.sdpMLineIndex;

			//std::cout << "Sending Answer: " << jsonCandidate << endl;
			client->websocket->send({pipes::OpCode::TEXT, Json::writeString(client->json_writer, jsonCandidate)});
		};

		client->peer->callback_new_stream = [client](const shared_ptr<rtc::Stream>& stream) {
			if(stream->type() != rtc::CHANTYPE_AUDIO) {
				cerr << "Remote offers invalid stream type! (" << stream->type() << ")" << endl;
				return; //We only want audio here!
			}

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
			weak_ptr<rtc::AudioStream> weak_astream = astream;
			astream->incoming_data_handler = [&, weak_astream](const std::shared_ptr<rtc::AudioChannel>& channel, const std::string& buffer, size_t payload_offset) {
				auto as = weak_astream.lock();
				if(!as) return;

				auto buf = buffer.substr(payload_offset);
				auto channels = as->list_channels();
				for(const auto& ch : channels)
					if(ch->local)
						as->send_rtp_data(ch, buf, ch->timestamp_last_send += 960); //960 = 20ms opus :)
			};
		};

		string error;
		if(!client->peer->initialize(error)) {
			cerr << "Failed to initialize client! (" << error << ")" << endl; //TODO error handling?
			return;
		}
	}

	connection->data = client;
}

int udp_setup() {
	auto fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

int main() {
	srand(time(nullptr));
	init_alsa();
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	Socket socket{};
	socket.callback_accept = initialize_client;
	socket.callback_read = [](const std::shared_ptr<Socket::Client>& client, const std::string& data) {
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