#include "include/ssl.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <test/utils/socket.h>
#include <thread>
#include <cstring>
#include <include/ws.h>
#include <include/rtc/PeerConnection.h>
#include <include/rtc/Stream.h>
#include <include/rtc/ApplicationStream.h>
#include "test/json/json.h"

using namespace std;

struct Client {
	std::weak_ptr<Socket::Client> connection;
	unique_ptr<pipes::SSL> ssl;
	unique_ptr<pipes::WebSocket> websocket;
	unique_ptr<rtc::PeerConnection> peer;

	Json::Reader reader;
	Json::StreamWriterBuilder json_writer;
};

void log(pipes::Logger::LogLevel level, const std::string& name, const std::string& message, ...) {
	auto max_length = 1024 * 2;
	char buffer[max_length];

	va_list args;
	va_start(args, message);
	max_length = vsnprintf(buffer, max_length, message.c_str(), args);
	va_end(args);

	printf("[%i][%s] %s\n", level, name.c_str(), buffer);
}

auto config = []{
	auto config = make_shared<rtc::PeerConnection::Config>();
	config->nice_config = make_shared<rtc::NiceWrapper::Config>();

	config->nice_config->ice_servers.push_back({"stun.l.google.com", 19302});

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
	X509_NAME_add_entry_by_txt(name, "OU",  MBSTRING_ASC, (unsigned char *) "DataPipes", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "emailAddress",  MBSTRING_ASC, (unsigned char *)"contact@teaspeak.de", -1, -1, 0);

	X509_set_issuer_name(cert, name);
	X509_set_subject_name(cert, name);

	X509_sign(cert, key.get(), EVP_sha512());

	return {key.release(), cert};
};

void configure_context(SSL_CTX *ctx) {
	assert(SSL_CTX_set_ecdh_auto(ctx, 1));
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
		client->peer->callback_ice_candidate = [client](const rtc::IceCandidate& ice) {
			Json::Value jsonCandidate;
			jsonCandidate["type"] = "candidate";
			jsonCandidate["msg"]["candidate"] = ice.candidate;
			jsonCandidate["msg"]["sdpMid"] = ice.sdpMid;
			jsonCandidate["msg"]["sdpMLineIndex"] = ice.sdpMLineIndex;

			//std::cout << "Sending Answer: " << jsonCandidate << endl;

			pipes::buffer buf;
			buf += Json::writeString(client->json_writer, jsonCandidate);
			client->websocket->send({pipes::OpCode::TEXT, buf});
		};

		client->peer->callback_new_stream = [](const std::shared_ptr<rtc::Stream>& stream) {
			cout << "[Stream] Got new stream of type " << stream->type() << " | " << stream->stream_id() << endl;
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
			}
		};
	}

	{
		string error;
		if(!client->peer->initialize(error)) {
			cerr << "Failed to initialize client! (" << error << ")" << endl; //TODO error handling?
			return;
		}

		client->websocket->callback_data([client](const pipes::WSMessage& message) {
			string error;
			Json::Value root;

			cout << "Got message " << message.data << endl;
			if(client->reader.parse(message.data.string(), root)) {
				std::cout << "Got msg of type: " << root["type"] << endl;
				if (root["type"] == "offer") {
					cout << "Recived offer" << endl;

					client->peer->apply_offer(error, root["msg"]["sdp"].asString());
					Json::Value answer;
					answer["type"] = "answer";
					answer["msg"]["sdp"] = client->peer->generate_answer(true);
					answer["msg"]["type"] = "answer";

					std::cout << "Sending Answer: " << answer << endl;

					pipes::buffer buf;
					buf += Json::writeString(client->json_writer, answer);
					client->websocket->send({pipes::OpCode::TEXT, buf});
				} else if (root["type"] == "candidate") {
					cout << "Apply candidates: " << client->peer->apply_ice_candidates(
							deque<shared_ptr<rtc::IceCandidate>> { make_shared<rtc::IceCandidate>(root["msg"]["candidate"].asString(), root["msg"]["sdpMid"].asString(), root["msg"]["sdpMLineIndex"].asInt()) }
					) << endl;
				}
			} else {
				cerr << "Failed to parse json" << endl;
			}
		});
	}

	connection->data = client;
}

int main() {
	srand(chrono::system_clock::now().time_since_epoch().count());
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