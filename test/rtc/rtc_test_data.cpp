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

	~Client() = default;
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
		client->ssl->logger(config->logger);
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