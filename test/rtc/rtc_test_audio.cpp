#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <thread>
#include <cstring>

#include <pipes/ssl.h>
#include <pipes/ws.h>
#include <pipes/rtc/PeerConnection.h>
#include <pipes/rtc/channels/ApplicationChannel.h>
#include <pipes/rtc/channels/AudioChannel.h>

#include <event2/thread.h>
#include <glib-2.0/glib.h>

#include "../utils/rtc_server.h"
#include "../json/json.h"

#include <opus/opus.h>

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

void log(void* ptr, pipes::Logger::LogLevel level, const std::string& name, const std::string& msg, ...) {
    auto max_length = 1024 * 2;
    char buffer[max_length];

    va_list args;
    va_start(args, msg);
    max_length = vsnprintf(buffer, max_length, msg.c_str(), args);
    va_end(args);

    printf("[%p][%i][%s] %s\n", ptr, level, name.c_str(), buffer);
}

auto initialize_default_logger() noexcept {
    auto logger = make_shared<pipes::Logger>();
    logger->callback_log = log;
    return logger;
}

auto default_logger = initialize_default_logger();

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

void initialize_client(rtc_server::Client* client) {
    auto peer = client->peer();

    int err{0};
    auto decoder = opus_decoder_create(48000, 2, &err);
    assert(err == OPUS_OK);

    peer->callback_new_stream = [decoder](const std::shared_ptr<rtc::Channel>& stream) {
        if(stream->type() == rtc::CHANTYPE_AUDIO) {
            auto astream = dynamic_pointer_cast<rtc::AudioChannel>(stream);
            assert(astream);
            {
                auto opus_codec = astream->find_codecs_by_name("opus");
                if(opus_codec.empty()) {
                    return; //FIXME disconnect client
                }

                for(const auto& codec: opus_codec) {
                    codec->accepted = true;
                    auto channel = astream->register_local_channel(codec, "X", "Y");
                    //channel->timestamp_last_send = 0xf23;
                    break;
                }
            }
            //astream->register_local_extension("urn:ietf:params:rtp-hdrext:ssrc-audio-level");

            weak_ptr<rtc::AudioChannel> weak_astream = astream;
            astream->incoming_data_handler = [&, weak_astream, decoder](const std::shared_ptr<rtc::MediaChannel>& channel, const pipes::buffer_view& buffer, size_t payload_offset) {
                auto as = weak_astream.lock();
                if(!as) return;

                for(const auto& ext : as->list_extensions(rtc::direction::incoming)) {
                    if(ext->name == "urn:ietf:params:rtp-hdrext:ssrc-audio-level") {
                        int level;
                        if(rtc::protocol::rtp_header_extension_parse_audio_level(buffer, ext->id, &level) == 0) {
                            cout << "Audio level " << level << endl;
                        }
                        break;
                    }
                }

                auto header = buffer.data_ptr<rtc::protocol::rtp_header>();
                auto buf = buffer.view(payload_offset);
                auto channels = as->list_channels();

                if(false) {

                    constexpr auto buffer_size = 4096;
                    opus_int16 result_buffer[buffer_size];

                    auto result = opus_decode(decoder, buf.data_ptr<unsigned char>(), buf.length(), result_buffer, buffer_size / 2, 0);
                    std::cout << "Decode result: " << result << std::endl;
                }

                for(const auto& ch : channels)
                    if(ch->local) {
                        cout << "Sending " << buf.length() << " - " << payload_offset << " - " << ntohl(header->timestamp) << std::endl;
                        //as->send_rtp_data(ch, buf, ch->timestamp_last_send += 960); //960 = 20ms opus :)
                        as->send_rtp_data(ch, buf.view(0), ntohl(header->timestamp), false, false); //960 = 20ms opus :)
                    }
            };
        } else {
            cerr << "Remote offers invalid stream type! (" << stream->type() << ")" << endl;
            return; //We only want audio here!
        }
    };
}

void cleanup_client(rtc_server::Client* client) {}


int main() {
    srand(std::chrono::system_clock::now().time_since_epoch().count());
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    evthread_use_pthreads();
    initializes_certificates();

    auto main_loop = std::shared_ptr<GMainLoop>(g_main_loop_new(nullptr, false), g_main_loop_unref);
    std::thread([main_loop]{
        g_main_loop_run(&*main_loop);
    }).detach();

    rtc_server server{default_logger};

    server.callback_peer_connection_config = [main_loop](rtc_server::Client* client){
        auto config = make_shared<rtc::PeerConnection::Config>();
        config->nice_config = make_shared<rtc::NiceWrapper::Config>();

        config->nice_config->main_loop = main_loop;
        config->nice_config->ice_servers.push_back({"stun.l.google.com", 19302});
        config->nice_config->allow_ice_udp = true;
        config->nice_config->allow_ice_tcp = false;

        config->logger = make_shared<pipes::Logger>();
        config->logger->callback_log = log;
        config->logger->callback_argument = client;
        return config;
    };
    server.callback_ssl_certificate_initialize = [](const std::shared_ptr<pipes::SSL::Options>& options) {
        options->enforce_sni = false;
        options->default_keypair(pipes::SSL::Options::KeyPair{certificates->ref_private_key(), certificates->ref_certificate()});
    };

    server.callback_client_disconnected = cleanup_client;
    server.callback_client_connected = initialize_client;

    std::string error{};
    if(!server.start(error, 1111)) {
        std::cerr << "Failed to start web socket server" << std::endl;;
        return 1;
    }
    std::cout << "Server started on port 1111" << std::endl;


    while(true) this_thread::sleep_for(chrono::seconds(100));
    return 0;
}