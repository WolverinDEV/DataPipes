#pragma once

#include "./pipeline.h"
#include <map>
#include <memory>
#include <openssl/ssl.h>

namespace pipes {
    enum SSLSocketState {
        SSL_STATE_CONNECTING,
        SSL_STATE_CONNECTED,

        SSL_STATE_UNDEFINED
    };

    class SSL : public Pipeline<buffer_view> {
        public:
            enum Type {
                SERVER,
                CLIENT
            };

            struct Options {
                typedef std::pair<std::shared_ptr<EVP_PKEY>, std::shared_ptr<X509>> KeyPair;
                const static KeyPair EmptyKeyPair;

                Type type = Type::SERVER;

                bool free_unused_keypairs = true;
                const SSL_METHOD *context_method = nullptr; /* default: SSLv23_method */
                std::function<bool(::SSL_CTX* /* context */)> context_initializer;
                std::function<bool(::SSL* /* context */)> ssl_initializer;

                /* empty key stand for the default keypair */
                std::map<std::string, KeyPair> servername_keys;
                bool enforce_sni = false; /* enforces SNI handling */

                bool verbose_io{false};

				inline const KeyPair default_keypair() const { return this->servername_keys.count("") > 0 ? this->servername_keys.at("") : EmptyKeyPair; }
				inline void default_keypair(const KeyPair& value) {
					this->servername_keys.erase("");
					this->servername_keys.insert({"", value});
				}
			};

            typedef std::function<void()> InitializedHandler;

            static bool is_ssl(const uint8_t* buf, int64_t length = -1) {
                if(length >= 0 && length < 1) return false;
                return ((*buf >= 20) && (*buf <= 64));
            }

            static bool isSSLHeader(const std::string &);
            //static bool isSSLHandschake(const std::string&, bool full = false);

            SSL();

            virtual ~SSL();

            inline bool initialize(const std::shared_ptr<Options>& options) {
                std::string error_{};
                return this->initialize(options, error_);
            }
            bool initialize(const std::shared_ptr<Options>& /* options */, std::string& /* error */);
            /* manually try to read/connect/write for the ssl handle */
            void continue_ssl();
            void finalize();

            [[nodiscard]] std::shared_ptr<const Options> options() const { return this->_options; }

			//Callbacks
			InitializedHandler callback_initialized = []() {};
			size_t readBufferSize = 1024;

            [[nodiscard]] SSLSocketState state() { return this->ssl_state_; }

            [[nodiscard]] std::string remote_fingerprint();

            [[nodiscard]] inline ::SSL *ssl_handle() const { return this->ssl_handle_; }
        private:
            bool initialize_bios();
            void continue_ssl_nolock();

        protected:
            ProcessResult process_data_in() override;
            ProcessResult process_data_out() override;

            std::shared_ptr<Options> _options;
            std::shared_ptr<SSL_CTX> sslContext = nullptr;

            std::recursive_mutex ssl_mutex_{};
            ::SSL *ssl_handle_{nullptr};

            SSLSocketState ssl_state_ = SSLSocketState::SSL_STATE_CONNECTING;
            std::chrono::system_clock::time_point handshake_start_timestamp;

        private:
            static int _sni_callback(::SSL*,int*,void*);

            static BIO_METHOD * input_bio_method();

            //Required methods
            static int bio_read(BIO *, char *, int);
            static int bio_write(BIO *, const char *, int);
            static long bio_ctrl(BIO *, int, long, void *);
            static int bio_create(BIO *);
            static int bio_destroy(BIO *);

            //"empty" methods
            static int bio_puts(BIO *, const char *);
            static int bio_gets(BIO *, char *, int);

#ifdef USE_BORINGSSL
            static long bio_callback_ctrl(BIO *, int, bio_info_cb);
			static constexpr int included_boringssl = 1;
#else
            static long bio_callback_ctrl(BIO *, int, bio_info_cb *);
            static constexpr int included_boringssl = 0;
#endif
            static int compiled_boringssl;
    };
}