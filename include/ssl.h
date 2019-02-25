#pragma once

#include <memory>
#include <openssl/ssl.h>
#include "pipeline.h"

namespace pipes {
	enum SSLSocketState {
		SSL_STATE_INIT,
		SSL_STATE_CONNECTED,
		SSL_STATE_UNDEFINED
	};

	class SSL : public Pipeline<buffer_view> {
		public:
			typedef std::function<void()> InitializedHandler;

			static bool is_ssl(const u_char* buf) {
				return ((*buf >= 20) && (*buf <= 64));
			}

			enum Type {
				SERVER,
				CLIENT
			};

			static bool isSSLHeader(const std::string &);
			//static bool isSSLHandschake(const std::string&, bool full = false);

			SSL();

			virtual ~SSL();

			bool initialize(const std::shared_ptr<SSL_CTX> &, Type /* type */);
			bool do_handshake();
			void finalize();

			//Callbacks
			InitializedHandler callback_initialized = []() {};
			size_t readBufferSize = 1024;

			SSLSocketState state() { return this->sslState; }

			std::string remote_fingerprint();

			inline ::SSL *ssl_handle() { return this->sslLayer; }
		private:
			bool initializeBio();

		protected:
			ProcessResult process_data_in() override;

			ProcessResult process_data_out() override;

			std::shared_ptr<SSL_CTX> sslContext = nullptr;
			::SSL *sslLayer = nullptr;
			Type type;
			SSLSocketState sslState = SSLSocketState::SSL_STATE_INIT;
			std::chrono::system_clock::time_point handshakeStart;

		private:
			std::mutex lock;
			static BIO_METHOD *SSLSocketBioMethods;

			//Required methods
			static int (*bio_read)(BIO *, char *, int);

			static int (*bio_write)(BIO *, const char *, int);

			static long (*bio_ctrl)(BIO *, int, long, void *);

			static int (*bio_create)(BIO *);

			static int (*bio_destroy)(BIO *);

			//"empty" methods
			static int (*bio_puts)(BIO *, const char *);

			static int (*bio_gets)(BIO *, char *, int);

#ifdef USE_BORINGSSL
			static long (*bio_callback_ctrl)(BIO *, int, bio_info_cb);
			static constexpr int included_boringssl = 1;
#else
			static long (*bio_callback_ctrl)(BIO *, int, bio_info_cb *);
			static constexpr int included_boringssl = 0;
#endif
			static int compiled_boringssl;
	};
}