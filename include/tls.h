#pragma once

#include <openssl/evp.h>
#include "ssl.h"

namespace pipes {
	class TLSCertificate {
		public:
			static std::shared_ptr<TLSCertificate> generate(const std::string& /* name */, int /* days */);
			TLSCertificate(const std::string& /* certificate pen */, const std::string& /* key pen */);

			X509* getCertificate() const { return this->certificate.get(); }
			EVP_PKEY* getPrivateKey() const { return this->evp_key.get(); }

			std::string getFingerprint() const { return this->fingerprint; }
		private:
			TLSCertificate(std::shared_ptr<X509> /* certificate */, std::shared_ptr<EVP_PKEY> /* key */);

			std::string fingerprint;
			std::shared_ptr<X509> certificate;
			std::shared_ptr<EVP_PKEY> evp_key;

			void generate_fingerprint();
	};

	enum TLSMode {
		TLS_X,
		TLS_v1,
		TLS_v1_1,
		TLS_v1_2,

		DTLS_X,
		DTLS_v1,
		DTLS_v1_2,
	};

	class TLS : public pipes::SSL {
		public:
			typedef std::function<bool(SSL_CTX*)> initialize_function;
			bool initialize(std::string& /* error */, const std::shared_ptr<TLSCertificate>& /* certificate */, TLSMode /* mode */, const initialize_function& /* initialize */ = nullptr);

			inline std::shared_ptr<TLSCertificate> getCertificate() { return this->certificate; }
		private:
			std::shared_ptr<TLSCertificate> certificate;
	};
}