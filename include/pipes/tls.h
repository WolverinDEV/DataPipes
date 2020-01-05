#pragma once

#include "./ssl.h"
#include <openssl/evp.h>

namespace pipes {
	class TLSCertificate {
		public:
			static std::unique_ptr<TLSCertificate> generate(const std::string& /* name */, int /* days */);
			TLSCertificate(const std::string& /* certificate pen */, const std::string& /* key pen */, bool /* files */ = false);

			std::shared_ptr<X509> ref_certificate();
			std::shared_ptr<EVP_PKEY> ref_private_key();
			X509* getCertificate() const { return this->certificate.get(); }
			EVP_PKEY* getPrivateKey() const { return this->evp_key.get(); }

			std::string getFingerprint() const { return this->fingerprint; }

			bool save(std::string& /* certificate */, std::string& /* key */, bool /* files */ = false);
			bool save_file(const std::string& /* certificate path */, const std::string& /* key path */);
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
			bool initialize(std::string& /* error */, const std::shared_ptr<TLSCertificate>& /* certificate */, TLSMode /* mode */, Type /* server/client */, const initialize_function& /* initialize */ = nullptr);

			inline std::shared_ptr<TLSCertificate> getCertificate() { return this->certificate; }
		private:
			std::shared_ptr<TLSCertificate> certificate;
	};
}