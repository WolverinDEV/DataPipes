#pragma once

#include <deque>
#include <string>
#include <utility>
#include <vector>
#include <map>
#include <memory>

namespace http {
	namespace code { struct HTTPCode; }
	typedef std::shared_ptr<code::HTTPCode> code_t;

	namespace code {
		struct HTTPCode {
			public:
				HTTPCode(int code, std::string message) : message(std::move(message)), code(code) { }

				const std::string message;
				const int code;

				bool operator==(const HTTPCode& other) { return other.code == this->code; }
		};

		extern code_t _200;
		extern code_t _101;
		extern code_t code(int code, const std::string&);
	}

    struct HttpHeaderEntry {
        std::string key;
        std::vector<std::string> values;

        operator bool() const { return !key.empty(); }
        std::string build() const;
    };

    class HttpPackage {
        public:
		    HttpPackage() = default;
		    virtual ~HttpPackage() = default;

		    std::string version = "HTTP/1.1";
            std::deque<HttpHeaderEntry> header;

            inline HttpHeaderEntry findHeader(const std::string& key) const {
                for(const auto& e : header)
                    if(e.key == key) return e;
                return {"", {}};
            }

		    bool removeHeader(const std::string& key);
		    bool setHeader(const std::string& key, const  std::vector<std::string>& values);

            std::string build() const;

	    protected:
            virtual void buildHead(std::ostringstream &) const = 0;
		    virtual void buildHeader(std::ostringstream&) const;
		    virtual void buildBody(std::ostringstream&) const;
    };

	class HttpRequest : public HttpPackage {
		public:
			HttpRequest() = default;
			~HttpRequest() override = default;

			std::string method = "GET";
			std::string url;
			std::map<std::string, std::string> parameters;
		private:
		protected:
			void buildHead(std::ostringstream &) const override;
	};

	class HttpResponse : public HttpPackage {
		public:
			HttpResponse();
			~HttpResponse() override = default;

			code_t code = code::_200;
		protected:
			void buildHead(std::ostringstream &) const override;
	};

    extern bool parse_request(const std::string &, HttpRequest &, const std::vector<std::string>& noParsing = {"Origin", "User-Agent"});

	extern std::string encode_url(std::string);
	extern std::string decode_url(std::string);
}