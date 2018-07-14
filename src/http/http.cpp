#include <sstream>
#include <algorithm>
#include "include/http.h"

using namespace std;
using namespace http;


code_t code::_200 = std::make_shared<HTTPCode>(200, "OK");
code_t code::_101 = std::make_shared<HTTPCode>(101, "Switching Protocols");
extern code_t code::code(int code, const std::string& message) { return std::make_shared<HTTPCode>(code, message); }

inline uint8_t hex_parse_nibble(char in) {
	if(in >= 'A' && in <= 'F') return (uint8_t) (in - 'A' + 0x0A);
	if(in >= 'a' && in <= 'f') return (uint8_t) (in - 'a' + 0x0A);
	if(in >= '0' && in <= '9') return (uint8_t) (in - '0');
	return 0;
}

inline char hex_encode_nibble(uint8_t in) {
	if(in > 0x0F) return '0';
	if(in >= 0x0A) return (char) ('A' + in - 0x0A);
	return '0' + in;
}

inline bool _decode_url(std::string &message) {
	for(size_t index = 0; index < message.length(); index++) {
		if(message[index] == '%') {
			if(index + 2 >= message.length()) return false;
			uint8_t character = hex_parse_nibble(message[index + 1]) << 4 | hex_parse_nibble(message[index + 2]);
			message.replace(index, 3, (char*) &character, 1);
		}
	}
	return true;
}

inline std::string _encode_url(std::string message) {
	char replacement[3];
	replacement[0] = '%';
	register uint8_t uc;

	for(size_t index = 0; index < message.length(); index++) {
		uc = (uint8_t) message[index];
		if(uc >= 'a' && uc <= 'z') continue;
		if(uc >= 'A' && uc <= 'Z') continue;
		if(uc >= '0' && uc <= '9') continue;
		replacement[1] = hex_encode_nibble(uc >> 4);
		replacement[2] = hex_encode_nibble(uc & (uint8_t) 0xF);

		message.replace(index, 1, replacement, 3);
		index += 2;
	}
	return message;
}


extern std::string http::encode_url(std::string message) {
	_decode_url(message);
	return message;
}
extern std::string http::decode_url(std::string message) {
	return _encode_url(std::move(message));
}

inline bool parse_header_entry(const std::string &entry, HttpHeaderEntry &e, const std::vector<std::string> &noParsing) {

    size_t kvBorder = entry.find(':');
    if(kvBorder == std::string::npos) return false;
    if(kvBorder + 2 > entry.length()) return false;

    auto key = entry.substr(0, kvBorder);
    auto value = entry.substr(kvBorder + 2);

    e.key = key;
    e.values.clear();
    for(const auto& k : noParsing)
        if(k == key) {
            e.values.push_back(value);
            return true;
        }

    size_t index = 0;
    do {
        auto idx = value.find("; ", index);
        e.values.push_back(value.substr(index, idx - index));
        index = idx + 1;
    } while(index != 0);
    return true;
}

bool http::parse_request(const std::string &header, HttpRequest &result, const std::vector<std::string>& noParsing) {
    vector<string> lines;
    size_t index = 0;
    do {
        auto idx = header.find('\n', index);

        auto line = header.substr(index, idx - index);
        lines.push_back(line.substr(0, line.back() == '\r' ? line.length() - 1 : line.length()));

        index = idx + 1;
    } while(index != 0);

    result.header.clear();

    auto request = lines[0];

    //Read the method
    auto method_idx = request.find(' ');
    if(method_idx == string::npos)
	    return false;
    result.method = request.substr(0, method_idx);
    request = request.substr(method_idx + 1);

    //Read the url
    auto urlIdx = request.find(' ');
    auto encodedUrl = request.substr(0, urlIdx);
    auto url_path_idx = encodedUrl.find('?');
	result.url = encodedUrl.substr(0, url_path_idx);
    if(url_path_idx != string::npos) {
	    auto encoded_parm = encodedUrl.substr(url_path_idx + 1);

	    //Read the url parms
	    index = 0;
	    do {
		    auto idx = encoded_parm.find('&', index);
		    auto element = encoded_parm.substr(index, idx - index);

		    auto key_idx = element.find('=');
		    auto key = element.substr(0, key_idx);
		    auto value = element.substr(key_idx + 1);
		    if(!_decode_url(value))
			    return false;
		    result.parameters[key] = value;

		    index = idx + 1;
	    } while(index != 0);
    }
	request = request.substr(urlIdx + 1);

	//Read the version
	result.version = request;

    for(int idx = 1; idx < lines.size(); idx++) {
        if(lines[idx].empty()) continue;
        HttpHeaderEntry e;
        if(!parse_header_entry(lines[idx], e, noParsing))
	        return false;
        result.header.push_back(e);
    }

    return true;
}

bool HttpPackage::removeHeader(const std::string &key) {
	for(const auto& e : this->header) {
		if(e.key != key) continue;
		auto it = find(this->header.begin(), this->header.end(), e);
		if(it != this->header.end())
			this->header.erase(it);
		return true;
	}
	return false;
}

bool HttpPackage::setHeader(const std::string &key, const std::vector<std::string> &values) {
	this->removeHeader(key);
	this->header.push_back(HttpHeaderEntry{key, values});
	return true;
}

#define NL "\r\n"

std::string HttpHeaderEntry::build() const {
    stringstream ss;
    ss << this->key << ": ";
    for(auto it = this->values.begin(); it != this->values.end(); it++)
        ss << *it << ((it + 1) != this->values.end() ? "; " : "");
    return ss.str();
}

std::string HttpPackage::build() const {
    ostringstream ss;

	this->buildHead(ss);
	ss << NL;

	this->buildHeader(ss);
	ss << NL;

	this->buildBody(ss);
    return ss.str();
}

void HttpPackage::buildHeader(std::ostringstream& ss) const {
	for(const auto& entry : this->header)
		ss << entry.build() << NL;
}

void HttpPackage::buildBody(std::ostringstream &) const {} //TODO


void HttpRequest::buildHead(std::ostringstream &ss) const {
	ss << this->method << ' ' << this->url;
	for(auto it = this->parameters.begin(); it != this->parameters.end(); it++) {
		if(it == this->parameters.begin())
			ss << '?';
		else
			ss << '&';
		ss << it->first << "=" << it->second;
	}
	ss << " " << this->version;
}

HttpResponse::HttpResponse() {
	this->setHeader("Content-Length", {"0"});
}

void HttpResponse::buildHead(std::ostringstream &ss) const {
	ss << this->version << " " << this->code->code << " " << this->code->message;
}