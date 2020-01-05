#pragma once

#include "./pipeline.h"
#include "./misc/http.h"

struct WSFrame;
namespace pipes {
    enum WebSocketState {
        UNINIZALISIZED,
        HANDSCHAKE,
        CONNECTED
    };

    enum OpCode {
        CONTINUE = 0x00,
        TEXT = 0x01,
        BINARY = 0x02,
        CLOSE = 0x08,
        PING = 0x09,
        PONG = 0x0A
    };

    struct WSMessage {
        OpCode code;
        buffer data;
    };

    class WebSocket : public Pipeline<WSMessage> {
        typedef std::function<void()>                       ConnectHandler;
        typedef std::function<void(const std::string &)>    DisconnectHandler;

        typedef std::function<void(const http::HttpRequest&, http::HttpResponse&)>    InvalidRequestHandler;

    public:
        WebSocket();
        virtual ~WebSocket();

        void initialize();

        void disconnect(int code = 1000, const std::string& reason = "");

        ConnectHandler on_connect = []() {};
        DisconnectHandler on_disconnect = [](const std::string&) {};

        InvalidRequestHandler callback_invalid_request = [](const http::HttpRequest&, http::HttpResponse&) {};

        WebSocketState getState(){ return this->state; }
    private:
    protected:
        ProcessResult process_data_in() override;
        ProcessResult process_data_out() override;

    private:
        buffer handshake_buffer;
        int process_handshake();

        std::unique_ptr<WSFrame> current_frame;
        bool process_frame();

        WebSocketState state = WebSocketState::UNINIZALISIZED;
    };
}