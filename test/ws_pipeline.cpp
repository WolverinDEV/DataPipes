#include "include/ssl.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <test/utils/socket.h>
#include <thread>
#include <assert.h>
#include <cstring>
#include <include/ws.h>

using namespace std;


void initialize_client(const std::shared_ptr<Socket::Client>& client) {
    cout << "Got new client" << endl;
    auto ws = new pipes::WebSocket{};
    ws->initialize();

    ws->direct_process(pipes::PROCESS_DIRECTION_OUT, true);
    ws->direct_process(pipes::PROCESS_DIRECTION_IN, true);


    weak_ptr<Socket::Client> weak = client;
    ws->callback_error([weak](int code, const std::string& reason) {
        auto cl = weak.lock();
        //if(cl) cl->disconnect(false);
        cout << "Got error: " << code << " => " << reason << endl;

    });
    ws->callback_write([weak](const std::string& data) -> void {
        auto cl = weak.lock();
        if(cl) cl->send(data);
    });

    ws->callback_data([weak](const pipes::WSMessage& message) {
        cout << "Got message " << message.data << endl;
        auto cl = weak.lock();
        if(cl) ((pipes::WebSocket*) cl->data)->send(pipes::WSMessage{pipes::TEXT, "You wrote: " + message.data});
    });

    client->data = ws;
}

int main() {
    Socket socket{};
    socket.callback_accept = initialize_client;
    socket.callback_read = [](const std::shared_ptr<Socket::Client>& client, const std::string& data) {
        ((pipes::WebSocket*) client->data)->process_incoming_data(data);
    };
    socket.callback_disconnect = [](const std::shared_ptr<Socket::Client>& client) {
        cout << "Client disconnected" << endl;
    };
    socket.start(1111);


    while(true) this_thread::sleep_for(chrono::seconds(100));
    return 0;
}