#pragma once

#include <event2/event.h>
#include <string>
#include <memory>
#include <deque>
#include <mutex>
#include <pipes/buffer.h>

class Socket {
public:
    struct Client {
            friend class Socket;
        public:
            Socket* handle = nullptr;
            void* data = nullptr;

            Client() = default;
            ~Client() = default;

            void send(const pipes::buffer_view& /* buffer */);
            void disconnect(bool blocking = true);
        private:
            void close_connection(bool blocking = true);

            int fd = 0;
            event* event_read = nullptr;
            event* event_write = nullptr;

            void on_read(int fd);
            void on_write(int fd);

            std::mutex buffer_lock;
            std::deque<pipes::buffer> buffer_write;
    };
    friend class Client;

    typedef void(*fnc_accept)(const std::shared_ptr<Client>&);
    typedef void(*fnc_disconnect)(const std::shared_ptr<Client>&);
    typedef void(*fnc_read)(const std::shared_ptr<Client>&, const pipes::buffer_view&);
public:
    explicit Socket(event_base* event_base = nullptr);
    virtual ~Socket();

    bool start(uint16_t /* port */);
    void stop();

    fnc_accept callback_accept = [](const std::shared_ptr<Client>&){};
    fnc_disconnect callback_disconnect = [](const std::shared_ptr<Client>&){};
    fnc_read callback_read;
private:
    int socket = 0;

    event* event_accept = nullptr;
    void on_accept(int fd, short);

    event_base* event_base_loop = nullptr;
    bool own_event_base = false;

    std::mutex connection_lock;
    std::deque<std::shared_ptr<Client>> connections;

    void on_disconnect(Client*);
};