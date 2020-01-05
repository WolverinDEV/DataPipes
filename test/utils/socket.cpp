#include <event2/event.h>
#include <cstring>
#include <thread>
#include <unistd.h>
#include <algorithm>
#include <iostream>
#include "socket.h"

using namespace std;
using namespace pipes;

Socket::Socket(event_base* event_base_loop) {
    if(event_base_loop)
        this->event_base_loop = event_base_loop;
    else {
        this->event_base_loop = event_base_new();
        this->own_event_base = true;
    }
}

Socket::~Socket() {}

bool Socket::start(uint16_t port) {
    struct sockaddr_in addr{};

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    this->socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (this->socket < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    int optval = 1;
    if (setsockopt(this->socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) < 0)
        printf("Cannot set SO_REUSEADDR option on listen socket (%s)\n", strerror(errno));

    if (setsockopt(this->socket, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(int)) < 0)
        printf("Cannot set SO_REUSEADDR option on listen socket (%s)\n", strerror(errno));

    if (bind(this->socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        return false;
    }
    if (listen(this->socket, 1) < 0) {
        perror("Unable to listen");
        return false;
    }

    this->event_accept = event_new(this->event_base_loop, this->socket, EV_READ | EV_PERSIST, [](int fd, short _, void* _this) {
        ((Socket*) _this)->on_accept(fd, _);
    }, this);
    event_add(this->event_accept, nullptr);
    if(this->own_event_base)
        thread([&](){
            event_base_dispatch(this->event_base_loop);
        }).detach();
    return true;
}

void Socket::stop() {
    if(this->event_accept) {
#ifdef LIBEVENT_USE_BLOCK
        if(blocking) event_del_block(this->event_accept);
        else event_del_noblock(this->event_accept);
#else
        event_del(this->event_accept);
#endif
    }

    {
        lock_guard<mutex> lock(this->connection_lock);
        for(const auto& connection : this->connections)
            connection->disconnect(true);
        this->connections.clear();
    }

    if(this->own_event_base) {
        event_base_loopexit(this->event_base_loop, nullptr);
    }
}

void Socket::on_disconnect(Socket::Client* client) {
    shared_ptr<Client> instance;
    {
        lock_guard<mutex> lock(this->connection_lock);
        for(const auto& entry : this->connections) {
            if(entry.get() == client) {
                instance = entry;
                break;
            }
        }
       if(!instance) return;
        this->connections.erase(find(this->connections.begin(), this->connections.end(), instance));
    }
    this->callback_disconnect(instance);
}

void Socket::on_accept(int socket_fd, short) {
    struct sockaddr_in addr{};
    uint len = sizeof(addr);

    int fd = accept(socket_fd, (struct sockaddr *) &addr, &len);
    if (fd < 0) {
        perror("Unable to accept");
        return;
    }
    auto client = make_shared<Client>();
    client->fd = fd;
    client->handle = this;

    client->event_read = event_new(this->event_base_loop, fd, EV_READ | EV_PERSIST, [](int fd, short _, void *_this) {
        ((Socket::Client *) _this)->on_read(fd);
    }, client.get());
    client->event_write = event_new(this->event_base_loop, fd, EV_WRITE, [](int fd, short _, void *_this) {
        ((Socket::Client *) _this)->on_write(fd);
    }, client.get());

    {
        lock_guard<mutex> lock(this->connection_lock);
        this->connections.push_back(client);
    }
    this->callback_accept(client);
    event_add(client->event_read, nullptr);
}

void Socket::Client::on_read(int fd) {
    size_t chunk_length = 1024;
    buffer chunk(chunk_length);

    auto length = ::read(fd, chunk.data_ptr(), chunk_length);
    if(length <= 0) {
        if(errno == EAGAIN) return;
        cout << "Got error while reading (" << length << ", " << errno << " => " << strerror(errno) << ")" << endl;
        this->disconnect(false);
        return;
    }

    shared_ptr<Client> instance;
    {
        lock_guard<mutex> lock(handle->connection_lock);
        for(const auto& entry : handle->connections) {
            if(entry.get() == this) {
                instance = entry;
                break;
            }
        }
    }
    if(instance && this->handle->callback_read) {
        chunk.resize(length);
        this->handle->callback_read(instance, chunk);
    } else
        perror("Invalid client read handle!");
}

void Socket::Client::on_write(int fd) {
    lock_guard<mutex> lock(this->buffer_lock);
    if(this->buffer_write.empty()) return;

    auto& buffer = this->buffer_write[0];

    auto wrote = ::send(fd, buffer.data_ptr(), buffer.length(), MSG_DONTWAIT | MSG_NOSIGNAL);
    if(wrote > 0 && (size_t) wrote < buffer.length())
        buffer = buffer.range(wrote);
    else
        this->buffer_write.pop_front();

    if(!this->buffer_write.empty())
        event_add(this->event_write, nullptr);
}

void Socket::Client::disconnect(bool blocking) {
    this->close_connection(blocking);
    this->handle->on_disconnect(this);
}

void Socket::Client::close_connection(bool blocking) {
    if(this->event_read) {
#ifdef LIBEVENT_USE_BLOCK
        if(blocking) event_del_block(this->event_read);
        else event_del_noblock(this->event_read);
#else
        event_del(this->event_read);
#endif
        event_free(this->event_read);
        this->event_read = nullptr;
    }

    if(this->event_write) {
#ifdef LIBEVENT_USE_BLOCK
        if(blocking) event_del_block(this->event_write);
        else event_del_noblock(this->event_write);
#else
        event_del(this->event_write);
#endif
        event_free(this->event_write);
        this->event_write = nullptr;
    }

    if(this->fd > 0) {
        shutdown(this->fd, SHUT_RDWR);
        this->fd = 0;
    }
}

void Socket::Client::send(const pipes::buffer_view& message) {
    {
        lock_guard<mutex> lock(this->buffer_lock);
        this->buffer_write.push_back(message.own_buffer());
    }
    event_add(this->event_write, nullptr);
}