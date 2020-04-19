#pragma once

#include <mutex>
#include <deque>
#include <memory>

#include "../misc/logger.h"
#include "pipes/tls.h"
#include "./NiceWrapper.h"

typedef struct _GMainContext GMainContext;
typedef struct _GSource GSource;
namespace rtc {
    class PeerConnection;
    class DTLSHandler {
            friend class PeerConnection;
        public:
            enum Role { Undefined, Client, Server }; //Undefined will fallback to client
            struct Config {
                bool verbose_io{false}; /* requires verbose log level to be active */
                std::shared_ptr<pipes::Logger> logger;
                GMainContext* event_loop{nullptr};
            };
            DTLSHandler(std::shared_ptr<NiceWrapper>, NiceStreamId, std::shared_ptr<Config>);
            virtual ~DTLSHandler();

            [[nodiscard]] bool initialize(std::string& /* error */);
            void reset();

            [[nodiscard]] bool dtls_initialized() const { return this->_initialized; }

            [[nodiscard]] inline NiceStreamId nice_stream_id() const { return this->_nice_stream; }

            void process_incoming_data(const pipes::buffer_view& /* data */);
            void send_data(const pipes::buffer_view& /* data */, bool /* encrypt */ = true);

            [[nodiscard]]  bool need_buffer_resend() {
                std::lock_guard lock{this->fail_buffer_lock};
                return !this->fail_buffer.empty();
            }
            bool resend_buffers(); /* true if everything has been sended */

            [[nodiscard]] inline Role role() const { return this->_role; }
            void role(Role r) { this->_role = r; }

            [[nodiscard]] inline std::shared_ptr<const pipes::TLSCertificate> dtls_certificate() const {
                return this->_dtls_certificate;
            }

            [[nodiscard]] inline std::shared_ptr<const pipes::TLS> dtls_pipe() const { return this->_dtls; }

            std::function<void()> on_initialized{nullptr};
            std::function<void(const pipes::buffer_view& /* data */)> on_data{nullptr};
        private:
            struct TimerData {
                std::mutex *mutex{nullptr};
                DTLSHandler *handler{nullptr};
            };

            std::shared_ptr<Config> _config{nullptr};
            std::shared_ptr<pipes::TLSCertificate> _dtls_certificate{nullptr}; /* here 'till dtls has been initialized */
            std::shared_ptr<pipes::TLS> _dtls{nullptr};
            std::shared_ptr<NiceWrapper> _nice{nullptr};
            NiceStreamId _nice_stream{0};
            GMainContext* event_context{nullptr};
            GSource* connect_resend_interval{nullptr};

            Role _role{Undefined};
            bool _initialized{false};

            std::mutex fail_buffer_lock{};
            std::deque<pipes::buffer> fail_buffer{};

            TimerData* timer{nullptr};
            std::mutex* timer_mutex{nullptr};

            void on_nice_ready();
    };
}