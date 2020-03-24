#include "pipes/rtc/PeerConnection.h"
#include "pipes/rtc/NiceWrapper.h"
#include "pipes/rtc/ApplicationStream.h"
#include "pipes/rtc/RtpStream.h"
#include "pipes/rtc/AudioStream.h"
#include "pipes/rtc/VideoStream.h"
#include "pipes/rtc/DTLSPipe.h"
#include "pipes/rtc/RTPPacket.h"
#include "pipes/rtc/Protocol.h"
#include "pipes/misc/logger.h"
#include "./json.h"

#include <iostream>
#include <utility>
#include <cassert>

#ifdef SDPTRANSFORM_INTERNAL
    #include <sdptransform.hpp>
#else
    #include <sdptransform/sdptransform.hpp>
#endif

using namespace std;
using namespace rtc;

PeerConnection::PeerConnection(std::shared_ptr<Config>  config) : config(std::move(config)) { }
PeerConnection::~PeerConnection() {
    this->reset();
}

void PeerConnection::reset() {
    //TODO: Somehow join all still running callbacks (manly because of arrived data)
    {
        std::unique_lock streams_lock{this->stream_lock};
        auto open_streams = std::move(this->streams);

        for(auto& stream : this->dtls_streams) {
            stream->on_initialized = nullptr;
            stream->on_data = nullptr;
        }
        this->dtls_streams.clear();
        streams_lock.unlock();

        for(auto& stream : open_streams) {
            std::unique_lock owner_lock{stream->_owner_lock};
            stream->_owner = nullptr;
            stream->_nice_stream_id = 0;
        }
    }

    if(this->nice) this->nice->finalize();
}

bool PeerConnection::initialize(std::string &error) {
    if(!this->config || !this->config->nice_config) {
        error = "Invalid config!";
        return false;
    }
    if(this->nice) {
        error = "invalid state! Please call reset() first!";
        return false;
    }

    shared_ptr<NiceStream> stream;
    {
        this->nice = make_unique<NiceWrapper>(this->config->nice_config);
        this->nice->logger(this->config->logger);

        this->nice->set_callback_local_candidate([&](const std::shared_ptr<NiceStream>& nice_stream, const std::vector<std::string>& candidates, bool more_candidates) {
            if(!this->callback_ice_candidate) return;

            for(const auto& stream : this->available_streams()) {
                if(stream->nice_stream_id() == nice_stream->stream_id) {
                     for(const auto &it : candidates) {
                        this->callback_ice_candidate(IceCandidate{it.length() > 2 ? it.substr(2) : it, stream->get_mid(), this->sdp_mline_index(stream)});
                    }
                    if(!more_candidates)
                        this->callback_ice_candidate(IceCandidate{"", stream->get_mid(), this->sdp_mline_index(stream)});
                }
            }
        });

        //FIXME!
        /*
        this->nice->set_callback_failed([&] {
            this->trigger_setup_fail(ConnectionComponent::NICE, "");
        });
         */
        if(!this->nice->initialize(error)) {
            error = "Failed to initialize nice (" + error + ")";
            return false;
        }
    }

    return true;
}

static void setup_sdptransform() {
    typedef std::map<char, std::vector<sdptransform::grammar::Rule>> SDPRuleMap;
    static bool setupped{false};
    if(setupped) return;

    const SDPRuleMap* rules_map = &sdptransform::grammar::rulesMap;
    auto mutable_rules_map = (SDPRuleMap*) rules_map;
    auto& map = (*mutable_rules_map)['a'];

    map.insert(map.begin(),
            // a=sctp-port:5000
               {
                       // name:
                       "sctp-port",
                       // push:
                       "",
                       // reg:
                       std::regex("^sctp-port:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[0-5]?[0-9]{1,4})$"),
                       // names:
                       { },
                       // types:
                       { 'd' },
                       // format:
                       "sctp-port:%d"
               });
    setupped = true;
}

bool PeerConnection::apply_offer(std::string& error, const std::string &raw_sdp) {
    setup_sdptransform();
    auto sdp = sdptransform::parse(raw_sdp);
    if(sdp.count("media") <= 0) {
        error = "Missing media entry";
        return false;
    }

    if(this->config->print_parse_sdp) {
        LOG_VERBOSE(this->config->logger, "PeerConnection::apply_offer", "Got sdp offer:");
        LOG_VERBOSE(this->config->logger, "PeerConnection::apply_offer", "%s", sdp.dump(4).c_str());
    }

    //merged_nice_channels
    nlohmann::json& media = sdp["media"];
    if(!media.is_array()) {
        error = "missing media entry";
        return false;
    }

    unique_lock stream_lock{this->stream_lock};
    this->streams.reserve(media.size());
    stream_lock.unlock();

    size_t stream_index{0};
    std::string nice_streams_sdp{"v=0\n"};
    for(nlohmann::json& media_entry : media) {
        if(media_entry.count("iceUfrag") <= 0) {
            error = "media entry misses ice username";
            return false;
        }
        if(media_entry.count("icePwd") <= 0) {
            error = "media entry misses ice password";
            return false;
        }
        if(media_entry.count("setup") <= 0) {
            error = "media entry misses setup entry";
            return false;
        }

        std::string ice_username{media_entry["iceUfrag"]};
        auto nice_stream = this->nice->find_stream(ice_username);
        if(!nice_stream) {
            nice_stream = this->nice->add_stream(ice_username);

            if(!nice_stream) {
                error = "failed to allocate nice stream for media entry";
                return false;
            }
            nice_stream->callback_receive = [&, stream_id{nice_stream->stream_id}](const pipes::buffer_view& data) {
                this->handle_nice_data(stream_id, data);
            };


            /* the dtls stream */
            {
                auto config = std::make_shared<DTLSPipe::Config>();
                config->logger = this->config->logger;

                auto dtls_stream = std::make_shared<DTLSPipe>(this->nice, nice_stream->stream_id, config);
                if(!dtls_stream->initialize(error)) {
                    error = "failed to initialize dtls pipe for new nice stream (" + error + ")";
                    return false;
                }

                dtls_stream->on_initialized = [&, stream_id{nice_stream->stream_id}] {
                    auto dtls = this->find_dts_pipe(stream_id);
                    if(!dtls) {
                        LOG_ERROR(this->config->logger, "PeerConnection::dtls", "Received initialized callback, but dtls handle is unknown");
                        return;
                    }

                    for(const auto& stream : this->available_streams())
                        if(stream->nice_stream_id() == stream_id)
                            stream->on_dtls_initialized(dtls);
                };
                dtls_stream->on_data = [&, stream_id{nice_stream->stream_id}](const pipes::buffer_view& data) {
                    this->handle_dtls_data(stream_id, data);
                };

                stream_lock.lock();
                this->dtls_streams.push_back(dtls_stream);
                stream_lock.unlock();

                nice_stream->callback_ready = [pipe = std::weak_ptr<DTLSPipe>{dtls_stream}]{
                    auto pipe_ref = pipe.lock();
                    if(!pipe_ref) return;

                    pipe_ref->on_nice_ready();
                };
            }

            /* create a matching sdp */
            {
                size_t index{0}, findex{0};
                size_t iter{0};

                do {
                    findex = raw_sdp.find("m=", index + 1); //the raw_spd will never start with m= :)
                    if(index == findex) {
                        error = "failed to find media stream start, but sdptransform found it... (0)";
                        return false;
                    }

                    if(iter == stream_index + 1) {
                        nice_streams_sdp += raw_sdp.substr(index, (findex == std::string::npos ? raw_sdp.length() : findex) - index) + "\n";
                        break;
                    } else {
                        index = findex;
                    }
                } while(iter++ <= stream_index);
                if(iter != stream_index + 1) {
                    error = "failed to find media stream start, but sdptransform found it... (1)";
                    return false;
                }
            }
        }

        /* role setup */
        {
            auto dtls_stream = this->find_dts_pipe(nice_stream->stream_id);
            assert(dtls_stream);

            string setup_type = media_entry["setup"];
            LOG_VERBOSE(this->config->logger, "PeerConnection::apply_offer", "Stream setup type: %s", setup_type.c_str());

            DTLSPipe::Role target_role{DTLSPipe::Undefined};
            if(setup_type == "active")
                target_role = DTLSPipe::Server;
            else if(setup_type == "passive")
                target_role = DTLSPipe::Client;
            if(target_role != DTLSPipe::Undefined) {
                if(dtls_stream->role() != DTLSPipe::Undefined && dtls_stream->role() != target_role) {
                    error = "inconsistent media stream roles";
                    return false;
                }

                dtls_stream->role(target_role);
            }
        }

        string type = media_entry["type"];
        std::shared_ptr<Stream> stream{nullptr};
        if(type == "audio") {
            auto config = make_shared<AudioStream::Configuration>();
            config->logger = this->config->logger;

            stream = std::make_shared<AudioStream>(this, nice_stream->stream_id, config);
            if(!stream->apply_sdp(sdp, media_entry)) {
                error = "failed to apply sdp for audio stream";
                return false;
            }
        } else if(type == "video") {
            auto config = make_shared<VideoStream::Configuration>();
            config->logger = this->config->logger;

            stream = std::make_shared<VideoStream>(this, nice_stream->stream_id, config);
            if(!stream->apply_sdp(sdp, media_entry)) {
                error = "failed to apply sdp for video stream";
                return false;
            }
        } else if(type == "application") {
            auto config = make_shared<ApplicationStream::Configuration>();
            config->logger = this->config->logger;

            stream = std::make_shared<ApplicationStream>(this, nice_stream->stream_id, config);
            if(!stream->initialize(error)) {
                error = "failed to initialize application stream";
                return false;
            }
            if(!stream->apply_sdp(sdp, media_entry)) {
                error = "failed to apply sdp for application stream";
                return false;
            }
        } else {
            error = "unknown media entry type " + type;
            return false;
        }

        stream_lock.lock();
        this->streams.push_back(std::move(stream));
        stream_lock.unlock();
        stream_index++;
    }
    for(const auto& lines : this->streams)
        this->callback_new_stream(lines);

    if(!nice->apply_remote_sdp(error, nice_streams_sdp)) {
        error = "failed to setup nice (" + error + ")";
        return false;
    }

    for(const auto& stream : nice->available_streams()) {
        if(!nice->gather_candidates(stream))
            LOG_ERROR(this->config->logger, "PeerConnection::apply_offer", "failed to start gathering for stream %u", stream->stream_id);
    }

    return true;
}

int PeerConnection::apply_ice_candidates(const std::deque<std::shared_ptr<rtc::IceCandidate>> &candidates) {
    //TODO: Prevent that candidates getting applied twice?

    int success_counter = 0;
    for(const auto& candidate : candidates) {
        std::shared_ptr<NiceStream> nice_handle;

        for(const auto& stream : this->available_streams()) {
            if(stream->get_mid() == candidate->sdpMid) {
                nice_handle = this->nice->find_stream(stream->nice_stream_id());
                break;
            }
        }
        if(!nice_handle) {
            LOG_ERROR(this->config->logger, "PeerConnection::apply_ice_candidates", "Failed to find nice handle for %s (%u)", candidate->sdpMid.c_str(), candidate->sdpMLineIndex);
            continue;
        }

        auto result = this->nice->apply_remote_ice_candidates(nice_handle, {"a=" + candidate->candidate});
        if(result < 0) {
            LOG_ERROR(this->config->logger, "PeerConnection::apply_ice_candidates", "Failed to apply candidate %s for %s (%u). Result: %d", candidate->candidate.c_str(), candidate->sdpMid.c_str(), candidate->sdpMLineIndex, result);
        } else success_counter++;
    }
    return success_counter;
}

bool PeerConnection::remote_candidates_finished() {
    for(const auto& stream : this->nice->available_streams())
        this->nice->remote_ice_candidates_finished(stream);
    return true;
}

#define SESSION_ID_SIZE 16
std::string random_session_id() {
    const static char *numbers = "0123456789";
    srand((unsigned)time(nullptr));
    std::stringstream result;

    for (int i = 0; i < SESSION_ID_SIZE; ++i) {
        int r = rand() % 10;
        result << numbers[r];
    }
    return result.str();
}

std::string PeerConnection::generate_answer(bool candidates) {
    std::stringstream sdp;
    std::string session_id = random_session_id();

    /* General header */
    sdp << "v=0\r\n";
    //FIXME Copy username from request
    sdp << "o=- " << session_id << " 2 IN IP4 0.0.0.0\r\n";
    sdp << "s=-\r\n"; //Username?
    sdp << "t=0 0\r\n";


    {
        sdp << "a=group:BUNDLE";
        for(const auto& entry : this->streams) {
            sdp << " " << entry->get_mid();
        }
        sdp << "\r\n";
    }
    sdp << "a=msid-semantic: WMS DataPipes\r\n";

    auto nice_entries = this->nice->generate_local_sdp(candidates);
    for(const auto& entry : this->streams) {
        sdp << entry->generate_sdp();

        auto dtls_pipe = this->find_dts_pipe(entry->nice_stream_id());
        if(dtls_pipe) {
            auto certificate = dtls_pipe->dtls_certificate();
            assert(certificate);
            sdp << "a=fingerprint:sha-256 " << certificate->getFingerprint() << "\r\n";
            sdp << "a=setup:" << (dtls_pipe->role() == DTLSPipe::Server ? "passive" : "active") << "\r\n";
        } else {
            LOG_ERROR(this->config->logger, "PeerConnection::generate_answer", "Media stream %s (%u) missing dtls pipe!", entry->get_mid().c_str(), entry->nice_stream_id());
        }


        for(const auto& nice_entry : nice_entries) {
            if(nice_entry->stream_id != entry->nice_stream_id()) continue;

            if(!nice_entry->has.ice_ufrag) {
                LOG_ERROR(this->config->logger, "PeerConnection::generate_answer", "Media stream %s (%u) missing ice ufrag!", entry->get_mid().c_str(), entry->nice_stream_id());
                continue;
            }
            if(!nice_entry->has.ice_pwd) {
                LOG_ERROR(this->config->logger, "PeerConnection::generate_answer", "Media stream %s (%u) missing ice pwd!", entry->get_mid().c_str(), entry->nice_stream_id());
                continue;
            }
            if(!nice_entry->has.candidates && candidates) {
                LOG_ERROR(this->config->logger, "PeerConnection::generate_answer", "Media stream %s (%u) missing ice candidates, but its requested!", entry->get_mid().c_str(), entry->nice_stream_id());
                continue;
            }

            sdp << "a=ice-ufrag:" << nice_entry->ice_ufrag << "\r\n";
            sdp << "a=ice-pwd:" << nice_entry->ice_pwd << "\r\n";
            //if(!candidates) //We send the candidates later
            sdp << "a=ice-options:trickle\r\n";

            for(const auto& candidate : nice_entry->candidates)
                sdp << "a=candidate:" << candidate << "\r\n";
            if(candidates)
                sdp << "a=end-of-candidates\r\n";
            break;
        }
    }

    return sdp.str();
}

void PeerConnection::handle_nice_data(rtc::NiceStreamId stream, const pipes::buffer_view &buffer) {
    auto dtls = this->find_dts_pipe(stream);
    if(!dtls) {
        LOG_VERBOSE(this->config->logger, "PeerConnection::handle_nice_data", "Dropping %i incoming bytes because of missing dtls handle", buffer.length());
        return;
    }

    if (pipes::SSL::is_ssl(buffer.data_ptr<u_char>(), buffer.length()) || (!protocol::is_rtp(buffer.data_ptr<void>(), buffer.length()) && !protocol::is_rtcp(buffer.data_ptr<void>(), buffer.length()))) {
        dtls->process_incoming_data(buffer);
        return;
    }
    if(!dtls->dtls_initialized()) {
        dtls->process_incoming_data(buffer);
    } else if(protocol::is_rtp(buffer.data_ptr<void>(), buffer.length())) {
        int process_count{0};
        RTPPacket packet{CryptState::ENCRYPTED, buffer};
        for(const auto& str : this->find_streams_from_nice_stream(stream))
            if(str->process_incoming_rtp_data(packet))
                process_count++;
        if(!process_count)
            LOG_ERROR(this->config->logger, "PeerConnection::handle_nice_data", "Received RTP packet which hasn't been handled by any stream. Dropping packet.");
    } else if(protocol::is_rtcp(buffer.data_ptr<void>(), buffer.length())) {
        int process_count{0};
        RTCPPacket packet{CryptState::ENCRYPTED, buffer};
        for(const auto& str : this->find_streams_from_nice_stream(stream))
            if(str->process_incoming_rtcp_data(packet))
                process_count++;
        if(!process_count)
            LOG_ERROR(this->config->logger, "PeerConnection::handle_nice_data", "Received RTP packet which hasn't been handled by any stream. Dropping packet.");
    } else {
        LOG_ERROR(this->config->logger, "PeerConnection::handle_nice_data", "Dropping %i incoming bytes which seems to match no known pattern", buffer.length());
    }
}

void PeerConnection::handle_dtls_data(rtc::NiceStreamId stream, const pipes::buffer_view &buffer) {
    for(const auto& str : this->find_streams_from_nice_stream(stream))
        str->process_incoming_dtls_data(buffer);
}

std::shared_ptr<DTLSPipe> PeerConnection::find_dts_pipe(rtc::NiceStreamId stream) {
    std::shared_lock lock{this->stream_lock};
    for(auto& dtls : this->dtls_streams)
        if(dtls->nice_stream_id() == stream)
            return dtls;
    return nullptr;
}
std::vector<std::shared_ptr<Stream>> PeerConnection::find_streams_from_nice_stream(rtc::NiceStreamId stream_id) {
    std::vector<std::shared_ptr<Stream>> result{};

    std::shared_lock lock{this->stream_lock};
    result.reserve(this->streams.size());
    for(const auto& stream : this->streams)
        if(stream->nice_stream_id() == stream_id)
            result.push_back(stream);
    return result;
}