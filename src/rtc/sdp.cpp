//
// Created by WolverinDEV on 19/04/2020.
//

#include "sdp.h"

/* https://github.com/meetecho/janus-gateway/blob/7aae63518efe96374a94306ed4d3bc00c2a45e4a/sdp.c#L684 */
sdp::candidate_parse_result sdp::parse_candidate(std::string candidate, std::string &error_value, NiceCandidate *&result) {
    using candidate_parse_result = sdp::candidate_parse_result;
    result = nullptr;
    error_value = "";

    if(auto candidate_begin = candidate.find("candidate:"); candidate_begin != std::string::npos)
        candidate = candidate.substr(candidate_begin + 10);

    if(candidate.empty() || candidate == "end-of-candidates")
        return candidate_parse_result::end_of_candidates;

    char rfoundation[33], rtransport[4], rip[50], rtype[6], rrelip[40];
    guint32 rcomponent, rpriority, rport, rrelport;
    int res = sscanf(candidate.c_str(), "%32s %30u %3s %30u %49s %30u typ %5s %*s %39s %*s %30u",
                     rfoundation, &rcomponent, rtransport, &rpriority,
                     rip, &rport, rtype, rrelip, &rrelport);

    if(res < 0)
        return candidate_parse_result::invalid_format;
    else if(res < 7)
        return candidate_parse_result::candidate_skipped;

    if(strstr(rip, ".local")) {/* we're not supporting .local addresses yet */
        error_value = rip;
        return candidate_parse_result::local_address;
    }

    if(!strcasecmp(rtype, "host")) {
        result = nice_candidate_new(NiceCandidateType::NICE_CANDIDATE_TYPE_HOST);

        if(strcasecmp(rtransport, "udp") != 0 && strcasecmp(rtransport, "tcp") != 0) {
            error_value = rtransport;
            return candidate_parse_result::invalid_protocol;
        }
    } else if(!strcasecmp(rtype, "srflx")) {
        result = nice_candidate_new(NiceCandidateType::NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);

        if(strcasecmp(rtransport, "udp") != 0 && strcasecmp(rtransport, "tcp") != 0) {
            error_value = rtransport;
            return candidate_parse_result::invalid_protocol;
        }
    } else if(!strcasecmp(rtype, "prflx")) {
        result = nice_candidate_new(NiceCandidateType::NICE_CANDIDATE_TYPE_PEER_REFLEXIVE);

        if(strcasecmp(rtransport, "udp") != 0 && strcasecmp(rtransport, "tcp") != 0) {
            error_value = rtransport;
            return candidate_parse_result::invalid_protocol;
        }
    } else if(!strcasecmp(rtype, "relay")) {
        result = nice_candidate_new(NiceCandidateType::NICE_CANDIDATE_TYPE_RELAYED);

        if(strcasecmp(rtransport, "udp") != 0 && strcasecmp(rtransport, "tcp") != 0 && strcasecmp(rtransport, "tls") != 0) {
            error_value = rtransport;
            return candidate_parse_result::invalid_protocol;
        }
    } else {
        error_value = rtype;
        return candidate_parse_result::unknown_type;
    }

    if(!strcasecmp(rtransport, "udp")) {
        result->transport = NiceCandidateTransport::NICE_CANDIDATE_TRANSPORT_UDP;
    } else {
        if(candidate.find("tcptype active") != std::string::npos)
            result->transport = NICE_CANDIDATE_TRANSPORT_TCP_ACTIVE;
        else if(candidate.find("tcptype passive") != std::string::npos)
            result->transport = NICE_CANDIDATE_TRANSPORT_TCP_PASSIVE;
        else if(candidate.find("tcptype so") != std::string::npos)
            result->transport = NICE_CANDIDATE_TRANSPORT_TCP_SO;
        else {
            return candidate_parse_result::unknown_tcptype_info;
        }
    }
    g_strlcpy(result->foundation, rfoundation, NICE_CANDIDATE_MAX_FOUNDATION);
    result->priority = rpriority;

    auto added = nice_address_set_from_string(&result->addr, rip);
    if(!added) {
        error_value = rip;
        return candidate_parse_result::invalid_address;
    }

    nice_address_set_port(&result->addr, rport);
    if(result->type == NICE_CANDIDATE_TYPE_SERVER_REFLEXIVE || result->type == NICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
        added = nice_address_set_from_string(&result->base_addr, rrelip);
        if(added)
            nice_address_set_port(&result->base_addr, rrelport);
    } else if(result->type == NICE_CANDIDATE_TYPE_RELAYED) {
        added = nice_address_set_from_string(&result->base_addr, rrelip);
        if(added)
            nice_address_set_port(&result->base_addr, rrelport);
    }
    if(!added) {
        error_value = rrelip;
        return candidate_parse_result::invalid_base_address;
    }

    return candidate_parse_result::success;
}