#pragma once

#include <string>
#include <string_view>
#include <nice/nice.h>

namespace sdp {
    enum struct candidate_parse_result {
        success,
        end_of_candidates,

        candidate_skipped,
        invalid_format,
        unknown_type,
        unknown_tcptype_info,
        invalid_address,
        local_address,
        invalid_base_address,
        invalid_protocol
    };

    /**
     * @return
     *
     * Attention: The result might be set, event thou the call has failed. You've to free it anyways!
     */
    extern candidate_parse_result parse_candidate(std::string /* candidate */, std::string& /* invalid value */, NiceCandidate*& /* result */);
}