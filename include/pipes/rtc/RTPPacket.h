#pragma once

#include "pipes/buffer.h"

namespace rtc {
    enum struct CryptState {
        ENCRYPTED,
        DECRYPTED_VERIFIED,
        DECRYPT_FAILED
    };
    struct RTPPacket {
        CryptState crypt_state{CryptState::ENCRYPTED};
        pipes::buffer_view buffer{};
    };

    struct RTCPPacket {
        CryptState crypt_state{CryptState::ENCRYPTED};
        pipes::buffer_view buffer{};
    };
}