#pragma once

#include <sdptransform/json.hpp>

namespace rtc {
    struct json : nlohmann::basic_json<> {
        using basic_json<>::basic_json;
        json(basic_json<> const& j) : basic_json<>(j) {}
    };
}