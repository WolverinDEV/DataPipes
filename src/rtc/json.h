#pragma once

#ifdef SDPTRANSFORM_INTERNAL
    #include <json.hpp>
#else
    #include <sdptransform/json.hpp>
#endif

namespace rtc {
    struct json : nlohmann::basic_json<> {
        using basic_json<>::basic_json;
        json(basic_json<> const& j) : basic_json<>(j) {}
    };
}