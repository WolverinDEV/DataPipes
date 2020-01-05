#pragma once

#include <cstdint>
#include <cstddef>

namespace vutils {
	namespace codec {
		inline size_t I430_size(size_t width, size_t height) {
			return width * height + (width / 2) * (height / 2) * 2;
		}

		inline size_t RGB_size(size_t width, size_t height) {
			return width * height * 3;
		}

		extern void RGBtoI420(const uint8_t* rgb, uint8_t* target, size_t width, size_t height);
	}
}