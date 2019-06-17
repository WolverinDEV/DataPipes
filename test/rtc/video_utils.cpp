#include "video_utils.h"

static uint8_t rgb_to_y(int r, int g, int b)
{
	int y = ((9798 * r + 19235 * g + 3736 * b) >> 15);
	return y>255? 255 : y<0 ? 0 : y;
}

static uint8_t rgb_to_u(int r, int g, int b)
{
	int u = ((-5538 * r + -10846 * g + 16351 * b) >> 15) + 128;
	return u>255? 255 : u<0 ? 0 : u;
}

static uint8_t rgb_to_v(int r, int g, int b)
{
	int v = ((16351 * r + -13697 * g + -2664 * b) >> 15) + 128;
	return v>255? 255 : v<0 ? 0 : v;
}

void RGBtoYUV420(uint8_t *plane_y, uint8_t *plane_u, uint8_t *plane_v, const uint8_t *rgb, size_t width, size_t height) {
	size_t x, y;
	const uint8_t *p;
	uint8_t r, g, b;

	for(y = 0; y != height; y += 2) {
		p = rgb;
		for(x = 0; x != width; x++) {
			r = *rgb++;
			g = *rgb++;
			b = *rgb++;
			*plane_y++ = rgb_to_y(r, g, b);
		}

		for(x = 0; x != width / 2; x++) {
			r = *rgb++;
			g = *rgb++;
			b = *rgb++;
			*plane_y++ = rgb_to_y(r, g, b);

			r = *rgb++;
			g = *rgb++;
			b = *rgb++;
			*plane_y++ = rgb_to_y(r, g, b);

			r = ((int)r + (int)*(rgb - 6) + (int)*p + (int)*(p + 3) + 2) / 4; p++;
			g = ((int)g + (int)*(rgb - 5) + (int)*p + (int)*(p + 3) + 2) / 4; p++;
			b = ((int)b + (int)*(rgb - 4) + (int)*p + (int)*(p + 3) + 2) / 4; p++;

			*plane_u++ = rgb_to_u(r, g, b);
			*plane_v++ = rgb_to_v(r, g, b);

			p += 3;
		}
	}
}

void vutils::codec::RGBtoI420(const uint8_t *rgb, uint8_t *target, size_t width, size_t height) {
	auto y_plane_size = width * height;
	auto z_plane_size = (width / 2) * (height / 2);
	auto v_plane_size = (width / 2) * (height / 2);

	RGBtoYUV420(target, target + y_plane_size, target + y_plane_size + v_plane_size, rgb, width, height);
}