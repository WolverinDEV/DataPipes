//
// Created by wolverindev on 12.06.19.
//

#include <vpx/vp8.h>
#include <vpx/vpx_encoder.h>
#include <vpx/vpx_image.h>
#include <vpx/vp8cx.h>
#include <assert.h>
#include <cstdio>
#include <zconf.h>
#include <fcntl.h>
#include <cerrno>

#include "./video/ivfenc.h"

#define V_TARGET_FRAMES 20
#define V_FPS 1
#define V_WIDTH  (256)
#define V_HEIGHT (256)


static int encode_frame(vpx_codec_ctx_t *codec, vpx_image_t *img, int frame_index, int flags, int out_fp) {
	int got_pkts = 0;
	vpx_codec_iter_t iter = nullptr;
	const vpx_codec_cx_pkt_t *pkt = nullptr;
	const vpx_codec_err_t res = vpx_codec_encode(codec, img, frame_index, 1, flags, VPX_DL_GOOD_QUALITY);
	//const auto detail = vpx_codec_error_detail(codec);
	assert(res == VPX_CODEC_OK);

	while ((pkt = vpx_codec_get_cx_data(codec, &iter)) != nullptr) {
		got_pkts = 1;

		if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
			ivf_write_frame_header(out_fp, pkt->data.frame.pts, pkt->data.frame.sz);
			auto writen = write(out_fp, pkt->data.frame.buf, pkt->data.frame.sz);
			if (writen != pkt->data.frame.sz) {
				assert(false);
			}

			const int keyframe = (pkt->data.frame.flags & VPX_FRAME_IS_KEY) != 0;
			printf(keyframe ? "K" : ".");
			fflush(stdout);
		}
	}

	return got_pkts;
}

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

void bgrtoyuv420(uint8_t *plane_y, uint8_t *plane_u, uint8_t *plane_v, uint8_t *rgb, uint16_t width, uint16_t height)
{
	uint16_t x, y;
	uint8_t *p;
	uint8_t r, g, b;

	for(y = 0; y != height; y += 2) {
		p = rgb;
		for(x = 0; x != width; x++) {
			b = *rgb++;
			g = *rgb++;
			r = *rgb++;
			*plane_y++ = rgb_to_y(r, g, b);
		}

		for(x = 0; x != width / 2; x++) {
			b = *rgb++;
			g = *rgb++;
			r = *rgb++;
			*plane_y++ = rgb_to_y(r, g, b);

			b = *rgb++;
			g = *rgb++;
			r = *rgb++;
			*plane_y++ = rgb_to_y(r, g, b);

			b = ((int)b + (int)*(rgb - 6) + (int)*p + (int)*(p + 3) + 2) / 4; p++;
			g = ((int)g + (int)*(rgb - 5) + (int)*p + (int)*(p + 3) + 2) / 4; p++;
			r = ((int)r + (int)*(rgb - 4) + (int)*p + (int)*(p + 3) + 2) / 4; p++;

			*plane_u++ = rgb_to_u(r, g, b);
			*plane_v++ = rgb_to_v(r, g, b);

			p += 3;
		}
	}
}

static int frame = 0;
static vpx_image_t* vpx_img_generate(vpx_image_t* handle) {
	auto y_plane_size = V_WIDTH * V_HEIGHT;
	auto z_plane_size = (V_WIDTH / 2) * (V_HEIGHT / 2);
	auto v_plane_size = (V_WIDTH / 2) * (V_HEIGHT / 2);

	auto rgb_buffer = new uint8_t[V_WIDTH * V_HEIGHT * 3];
	auto yuv420_buffer = new uint8_t[y_plane_size + z_plane_size + v_plane_size];

	auto red = ((float) frame++ / (float) V_TARGET_FRAMES) * 0xFF;
	{ /* generate RGB image */
		size_t buffer_index = 0;
		for(int d_w = 0; d_w < V_WIDTH; d_w++) {
			for(int d_h = 0; d_h < V_HEIGHT; d_h++) {
				rgb_buffer[buffer_index++] = 0x00; //Blue
				rgb_buffer[buffer_index++] = 0x00; //Green
				rgb_buffer[buffer_index++] = d_w % 2 == 0 ? red : 0; //Red
			}
		}
	}

	bgrtoyuv420(yuv420_buffer, yuv420_buffer + y_plane_size, yuv420_buffer + y_plane_size + v_plane_size, rgb_buffer, V_WIDTH, V_HEIGHT);
	handle = vpx_img_wrap(handle, VPX_IMG_FMT_I420, V_WIDTH, V_HEIGHT, 1, (u_char*) yuv420_buffer);

	delete[] handle->user_priv;
	handle->user_priv = yuv420_buffer;

	delete[] rgb_buffer;
	return handle;
}

int main() {
	vpx_codec_err_t err;

	auto codec_interface = vpx_codec_vp8_cx();
	vpx_codec_enc_cfg_t codec_config;

	vpx_image_t* vpx_image_handle = nullptr;
	vpx_codec_ctx_t vpx_encoder;

	vpx_image_handle = vpx_img_alloc(nullptr, VPX_IMG_FMT_RGB32, V_WIDTH, V_HEIGHT, 1);
	vpx_image_handle->user_priv = nullptr;

	{
		err = vpx_codec_enc_config_default(codec_interface, &codec_config, 0);
		assert(err == VPX_CODEC_OK);

		codec_config.g_w = V_WIDTH;
		codec_config.g_h = V_HEIGHT;
		codec_config.g_timebase.num = 1;
		codec_config.g_timebase.den = V_FPS;
		codec_config.rc_target_bitrate = 1024 * 8;
		codec_config.g_error_resilient = (vpx_codec_er_flags_t) VPX_ERROR_RESILIENT_DEFAULT;
	}

	auto fp = ::open("test.ivf", O_WRONLY | O_TRUNC);
	assert(fp > 0);

	const char fcc[4]{'V', 'P', '8', '0'};
	ivf_write_file_header(fp, &codec_config, *(unsigned int*) &fcc, V_TARGET_FRAMES);

	err = vpx_codec_enc_init_ver(&vpx_encoder, vpx_codec_vp8_cx(), &codec_config, 0, VPX_ENCODER_ABI_VERSION);
	assert(err == VPX_CODEC_OK);

	/* create and encode frames */
	int frames_encoded = 0, frame_count = 0, keyframe_interval = 0;
	int max_frames = V_TARGET_FRAMES;
	while ((vpx_image_handle = vpx_img_generate(vpx_image_handle))) {
		int flags = 0;
		if (keyframe_interval > 0 && frame_count % keyframe_interval == 0)
			flags |= VPX_EFLAG_FORCE_KF;
		encode_frame(&vpx_encoder, vpx_image_handle, frame_count++, flags, fp);
		frames_encoded++;
		if (max_frames > 0 && frames_encoded >= max_frames) break;
	}

	// Flush encoder.
	while (encode_frame(&vpx_encoder, nullptr, -1, 0, fp)) { }

	printf("\n");
	printf("Processed %d frames.\n", frame_count);

	vpx_img_free(vpx_image_handle);
	err = vpx_codec_destroy(&vpx_encoder);
	assert(err == VPX_CODEC_OK);

	close(fp);
	return 0;
}