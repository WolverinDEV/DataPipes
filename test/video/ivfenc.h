/*
 *  Copyright (c) 2013 The WebM project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#pragma once

#include <cstdint>
#include <cstddef>

typedef int ivf_enc_target_t; /* file descriptor */

struct vpx_codec_enc_cfg;
struct vpx_codec_cx_pkt;

void ivf_write_file_header(ivf_enc_target_t out, const struct vpx_codec_enc_cfg *cfg, uint32_t fourcc, int frame_cnt);
void ivf_write_frame_header(ivf_enc_target_t out, int64_t pts, size_t frame_size);
void ivf_write_frame_size(ivf_enc_target_t out, size_t frame_size);