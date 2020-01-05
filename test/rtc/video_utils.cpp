#include "video_utils.h"

void vutils::codec::RGBtoI420(const uint8_t *rgb, uint8_t *destination, size_t width, size_t height ) {
    const size_t image_size = width * height;
    size_t upos = image_size;
    size_t vpos = upos + upos / 4;
    for( size_t i = 0; i < image_size; ++i ) {
        uint8_t r = rgb[3 * i  ];
        uint8_t g = rgb[3 * i+1];
        uint8_t b = rgb[3 * i+2];
        destination[i] = ( (66 * r + 129 * g + 25 * b ) >> 8 ) + 16;
        if (!((i / width) % 2) && !(i % 2)) {
            destination[upos++] = ( ( -38*r + -74*g + 112*b ) >> 8) + 128;
            destination[vpos++] = ( ( 112*r + -94*g + -18*b ) >> 8) + 128;
        }
    }
}