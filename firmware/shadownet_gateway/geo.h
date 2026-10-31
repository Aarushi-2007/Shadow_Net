// ShadowNet — geo report payload
//
// The whole 16-byte application payload, as a struct. Coordinates are
// stored as degrees x 1e7 in a signed 32-bit integer: the same fixed-point
// convention u-blox GPS modules report natively, so a real module drops in
// without a format change, and no floating point ever touches the wire.
//
//   lat  int32   4 bytes
//   lon  int32   4 bytes
//   note char[8] 8 bytes
//   -------------------
//                16 bytes == CONTROL_DATA_LEN
//
// The payload is the same size it always was, so every anonymity result
// (constant 128-byte frames, constant used_len, constant type) is
// unaffected by carrying coordinates instead of text.

#pragma once
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "packet.hpp"

namespace shadownet {

#pragma pack(push, 1)
struct GeoReport {
    int32_t lat_e7;
    int32_t lon_e7;
    char    note[8];   // short tag; NOT guaranteed NUL-terminated when full
};
#pragma pack(pop)
static_assert(sizeof(GeoReport) == CONTROL_DATA_LEN,
              "GeoReport must fill the payload exactly");

// Format one coordinate as e.g. "+31.7754", without floating point.
inline void geo_fmt(int32_t e7, char* out, size_t len) {
    const char sign = (e7 < 0) ? '-' : '+';
    uint32_t a = (e7 < 0) ? (uint32_t)(-(int64_t)e7) : (uint32_t)e7;
    snprintf(out, len, "%c%lu.%04lu", sign,
             (unsigned long)(a / 10000000UL),
             (unsigned long)((a % 10000000UL) / 1000UL));
}

// "31.7754" -> 317754000. Accepts a leading sign.
inline int32_t geo_parse(const char* s) {
    double d = strtod(s, nullptr);
    if (d > 180.0) d = 180.0;
    if (d < -180.0) d = -180.0;
    return (int32_t)(d * 10000000.0 + (d >= 0 ? 0.5 : -0.5));
}

// "+31.7754 +76.9861" into `out` (needs ~20 bytes).
inline void geo_pair(const GeoReport& g, char* out, size_t len) {
    char a[14], b[14];
    geo_fmt(g.lat_e7, a, sizeof(a));
    geo_fmt(g.lon_e7, b, sizeof(b));
    snprintf(out, len, "%s %s", a, b);
}

} // namespace shadownet