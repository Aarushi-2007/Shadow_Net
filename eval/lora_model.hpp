// LoRa PHY airtime / duty-cycle / energy model.
//
// These are the exact formulas from the Semtech SX1272/SX1276 datasheet
// (section "LoRa Modem Time on Air"), which the SX1262 shares. They are
// closed-form, not estimates — given SF/BW/CR/payload they tell you exactly
// how many milliseconds a packet occupies the channel.
//
// WHY THIS FILE EXISTS: Wu & Li (2006) evaluate throughput as a ratio of
// hop counts under an assumed ~60% CSMA channel efficiency (Section 5.4).
// That model is for 802.11-class radios where a packet takes microseconds.
// On LoRa at SF9 a 129-byte packet takes most of a second, so the paper's
// "the bandwidth consumption for sending request carriers can be ignored if
// the sending frequency is not too high" needs to be re-derived, not
// assumed, for this hardware. That's what this model lets the evaluation do.

#pragma once
#include <cmath>
#include <cstddef>
#include <cstdint>

namespace shadownet {
namespace lora {

struct PhyConfig {
    int sf = 7;              // spreading factor 6..12
    double bw_hz = 125000.0; // bandwidth in Hz
    int cr_denom = 7;        // RadioLib style: 5..8 meaning coding rate 4/5..4/8
    int preamble_syms = 8;
    bool explicit_header = true;
    bool crc_on = true;
    double tx_power_dbm = 14.0;
};

// Symbol time: T_sym = 2^SF / BW
inline double symbol_time_s(const PhyConfig& c) {
    return std::pow(2.0, c.sf) / c.bw_hz;
}

// Low Data Rate Optimization is mandatory when T_sym > 16 ms (SF11/SF12 at
// 125 kHz). It costs throughput, so the model has to account for it.
inline bool low_data_rate_opt(const PhyConfig& c) {
    return symbol_time_s(c) > 0.016;
}

// Number of symbols in the payload portion, per the datasheet formula:
//   n = 8 + max(ceil((8PL - 4SF + 28 + 16CRC - 20IH) / (4(SF - 2DE))) * (CR+4), 0)
inline double payload_symbols(const PhyConfig& c, size_t payload_bytes) {
    const int DE = low_data_rate_opt(c) ? 1 : 0;
    const int IH = c.explicit_header ? 0 : 1;
    const int CRC = c.crc_on ? 1 : 0;
    const int CR = c.cr_denom - 4; // 1..4

    const double numer = 8.0 * static_cast<double>(payload_bytes)
                       - 4.0 * c.sf + 28.0 + 16.0 * CRC - 20.0 * IH;
    const double denom = 4.0 * (c.sf - 2.0 * DE);
    double n = std::ceil(numer / denom) * (CR + 4);
    if (n < 0) n = 0;
    return 8.0 + n;
}

inline double preamble_time_s(const PhyConfig& c) {
    return (c.preamble_syms + 4.25) * symbol_time_s(c);
}

inline double payload_time_s(const PhyConfig& c, size_t payload_bytes) {
    return payload_symbols(c, payload_bytes) * symbol_time_s(c);
}

// Total time-on-air for one packet, in seconds.
inline double time_on_air_s(const PhyConfig& c, size_t payload_bytes) {
    return preamble_time_s(c) + payload_time_s(c, payload_bytes);
}

inline double time_on_air_ms(const PhyConfig& c, size_t payload_bytes) {
    return 1000.0 * time_on_air_s(c, payload_bytes);
}

// Effective on-air bitrate for this configuration (bits/sec of PHY payload),
// i.e. what you actually get once preamble + coding overhead is paid.
inline double effective_bitrate_bps(const PhyConfig& c, size_t payload_bytes) {
    return (8.0 * static_cast<double>(payload_bytes)) / time_on_air_s(c, payload_bytes);
}

// --- Energy -------------------------------------------------------------
// Current draw figures for SX1262 at typical settings (datasheet Table
// "Power Consumption"). These are the radio only — the ESP32-S3 core draws
// its own current on top, which the on-board benchmark measures separately.
struct PowerModel {
    double tx_current_ma_14dbm = 45.0;  // SX1262 @ +14 dBm, DC-DC
    double rx_current_ma = 5.3;         // SX1262 RX boosted gain
    double idle_current_ma = 1.5;       // standby with XOSC
    double mcu_active_ma = 40.0;        // ESP32-S3 running, radio-independent
    double supply_v = 3.3;
};

// Energy in millijoules for a given duration at a given current.
inline double energy_mj(double current_ma, double seconds, double supply_v = 3.3) {
    return current_ma * 1e-3 * supply_v * seconds * 1000.0;
}

// --- Regulatory ---------------------------------------------------------
// Duty-cycle caps by band. India's 865-867 MHz ISM band permits higher duty
// use than EU's 868 sub-bands, but the EU numbers are the ones most
// commonly cited and the ones a report should be checked against.
struct DutyCycleLimit {
    const char* name;
    double max_fraction; // e.g. 0.01 for 1%
};

inline const DutyCycleLimit EU868_G1{"EU 868 MHz (g1 sub-band)", 0.01};
inline const DutyCycleLimit EU868_G3{"EU 868 MHz (g3 sub-band)", 0.10};
inline const DutyCycleLimit IN865{"India 865-867 MHz ISM", 0.01};

} // namespace lora
} // namespace shadownet
