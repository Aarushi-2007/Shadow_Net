// Tiny OLED status helper for the Heltec V3's onboard SSD1306 (U8g2 library).
// Install "U8g2" from the Arduino Library Manager.
#pragma once
#include <U8g2lib.h>
#include <stdarg.h>
#include "node_config.h"

static U8G2_SSD1306_128X64_NONAME_F_HW_I2C g_oled(U8G2_R0, OLED_RST_PIN, OLED_SCL_PIN, OLED_SDA_PIN);

// Powers the Vext rail (shared with the radio) and starts the display.
inline void oledBegin() {
    pinMode(VEXT_PIN, OUTPUT);
    digitalWrite(VEXT_PIN, LOW);
    delay(100);
    g_oled.begin();
    g_oled.setFont(u8g2_font_6x10_tr);
}

// Title bar + up to 5 body lines (21 chars each fit on the 128px screen).
inline void oledShow(const char* title, const char* l1 = "", const char* l2 = "",
                     const char* l3 = "", const char* l4 = "", const char* l5 = "") {
    const char* lines[5] = {l1, l2, l3, l4, l5};
    g_oled.clearBuffer();
    g_oled.drawStr(0, 9, title);
    g_oled.drawHLine(0, 12, 128);
    for (int i = 0; i < 5; ++i) g_oled.drawStr(0, 23 + i * 10, lines[i]);
    g_oled.sendBuffer();
}
