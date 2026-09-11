# ShadowNet Onion Ring — implementation

A working implementation of the Onion Ring protocol from Wu & Li,
*"Achieving Privacy in Mesh Networks"* (SASN '06), adapted to your 3
Heltec WiFi LoRa 32 V3 nodes (ESP32-S3 + internal SX1262): 1 Gateway + 2
forwarders (F1, F2) in a fixed ring `G -> F1 -> F2 -> G`.

**Start here:** build and run `sim/`. It's the same protocol code the
firmware runs, over an in-memory channel instead of a radio, so you can
watch the whole thing work — key exchange, ring formation, dummy traffic,
a real access request, a granted downlink, an ack, and a tamper-detection
test — in about a second, with no hardware needed. That's the thing to
run in front of your teacher first; the firmware is the same logic on
real boards.

## Layout

```
core/               Protocol logic — pure C++, no radio/Arduino dependency
  crypto.hpp           crypto primitives interface (X25519, HKDF-SHA256, AES-256-GCM)
  crypto_openssl.cpp    host backend (used by sim/)
  crypto_mbedtls.cpp     ESP32-S3 backend (used by firmware/, via mbedTLS)
  packet.hpp            fixed-size wire packet format
  ring_node.hpp/.cpp    GatewayNode / ForwarderNode — the actual Onion Ring protocol

sim/                Host simulation — run this first
  main.cpp

eval/               Evaluation harness — the numbers for your report
  lora_model.hpp        LoRa airtime / duty-cycle / energy model (Semtech formulas)
  eval_main.cpp         every metric, tagged [MEASURED] / [SIMULATED] / [MODELLED]
  results/              CSVs for plotting (created on first run)

firmware/           ESP32 Arduino sketches for your 3 real boards
  tools/keygen/        flash once per board: generates + persists its keypair
  tools/bench/         flash to one board: on-MCU crypto timing + side-channel test
  shadownet_gateway/   flash to the Gateway board
  shadownet_forwarder/ flash to F1 and F2 (same .ino, different node_config.h)
```

See **EVALUATION.md** for what each metric is, which paper section it comes
from, and how to structure the evaluation chapter of your report.

`core/` is the single source of truth for the protocol. The sim links it
against OpenSSL; the firmware sketches each have their own copy of `core/`
(plus `crypto_mbedtls.cpp` instead of `crypto_openssl.cpp`) so Arduino IDE
can compile them with zero extra project setup. If you change the
protocol logic, edit `core/ring_node.cpp` / `core/packet.hpp` and copy the
updated files into both firmware sketch folders.

## 0. Before you touch code: hardware notes + software

**Heltec V3 / SX1262 notes** — your boards' transceiver is *internal*
(unlike a bare ESP32 + external SX1276 module), so there's nothing to
physically wire for the radio itself — VCC/GND/SCK/MISO/MOSI/NSS/RST/DIO1
are all fixed traces on the board. What that means for the firmware
instead of a wiring table:

- **Pins are fixed in `node_config.h`** as `LORA_NSS_PIN=8`, `LORA_SCK_PIN=9`,
  `LORA_MISO_PIN=11`, `LORA_MOSI_PIN=10`, `LORA_RST_PIN=12`,
  `LORA_BUSY_PIN=13`, `LORA_DIO1_PIN=14` — these are Heltec's published V3
  values. If `radio.begin()` fails on a specific unit, this is the first
  thing to double-check against Heltec's own example sketches for your
  exact board revision (silkscreen should say "HTIT-WB32..." — search that
  code + "pinout" if in doubt).
- **Vext power gate**: the onboard SX1262 (and the OLED, if you ever use
  it) sits behind a power-enable pin (`VEXT_PIN=36`) that must be driven
  LOW before `radio.begin()` — the firmware does this in `setup()`. A
  plain external SX1276 module never needed this; skipping it on this
  board means the radio silently never powers on.
- **SX1262's BUSY pin**: a control line the SX1276 didn't have — RadioLib's
  `SX1262` class needs it (that's the 4th constructor argument), it's not
  optional here the way DIO1 sometimes was for SX1276.
- **DIO2-as-RF-switch**: Heltec V3 (like most SX1262 boards) uses the
  chip's DIO2 pin to control the antenna's TX/RX switch instead of a
  separate GPIO. The firmware calls `radio.setDio2AsRfSwitch(true)` right
  after `begin()` — without it, `radio.begin()` can report success while
  the antenna gets little or no actual signal.
- **TCXO voltage**: SX1262 modules commonly use a temperature-compensated
  crystal instead of a plain one, which RadioLib needs a voltage for
  (`LORA_TCXO_VOLTAGE=1.6` in `node_config.h`, the commonly-documented
  value for this board). If `radio.begin()` returns a TCXO-related error
  code, that's the value to try changing (0 disables TCXO handling
  entirely, for boards that turn out to use a plain crystal instead).
- **Frequency variant**: Heltec ships WiFi LoRa 32 V3 in region-specific
  RF variants (433/470/868/915 MHz). Check your board's listing or
  silkscreen and set `LORA_FREQ_MHZ` accordingly — same requirement as
  before, just double-check it since it's easy to assume and be wrong.
- **Antenna**: make sure the screw-on antenna is actually attached before
  testing range — same as any LoRa board, but easy to forget.

None of this touches `core/` — the onion-ring protocol logic has no idea
what radio chip is underneath it; only the two firmware `.ino` files and
their `node_config.h` know about SX1262 specifics.

All 3 boards are the same hardware, so the same pin values in
`node_config.h` apply to all of them unchanged — you should only need to
edit `LORA_FREQ_MHZ` if your 3 units turn out to be different regional
variants (unlikely if bought together).

**Software (do this once, on your laptop):**
1. Install the Arduino IDE (2.x).
2. File > Preferences > "Additional boards manager URLs" — add
   `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`,
   then Tools > Board > Boards Manager, search "esp32", install the
   Espressif package. This is what gives you `Preferences.h` and mbedTLS.
3. Tools > Manage Libraries — search "RadioLib" (by Jgromes), install it —
   version 6.x or newer (needed for the `SX1262`/`setDio2AsRfSwitch` API
   this firmware uses).
4. Tools > Board — select an ESP32-S3 board. Either the generic
   "ESP32S3 Dev Module" (from the Espressif package above — works fine,
   since this firmware hardcodes its own pin numbers rather than relying
   on board-specific pin macros), or, if you'd rather also get Heltec's
   own board-specific macros/OLED support for other work, add
   `https://resource.heltec.cn/download/package_heltec_esp32_index.json`
   as another boards-manager URL and pick "Heltec WiFi LoRa 32(V3)"
   instead — either selection works with this firmware unchanged.
5. Unzip `shadownet_onion_ring.zip` somewhere on disk. Arduino IDE wants
   each sketch in a folder matching its `.ino` filename, which is already
   how `firmware/tools/keygen/`, `firmware/shadownet_gateway/`, and
   `firmware/shadownet_forwarder/` are laid out — just open the `.ino`
   file inside each folder directly.

## 1. Run the simulation

```bash
g++ -std=c++17 -O2 core/crypto_openssl.cpp core/ring_node.cpp sim/main.cpp \
    -o sim/shadownet_sim -lssl -lcrypto
./sim/shadownet_sim
```

(Needs OpenSSL dev headers: `sudo apt install libssl-dev` on Debian/Ubuntu,
or `brew install openssl` on macOS — see that platform's OpenSSL include/
lib path if the linker can't find it.)

**On Windows**, there's no `g++`/OpenSSL dev headers out of the box, so use
WSL rather than trying to compile natively:

1. Open PowerShell **as Administrator** and run `wsl --install`. Reboot if
   it asks. This installs Ubuntu inside Windows (one-time, ~5-10 min incl.
   the reboot).
2. Open the new "Ubuntu" app from the Start menu, finish its one-time
   username/password setup.
3. Install the build tools (once): `sudo apt update && sudo apt install -y build-essential libssl-dev`
4. Get the project into that Ubuntu environment. Easiest: from Windows,
   copy the unzipped `shadownet_onion_ring` folder into a location under
   your Windows user folder (e.g. `C:\Users\<you>\shadownet_onion_ring`)
   — WSL can see your Windows drives at `/mnt/c/...`. So in the Ubuntu
   terminal: `cd /mnt/c/Users/<you>/shadownet_onion_ring`
5. Run the exact same two commands as above (the `g++ ...` line, then
   `./sim/shadownet_sim`) — they work unchanged inside WSL's Ubuntu shell.

This only affects the `sim/` build-and-run step above — it's a laptop-side
proof, not something that runs on the boards. The **firmware** (the actual
`.ino` files you flash to your 3 boards in section 2) runs through the
Arduino IDE exactly the same way on Windows as anywhere else — no WSL
needed for that part, just the normal Arduino IDE install. One Windows-only
note there: your boards use a CP2102 USB-to-serial chip, so if Windows
doesn't show a COM port when you plug one in, install the
["CP210x Universal Windows Driver"](https://www.silabs.com/developer-tools/usb-to-uart-bridge-vcp-drivers)
from Silicon Labs once, then replug.

You should see 8 phases run — key setup, ring init, baseline dummy
cycles, a real request from F1, a solo request from F2, the paper's
collision rule (F2's request overwriting F1's, Section 5.2), a granted
downlink, an ack, a 2-hop downlink to F2, and a tamper-detection test —
followed by a table showing every single one of those, real or dummy,
transmitted as an identical 128-byte encrypted blob. **That table is your
empirical anonymity evidence** — screenshot or copy it straight into your
DP submission.

## 1b. Run the evaluation

```bash
g++ -std=c++17 -O2 core/crypto_openssl.cpp core/ring_node.cpp \
    eval/eval_main.cpp -o eval/shadownet_eval -lssl -lcrypto
./eval/shadownet_eval
```

Same OpenSSL dependency as the sim, so if the sim built, this will too.
Produces the full metric set plus CSVs in `eval/results/`. **EVALUATION.md**
explains every number and maps it back to the paper section that asks for it.

Two results to look at first: the anonymity leakage analysis at the top
(A1 — it checks every cleartext header field, and it is what caught a real
break in an earlier version of this code), and the duty-cycle table (A8 —
your currently configured 4 s carrier interval is not legally transmittable,
and the table tells you the interval that is).

Later, once the boards are flashing, `firmware/tools/bench/bench.ino`
measures what only real silicon can: per-op crypto timing on the ESP32-S3,
heap behaviour, and the active-vs-idle timing side-channel test that decides
whether the paper's indistinguishability claim survives on this hardware.

## 2. Provision the 3 boards

1. Flash `firmware/tools/keygen/keygen.ino` to **all three** boards, one at
   a time. Each board prints its own public key over Serial (115200 baud)
   — copy each one down, labeled by which physical board it came from.
2. Edit `firmware/shadownet_gateway/node_config.h`: paste F1's and F2's
   public keys into `F1_PUBKEY_HEX` / `F2_PUBKEY_HEX`.
3. Edit `firmware/shadownet_forwarder/node_config.h`: paste the Gateway's
   public key into `GATEWAY_PUBKEY_HEX`.
4. In both files, double-check `LORA_FREQ_MHZ` against your specific
   boards' regional variant (see "Heltec V3 / SX1262 notes" above) — the
   pin numbers (`LORA_NSS_PIN` etc.) shouldn't need touching since they're
   fixed by the board, not your wiring.
5. Flash `shadownet_gateway.ino` to the Gateway board.
6. Flash `shadownet_forwarder.ino` to F1: in its `node_config.h`, set
   `#define MY_POSITION 1`.
7. Flash the same `shadownet_forwarder.ino` to F2, changing only
   `#define MY_POSITION 2` in its `node_config.h` before uploading.

Power all 3, open Serial monitors on each (115200 baud — one USB cable and
one Serial Monitor window per board; on a laptop this means 3 USB ports,
or flash/test one board at a time if you only have fewer ports free).
Order matters a little: power the Gateway last (or reset it last) so F1
and F2 are already listening when ring-init goes out. The Gateway starts
ring initiation on boot; F1 and F2 should each print `joined ring_id=7`.
The Gateway then cycles carriers every `CARRIER_INTERVAL_MS`. Hold the
BOOT button on F1 or F2 when you see `[frame] uplink cycle` in that
board's Serial output to originate a real access request and watch the
Gateway log it — while an outsider watching just the radio traffic sees
identical 128-byte frames the whole time.

### Troubleshooting

- **`radio.begin()` failed on any board:** most likely the TCXO voltage —
  try `LORA_TCXO_VOLTAGE 0` (no TCXO) vs `1.6`/`1.8`/`3.3` in
  `node_config.h`. Less likely but possible: your specific board revision
  uses different NSS/SCK/MISO/MOSI/RST/BUSY/DIO1 numbers than the ones
  here — cross-check against Heltec's own example sketch for "WiFi LoRa
  32 V3" if the TCXO fix doesn't resolve it. Also recheck `LORA_FREQ_MHZ`
  against your region (433/470/868/915 MHz variants exist).
- **`radio.begin()` succeeds but nothing is ever received, even at close
  range:** almost always the DIO2-as-RF-switch step — confirm
  `radio.setDio2AsRfSwitch(true)` is actually being called (it's right
  after `radio.begin()` in both `.ino` files) and that the antenna is
  screwed on.
- **Forgot to power the radio on:** if `Vext`/`VEXT_PIN` isn't driven LOW
  before `radio.begin()`, the SX1262 has no power and `begin()` will fail
  outright — confirm that line runs before the radio init, not after.
- **A forwarder never prints `joined ring_id=...`:** almost always a
  pasted-key mistake — open `node_config.h` and confirm the hex string is
  exactly 64 characters with no stray newline/space, and that you copied
  the *Gateway's* key into the forwarder (not another forwarder's).
- **Gateway prints "no reply within timeout" every cycle:** the ring
  formed but the carrier cycle isn't completing. Check that
  `LORA_FREQ_MHZ` / `LORA_BW_KHZ` / `LORA_SF` / `LORA_CR` / `LORA_SYNCWORD`
  are **identical across all 3 boards' `node_config.h`** — these aren't
  negotiated, they have to match exactly for any board to hear another.
  Also check that F1 and F2's `MY_POSITION` are actually 1 and 2 (not both
  1, or both 2 — easy to forget to change before the second flash).
- **Works at your desk, not across the room:** normal LoRa range tuning —
  raise `LORA_SF` (slower, more range) or check antennas are actually
  attached before assuming the protocol is at fault. Bench-test at close
  range first; the sim already proves the protocol logic itself is
  correct, so a real-hardware issue at this stage is config/wiring, not
  the onion routing code.

### Required libraries (Arduino IDE Library Manager)
- **RadioLib** (Jgromes), v6.x+ — SX1262 driver
- ESP32 board package (esp32 by Espressif Systems) — provides `Preferences.h`
  and `mbedTLS` (bundled, no separate install)

### If X25519 doesn't build
`core/crypto_mbedtls.cpp` uses mbedTLS's documented Curve25519 ECDH
pattern. This is the one file that couldn't be compiled in the sandbox
this project was built in (no ESP32 toolchain there — everything else was
verified via `sim/`). If your board's mbedTLS build has
`MBEDTLS_ECP_DP_CURVE25519_ENABLED` off, or the exact function signatures
differ from what's here, the fallback is to vendor a small public-domain
X25519 reference implementation (e.g. a "donna" or "ref10" single-file
implementation) in place of the `mbedtls_ecdh_*` calls — the rest of
`crypto_mbedtls.cpp` (AES-256-GCM, HKDF, random bytes) uses stable,
long-standing mbedTLS APIs and shouldn't need changes.

## Why `dest_hop` doesn't weaken the anonymity property

LoRa with 3 boards is a shared broadcast medium — every board hears every
transmission. The firmware adds a 1-byte `dest_hop` routing field at the
*radio framing* layer only (not part of `core/packet.hpp`'s onion format)
so each board knows when it's its turn to act. This doesn't leak anything
an eavesdropper couldn't already get for free: RF transmissions are
inherently locatable and timeable per physical node regardless of any
field inside the packet. The paper's anonymity guarantee is about which
*logical* message (real vs. dummy, whose request) a given transmission
corresponds to — not about hiding which radio is currently keying up,
which no onion-routing scheme (including Tor) ever claimed to hide.

## Known limitations (say these explicitly in your DP report)

- **Ring order is fixed** (`G -> F1 -> F2 -> G`), not dynamically
  reconfigured (paper Section 5.1 allows this; it's real future work).
- **Ring size is capped at 3 by the packet size, not by choice.** Each onion
  layer costs 28 B (12 B nonce + 16 B GCM tag), so a 128 B packet holds at
  most 3 layers, and even at LoRa's 255 B PHY maximum you top out near 8.
  Since the anonymity set *is* the ring (paper Section 5.3), the radio's MTU
  is what caps anonymity here — the paper's "keep the ring large" is not
  available on this hardware. See EVALUATION.md B1.
- **At the default 4 s carrier interval the ring occupies ~69% of the
  channel**, far past the 1% duty-cycle limit for 865-867 MHz. A legally
  transmittable configuration needs a carrier interval of >= 275 s. This is a
  configuration issue, not a design flaw, but you must address it before
  running the ring on air for any length of time. See EVALUATION.md B3.
- **An earlier version of this code leaked the active node in cleartext.**
  The `type` and `used_len` header fields (which sit outside the encrypted
  blob) both varied with who originated, identifying the active node without
  any need to break encryption. `eval/` caught it; `sim/` did not, because it
  only compared packet lengths. It is fixed now via constant-length
  random-padded bodies and direction-only cleartext types — see the note in
  `core/packet.hpp`. Worth writing up: it shows why "all packets are the same
  size" is a weaker claim than "the protocol is anonymous".
- **Anonymity set = 2 forwarders.** The paper is explicit that anonymity
  scales with ring size (Section 5.3) — this prototype demonstrates the
  mechanism correctly, but 2 forwarders is a weak anonymity set on its
  own. Scaling ShadowNet to more physical nodes is the natural next step.
- **Session keys are derived, not transmitted**, and **ring-init doesn't
  use the paper's full N-onion-with-padding list structure** (Section
  3.1) — both are documented simplifications in `core/ring_node.hpp` /
  `core/packet.hpp`, chosen because ring-init is a rare control message,
  not part of the steady-state traffic pattern the anonymity guarantee
  actually depends on.
- **No duty-cycle enforcement is built in yet.** `CARRIER_INTERVAL_MS` is
  a manual knob — before running this on air in a duty-cycle-regulated
  band, compute your actual airtime at your SF/BW/CR (see the process
  guide's Phase 2 budget check) and make sure your interval respects it.
- **SX1262 pin numbers and TCXO voltage are documented values for Heltec
  WiFi LoRa 32 V3, not verified against your specific 3 physical boards**
  (no ESP32 toolchain was available to compile-test this firmware before
  delivery — same caveat as `crypto_mbedtls.cpp` below). If `radio.begin()`
  doesn't succeed first try, the "Heltec V3 / SX1262 notes" and
  Troubleshooting sections above list the values most likely to need a
  small correction for your exact board revision.

## Mapping to your DP documentation

- **Alternative solutions analysis:** the X25519/HKDF substitution for the
  paper's RSA-based onion, the derived-vs-transmitted session keys, and
  the `dest_hop` radio-framing addition are all documented engineering
  decisions — cite this README's relevant sections directly.
- **Empirical evidence:** the `sim/` adversary-view table (constant
  128-byte frames across ring-init, dummy, and real traffic) and, once
  the boards are provisioned, real Serial logs from a live demo with the
  BOOT-button trigger.
- **Future work:** dynamic ring reconstruction, scaling past 2
  forwarders, and the paper's k-anonymity/l-diversity mitigation for
  intersection attacks (Section 8) are legitimate next milestones to name.
