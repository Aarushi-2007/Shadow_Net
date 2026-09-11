# Evaluation — what to test, why, and how

Two groups of parameters. **Group A** is everything Wu & Li's paper says an
Onion Ring implementation should be evaluated on, with the section that says
it. **Group B** is what the paper does *not* cover, because two of its stated
assumptions are false on your hardware.

Run it:

```bash
g++ -std=c++17 -O2 core/crypto_openssl.cpp core/ring_node.cpp \
    eval/eval_main.cpp -o eval/shadownet_eval -lssl -lcrypto
./eval/shadownet_eval
```

CSVs land in `eval/results/` for plotting. The board-only measurements come
from `firmware/tools/bench/bench.ino` — flash it to one board, read Serial at
115200.

Every printed line is tagged so you always know what kind of claim it is:

| Tag | Meaning |
|---|---|
| `[MEASURED]` | Produced by running the real protocol/crypto code |
| `[SIMULATED]` | Monte-Carlo, with the closed-form value printed beside it to cross-check |
| `[MODELLED]` | Closed-form, from the LoRa datasheet or the paper's own model |

Keep these tags in your report. "We measured X" and "we modelled X" are
different claims, and an examiner will ask which one you mean.

---

## The evaluation found a real bug — lead with this

The first version of this implementation **leaked the identity of the active
node in cleartext**, and the evaluation harness is what caught it.

`sim/`'s adversary table checked that every packet was the same 128 bytes on
the wire, and it was. But packet length is not the only thing an eavesdropper
reads. The 6-byte header is *outside* the encrypted blob, and two of its
fields varied with who originated:

- **`type`** flipped from `CARRIER` (0x02) to `ACCESS_REQUEST` (0x03) at
  exactly the hop that originated.
- **`used_len`** was 75 B at the final hop if the last forwarder relayed, but
  47 B if it originated — because an originating node discards the body it
  received and wraps its own shorter message.

Either field alone identifies the active node with certainty, without
breaking any encryption. That is a total break of the one property the
protocol exists to provide.

**The fix** (now in `core/packet.hpp` and `core/ring_node.cpp`): every onion
body is padded to a constant `ONION_BODY_LEN` with *random* bytes (not zeros
— zero padding is itself a distinguisher), `used_len` always reports that
constant, and the cleartext `type` carries only the *direction* (uplink /
downlink / ring-init), never the semantic message type. The true type travels
inside the encrypted `ControlMsg`. Each forwarder still knows how many bytes
are real because its own ring position determines it; the Gateway, which
cannot know a priori who originated, recovers it by trial decryption over at
most `RING_SIZE` candidates, with the GCM auth tag making that unambiguous.

After the fix the harness reports all four header fields constant across all
four activity patterns, and degree of anonymity d = 1.0.

This is worth a section of its own in your report. It is a concrete
demonstration of why "the packets are all the same size" is not the same
claim as "the protocol is anonymous", and it is the kind of finding that only
comes from building the thing and testing it properly.

---

## Statistical security tests — is the model actually secure?

`eval/security_tests.cpp` is a separate, stronger battery. Where the
evaluation harness checks whether observable fields are *equal* across
activity patterns, this asks the question an attacker would actually ask:
**given a large sample of intercepted traffic, does any statistical test
distinguish "F1 active" from "F2 active" from "nobody active"?**

```bash
g++ -std=c++17 -O2 core/crypto_openssl.cpp core/ring_node.cpp \
    eval/security_tests.cpp -o eval/shadownet_sectest -lssl -lcrypto
./eval/shadownet_sectest
```

| Test | What it checks | Result |
|---|---|---|
| **T1** Ciphertext randomness | Shannon entropy, byte uniformity χ², monobit, runs, serial correlation over 300 KB of output | entropy 7.9994 / 8.0, all p > 0.4 |
| **T2** Padding vs real ciphertext | Whether the random padding added by the leak fix is distinguishable from genuine ciphertext — if it were, onion depth would be recoverable anyway | χ²=246.5, df=255, p=0.64 — indistinguishable |
| **T3** Activity indistinguishability | χ² homogeneity test at **every one of 128 byte positions** across all 4 activity classes, Bonferroni-corrected | 0 positions flagged |
| **T4** Nonce / ciphertext uniqueness | 50,000 packets: any repeated GCM nonce (catastrophic) or repeated ciphertext; plus identical-plaintext → distinct-ciphertext (IND-CPA) | 0 repeats, 1000/1000 distinct |
| **T5** Avalanche | 1-bit change in plaintext → auth tag bits; 1-bit change in key → ciphertext bits | ~48% and ~50% (ideal 50%) |
| **T6** Key separation | 3000 attempts by F1 to open F2's layer — a compromised node must not read its neighbour's | 0 successes |

### Why you can trust the T3 result

A test that always passes proves nothing, so the suite validates itself two
ways:

**Positive control** (built in): the pre-fix `type` leak is injected
synthetically and the χ² test fires at p < 0.000001.

**Negative control** (the strong one): `core/ring_node.cpp` has a
`SHADOWNET_VULNERABLE_DEMO` compile flag that reintroduces the *actual*
historical bug. Build with it and run the suite:

```bash
g++ -std=c++17 -O2 -DSHADOWNET_VULNERABLE_DEMO core/crypto_openssl.cpp \
    core/ring_node.cpp eval/security_tests.cpp -o /tmp/sectest_vuln -lssl -lcrypto
/tmp/sectest_vuln
```

It reports `*** LEAK DETECTED ***` and flags **byte 3** — which is exactly
the `type` field in the header. So the suite demonstrably has power against
the real vulnerability, not just a synthetic one. **Never define that flag
for firmware you actually flash.** Running both builds side by side is a
strong thing to show in a viva.

### Reading the p-values correctly

T3's raw minimum p-value bounces around between runs (roughly 0.002–0.06) at
a *different* byte position each time. That is expected, not a warning sign:
you are running 128 independent tests, so under the null hypothesis the
smallest of 128 uniform p-values is usually small. The Bonferroni correction
is what accounts for this, and it reports 0 flagged positions every run. If
a *specific* position kept coming up across runs, that would be a real leak.

### What passing does NOT mean

These are **necessary conditions, not sufficient ones.** Passing shows this
battery found no leak at this sample size — not that the protocol is secure.
Statistical testing can refute a security claim decisively but can only
support one provisionally. Not covered:

- **Timing** — a timing leak breaks anonymity just as completely, and none of
  these tests would see it. Covered separately (B6 / `bench.ino` TEST 4).
- **Power analysis** — an attacker with physical access reads current draw.
- **RF fingerprinting** — radios have hardware quirks that identify the
  transmitter regardless of protocol. No onion scheme, Tor included, claims
  to stop this.
- **Traffic analysis over time** — these tests treat packets independently.
  Correlations *across* cycles (intersection attacks, paper Sec 5.3) are a
  real threat this suite does not model.

The defensible claim:

> No statistical test in our battery distinguished the activity classes at
> n = 6000 samples per class (Bonferroni-corrected p > 0.01 across all 128
> byte positions).

That is falsifiable and specific. "Our protocol is secure" is neither.

---

## Group A — parameters the paper names

### A1. Anonymity set size and degree of anonymity
**Paper Sec 5.3:** *"The anonymity set for any active node in an Onion ring is
all the Mesh nodes in the ring."*

The paper states the set size but never quantifies anonymity itself. The
harness adds the standard information-theoretic metric (Serjantov & Danezis
2002; Díaz et al. 2002), which postdates the paper: d = H(X) / log₂(N), where
d = 1.0 means the adversary learns nothing.

It measures this properly — by running every activity pattern through the
real code and comparing **every cleartext field**, not just length. It also
checks the downlink direction, since receiver anonymity is the other half of
the property the paper claims (Sec 5.3).

Report both numbers: d = 1.0 sounds perfect, but with 2 forwarders a blind
guess is still right 50% of the time. Set size, not entropy, is the binding
constraint — see B1.

### A3. Throughput penalty vs a shortest-path route
**Paper Sec 5.4:** the ring's hop count vs a direct route, scaled by channel
efficiency (100% for the globally-scheduled ring vs ~60% for CSMA/CA), giving
throughput ratios of 5.9, 4.8 and 2.4 for its three geometric cases.

The harness reproduces the paper's own arithmetic first — it recomputes 5.92,
4.80 and 2.40, confirming the model is implemented correctly — then
re-derives it for LoRa.

**Finding:** the paper's 0.6 efficiency credit does not transfer. It rewards
the ring for avoiding CSMA contention, but LoRa has no CSMA to avoid, so on
your hardware the penalty is exactly the hop count (3×), not hop count × 0.6.
The paper's model is optimistic for this radio.

### A4 / A5 / A6. Access delay, collision probability, delay jitter
**Paper Sec 5.4:** *"it is rare that two Mesh nodes start sessions at the same
Mesh transmission cycle. Therefore, the probability of a request collision is
small ... The access delay caused by the request collision is not a
significant problem."*

The harness tests this instead of accepting it: a 200,000-trial Monte-Carlo
sweep over ring size and per-node activity rate, with the closed-form
P(collision) = 1 − (1−p)ᴺ − Np(1−p)ᴺ⁻¹ printed beside each simulated value.
They agree to three decimals, which validates both.

**Finding:** the claim holds for small rings and low activity — comfortably
so for your 2-forwarder ring — but not unconditionally. At N=16, p=0.25 the
collision probability exceeds 90%. State the condition.

On jitter: the paper is structurally right (a fixed carrier cadence means
near-zero jitter absent collisions), but the *floor* on latency is one
carrier interval, and at 4 s that rules out real-time services regardless of
how good the jitter is.

### A7 / A8. Communication overhead and carrier bandwidth
**Paper Sec 5.4:** *"Onion ring achieves Mesh node anonymity at the cost of
communication overhead"* and *"the bandwidth consumption for sending request
carriers can be ignored if the sending frequency is not too high."*

**Finding:** 24.2× overhead (387 bytes transmitted per 16 bytes of payload) —
that is the honest price of the anonymity property, quote it directly. And
the "can be ignored" claim is false here by two orders of magnitude: see the
duty-cycle result below, which is the most important practical finding in
this evaluation.

### A9 / A10. Intrusion detection and intruder identification
**Paper Sec 6**, including *"The probability of a false positive for the
intruder identification scheme depends on how aggressively the Gateway router
judges a node to be malicious."*

Tamper detection is measured directly: 2,000 single-bit flips into the
ciphertext, 100% caught. That is the expected result (GCM's forgery
probability is 2⁻¹²⁸), not luck — a single miss would mean a bug.

The false-positive sweep implements Sec 6's accusation scheme and sweeps the
threshold T. The attacker is always caught by construction, so the entire
design question is how many *honest* nodes get accused alongside it — which
is the tradeoff Sec 6 describes but never quantifies.

**Caveat to state plainly:** this scheme needs at least 3 forwarders to be
meaningful. It is not demonstrable on your 3-board setup; it needs a 4th
board. Say so rather than implying you tested it.

---

## Group B — what the paper omits, and why it matters here

Two of the paper's own assumptions fail on your hardware:

> **Sec 1:** *"The extra computing load caused by using cryptography is not a
> concern for Mesh networks because Mesh nodes are desktop or laptop computers
> with sufficient power supply and computing capability."*

> **Sec 6:** *"we have assumed a perfect link layer error control"*

Your nodes are 240 MHz microcontrollers on batteries, talking over a lossy
sub-GHz radio. Every metric below exists because one of those two assumptions
does not hold. This section is where your evaluation goes beyond reproducing
the paper — it is the part that is genuinely yours.

### B1. Onion depth ceiling vs radio MTU → maximum achievable anonymity
**The single most important structural finding.**

Anonymity set size equals ring size (Sec 5.3). Ring size is bounded by how
many onion layers fit in one packet. Each AES-GCM layer costs 12 B nonce +
16 B tag = 28 B. The harness measures this empirically with the real crypto
and verifies the full nest round-trips.

At your 128 B wire packet: **max 3 layers → max ring of 3 → best-case
adversary guess of 1 in 3.** Even at the 255 B LoRa PHY maximum it tops out
around 8.

So the paper's *"the ring size can be kept large to improve anonymity"*
(Sec 5.3) is simply **not available on LoRa**. That is a real limitation of
applying this protocol to this class of radio, and identifying it is a
contribution — present it as a finding, not as a shortcoming of your build.

### B2. Cryptographic cost on the actual MCU
Host figures are a baseline only. The real numbers come from `bench.ino`
(TEST 1 and TEST 2). Expect crypto to be roughly 100–1000× slower than on
x86 — and still utterly dwarfed by ~914 ms of LoRa time-on-air, meaning
crypto is *not* your bottleneck. Confirm that with the board's numbers before
claiming it.

### B3 / A8. Airtime and duty-cycle compliance — **the binding constraint**
Closed-form Semtech time-on-air formula, in `eval/lora_model.hpp`.

At SF9 / BW125 kHz / CR4-7, one 129-byte frame occupies the channel for
**914 ms**. A full 3-transmission ring cycle costs **2.74 s of airtime.**

At your currently configured 4 s carrier interval that is **69% channel
occupancy** — far outside the 1% duty-cycle limit for the 865–867 MHz band.
A legal configuration needs a carrier interval of **≥ 275 s**, which sets a
hard floor on access latency.

This is the finding with the most practical consequence, and it follows
directly from the paper's design meeting a radio the paper never considered.

### B4. Energy per cycle and battery life
The MCU-awake term dominates, not the radio — so the biggest available win is
deep sleep between carriers, not lowering TX power. But note the tension:
always-on receive is *required by the anonymity design* (every node must
appear to participate every cycle), so any sleep schedule has to be
synchronised rather than opportunistic. That tension is worth a paragraph.

### B5. Memory footprint
`GatewayNode` grows only 64 B per forwarder, so even a 32-node ring costs
~2 KB. Memory is **not** what limits ring size — the MTU ceiling in B1 is.
Worth stating explicitly, because "it won't fit in RAM" is the intuitive
wrong answer.

### B6. Timing side-channel — **the test that matters most**
The paper's central anonymity claim (Sec 5.3) is that an active node's
activity *"is indistinguishable from the activity for an inactive node."*
That argument is entirely about **ciphertext**. It says nothing about
**time**.

On an MCU an originating node runs a different code path than a relaying one.
If that path is measurably slower, an adversary with a timestamping SDR
identifies the active node without breaking any encryption — defeating the
protocol completely, exactly like the header leak did.

The host-side result is weak evidence at best (different CPU, different
caches, ~100× faster). **`bench.ino` TEST 4 on the real board is the decisive
measurement.** Do not claim timing indistinguishability in your report on the
host number alone.

Standard mitigation if a difference shows up: transmit on a fixed schedule (a
deadline timer) rather than as soon as processing finishes, so
receive-to-transmit latency is constant regardless of what happened in
between. Good future-work item either way.

### B7. Reliability under real packet loss
The paper assumes perfect link-layer error control. Real LoRa has none, and
this design has no retransmission — one lost packet kills the whole cycle, so
completion = PDR^(N+1).

At 90% per-link PDR: N=2 gives 72.9%, N=4 gives 59.0%, N=8 gives 38.7%.

This compounds with B1 in a way worth drawing out explicitly: **anonymity
wants a large ring, MTU caps it at ~3, and reliability punishes it
exponentially.** The sweet spot for a real deployment is small — a
defensible conclusion, and one you can support with your own numbers.

---

## Suggested structure for the report's evaluation chapter

1. **Method** — the three tags, the fixed RNG seed, what runs on host vs board.
2. **Reproducing the paper** — A3's recomputation of 5.9 / 4.8 / 2.4 shows
   your model matches theirs before you start changing things.
3. **Security properties** — A1 (with the header-leak bug and its fix as the
   centrepiece), A10.
4. **Performance** — A5, A7, A8, B3.
5. **What LoRa changes** — B1, B3, B7 as a group, framed as the paper's
   assumptions meeting a radio it was not written for.
6. **Open questions** — B6's board result, A9 needing a 4th node, dynamic
   ring reconstruction.

Two things to be careful about, because an examiner will probe them:
- Never present a `[MODELLED]` number as a measurement. The duty-cycle and
  energy figures are models; the anonymity, tamper-detection and depth-ceiling
  figures are measurements.
- The 2-forwarder ring is a demonstration of the mechanism, not a
  deployable anonymity system. Say that yourself before anyone says it to you.
