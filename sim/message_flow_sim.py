#!/usr/bin/env python3
"""
ShadowNet — message-flow simulation graphs.

Models how a message typed into the dashboard actually travels the
G -> F1 -> F2 -> G onion ring, using the numbers from this repo:

  * core/packet.hpp     : 128 B wire packet, 6 B cleartext header,
                          19 B ControlMsg, +28 B per AES-GCM layer,
                          every body padded to ONION_BODY_LEN = 75 B
  * core/ring_node.cpp  : F1 always replaces the carrier body; a later
                          node that originates erases what it received
                          (paper Sec 5.2 collision rule)
  * firmware node_config: SF7 / BW125 / CR4/7, 129 B radio frame,
                          CARRIER_INTERVAL_MS = 4000
  * forwarder .ino      : one pending-message slot per node (a newer
                          message overwrites a queued one), sent once,
                          no retry, truncated to 16 bytes

Assumptions that are NOT in the code (change below if you measure them):
  * TURNAROUND_S  : radio RX->TX + crypto time per hop
  * PDR           : per-link packet delivery ratio

Run:  python3 sim/message_flow_sim.py      -> PNGs in sim/graphs/
"""
import math
import os
import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, Rectangle

# ---------------------------------------------------------------- constants
WIRE_PACKET = 128
HEADER = 6
CIPHER_AREA = WIRE_PACKET - HEADER
CONTROL_MSG = 19
LAYER_OVERHEAD = 12 + 16           # nonce + GCM tag
RING_SIZE = 2
ONION_BODY = CONTROL_MSG + RING_SIZE * LAYER_OVERHEAD   # 75
FRAME_BYTES = 129
CARRIER_INTERVAL_S = 4.0
TURNAROUND_S = 0.010                # assumption
PDR = 0.95                          # assumption for the Monte Carlo


def lora_airtime_s(payload, sf=7, bw=125e3, cr_denom=7, preamble=8, crc=True):
    """Semtech SX126x time-on-air (same formula as eval/lora_model.hpp)."""
    tsym = (2 ** sf) / bw
    de = 1 if tsym > 0.016 else 0
    cr = cr_denom - 4
    numer = 8 * payload - 4 * sf + 28 + 16 * (1 if crc else 0)
    n = math.ceil(numer / (4 * (sf - 2 * de))) * (cr + 4)
    return (preamble + 4.25) * tsym + (8 + max(n, 0)) * tsym


AIR = lora_airtime_s(FRAME_BYTES)    # ~0.293 s at SF7
HOP = AIR + TURNAROUND_S

# ---------------------------------------------------------------- styling
SURF = "#fcfcfb"
INK = "#0b0b0b"
INK2 = "#52514e"
MUTED = "#8a8985"
GRID = "#e6e5e1"
C_F1 = "#2a78d6"      # series 1 — F1's messages
C_F2 = "#eb6834"      # series 2 — F2's messages
C_GW = "#1baf7a"      # series 3 — gateway / downlink
C_DUMMY = "#c9c8c3"   # dummy / carrier traffic
C_LOST = "#e34948"    # dropped

plt.rcParams.update({
    "font.family": ["Inter", "DejaVu Sans"],
    "font.size": 10,
    "axes.facecolor": SURF,
    "figure.facecolor": SURF,
    "axes.edgecolor": GRID,
    "axes.labelcolor": INK2,
    "xtick.color": INK2,
    "ytick.color": INK2,
    "axes.titlecolor": INK,
    "axes.titlesize": 12,
    "axes.titleweight": "semibold",
    "axes.titlelocation": "left",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": False,
})

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "graphs")
os.makedirs(OUT, exist_ok=True)


def save(fig, name):
    path = os.path.join(OUT, name)
    fig.savefig(path, dpi=170, bbox_inches="tight")
    plt.close(fig)
    print("wrote", path)


def footnote(fig, text, y=-0.01):
    fig.text(0.01, y, text, ha="left", va="top", fontsize=8, color=MUTED)


# =========================================================== 1. one message
def graph_message_journey():
    """Sequence diagram: phone -> BLE -> F1 queue -> next carrier lap -> Gateway."""
    lanes = {"Phone (BLE)": 4, "F1": 3, "F2": 2, "Gateway": 1}
    fig, ax = plt.subplots(figsize=(12, 5.2))

    for name, y in lanes.items():
        ax.axhline(y, color=GRID, lw=1, zorder=0)
        ax.text(-0.25, y, name, ha="right", va="center", color=INK, fontsize=10,
                fontweight="semibold")

    def hop(t0, a, b, color, label=None, lw=2):
        t1 = t0 + AIR
        ax.add_patch(Rectangle((t0, lanes[a] - 0.07), AIR, 0.14, color=color,
                               lw=0, zorder=3))
        arr = FancyArrowPatch((t0, lanes[a]), (t1, lanes[b]),
                              arrowstyle="-|>", mutation_scale=11, color=color,
                              lw=lw, zorder=4, shrinkA=0, shrinkB=0)
        ax.add_patch(arr)
        if label:
            if a == "Gateway":
                ax.text(t0 + AIR * 0.25 + 0.06, 1.3, label, fontsize=8, color=INK2,
                        va="center", ha="left")
            else:
                ax.text((t0 + t1) / 2 + 0.06, (lanes[a] + lanes[b]) / 2, label,
                        fontsize=8, color=INK2, va="center", ha="left")
        return t0 + HOP

    def lap(t0, f1_col, f2_col, l1=None, l2=None, l3=None):
        t = hop(t0, "Gateway", "F1", C_DUMMY, l1)
        t = hop(t, "F1", "F2", f1_col, l2)
        t = hop(t, "F2", "Gateway", f2_col, l3)
        return t

    # cycle 0 — idle
    lap(0.0, C_DUMMY, C_DUMMY, "carrier", "dummy", "dummy")
    # phone writes at t = 1.3 s
    t_msg = 1.3
    ax.annotate("", xy=(t_msg + 0.05, lanes["F1"]), xytext=(t_msg, lanes["Phone (BLE)"]),
                arrowprops=dict(arrowstyle="-|>", color=C_F1, lw=2))
    ax.text(t_msg + 0.08, 3.55, 'you type "hello gw"\nBLE write (~ms)', fontsize=8.5,
            color=INK, va="center")
    # waiting in queue
    ax.add_patch(Rectangle((t_msg + 0.05, lanes["F1"] + 0.12), 4.0 - t_msg - 0.05, 0.08,
                           color=C_F1, alpha=0.25, lw=0))
    ax.text((t_msg + 4.0) / 2 - 0.2, lanes["F1"] - 0.22,
            f"queued in F1's one slot — waits {4.0 - t_msg:.1f} s",
            fontsize=8.5, color=INK2, ha="center")
    # cycle 1 — F1 originates
    t_end = lap(4.0, C_F1, C_F1, "carrier", "F1 msg, 1 layer", "F1 msg, 2 layers")
    ax.plot([t_end - TURNAROUND_S], [lanes["Gateway"]], "o", ms=9, color=C_F1,
            mec=SURF, mew=2, zorder=5)
    ax.text(t_end + 0.05, lanes["Gateway"] - 0.32,
            f"Gateway peels 2 layers → reads \"hello gw\"\n"
            f"end-to-end: {t_end - TURNAROUND_S - t_msg:.2f} s", fontsize=8.5, color=INK)
    # cycle 2 — F2's phone message
    t2 = 6.6
    ax.annotate("", xy=(t2 + 0.05, lanes["F2"]), xytext=(t2, lanes["Phone (BLE)"]),
                arrowprops=dict(arrowstyle="-|>", color=C_F2, lw=2))
    ax.text(t2 + 0.08, 3.55, "a 2nd phone writes to F2", fontsize=8.5, color=INK,
            va="center")
    ax.add_patch(Rectangle((t2 + 0.05, lanes["F2"] + 0.12), 8.0 + HOP - t2 - 0.05, 0.08,
                           color=C_F2, alpha=0.25, lw=0))
    t_end2 = lap(8.0, C_DUMMY, C_F2, "carrier", "dummy", "F2 msg (replaces dummy)")
    ax.plot([t_end2 - TURNAROUND_S], [lanes["Gateway"]], "o", ms=9, color=C_F2,
            mec=SURF, mew=2, zorder=5)

    for k in range(3):
        ax.axvline(k * CARRIER_INTERVAL_S, color=GRID, lw=1, ls=(0, (2, 3)), zorder=0)
        ax.text(k * CARRIER_INTERVAL_S + 0.03, 0.45, f"carrier #{k}", fontsize=8, color=MUTED)

    ax.set_xlim(-0.1, 11.5)
    ax.set_ylim(0.3, 4.4)
    ax.set_yticks([])
    ax.spines["left"].set_visible(False)
    ax.set_xlabel("time (s)")
    ax.set_title("How one message travels the ring  —  G → F1 → F2 → G")
    # legend
    from matplotlib.lines import Line2D
    handles = [Line2D([], [], color=c, lw=6) for c in (C_DUMMY, C_F1, C_F2)]
    ax.legend(handles, ["dummy / carrier", "F1's message", "F2's message"],
              loc="upper right", frameon=False, ncol=3, fontsize=9,
              bbox_to_anchor=(1.0, 1.08))
    footnote(fig, f"Each bar = one LoRa transmission of a {FRAME_BYTES} B frame at SF7/BW125/CR4/7 "
                  f"= {AIR*1000:.0f} ms on air, + {TURNAROUND_S*1000:.0f} ms assumed turnaround per hop. "
                  f"Gateway starts a lap every {CARRIER_INTERVAL_S:.0f} s.")
    save(fig, "01_message_journey.png")


# =========================================================== 2. packet anatomy
def graph_packet_anatomy():
    """Inside vs outside: what each hop carries, and what a sniffer sees."""
    pad_to_body = lambda real: ONION_BODY - real
    rows = []
    scen = [
        ("Idle cycle", C_DUMMY, C_DUMMY, "dummy", "dummy"),
        ("F1 sends", C_F1, C_F1, "F1 msg  [L1]", "F1 msg  [L1 ⊂ L2]"),
        ("F2 sends", C_DUMMY, C_F2, "dummy", "F2 msg  [L1 ⊂ L2]*"),
    ]
    for name, c12, c2g, l12, l2g in scen:
        rows.append((name, "G → F1", C_DUMMY, ONION_BODY, "random carrier body"))
        rows.append((name, "F1 → F2", c12, CONTROL_MSG + LAYER_OVERHEAD, l12))
        rows.append((name, "F2 → G", c2g, ONION_BODY, l2g))

    fig, ax = plt.subplots(figsize=(12, 6.2))
    y = 0
    yt, yl = [], []
    for i, (scn, hopname, col, real, lab) in enumerate(rows):
        if i and i % 3 == 0:
            y += 0.7
        x = 0
        segs = [(HEADER, "#52514e"), (real, col), (pad_to_body(real), "#e9e8e4"),
                (CIPHER_AREA - ONION_BODY, "#f3f2ef")]
        for w, c in segs:
            if w <= 0:
                continue
            ax.add_patch(Rectangle((x + 1, y - 0.36), w - 2, 0.72, color=c, lw=0))
            x += w
        ax.text(HEADER + real / 2, y, lab, ha="center", va="center", fontsize=8,
                color=INK if col == C_DUMMY else "white", fontweight="medium")
        ax.text(WIRE_PACKET + 2, y, "128 B · type=CARRIER · used_len=75" if hopname != "G → F1"
                else "128 B · type=CARRIER · used_len=75", fontsize=8, va="center", color=INK2)
        yt.append(y)
        yl.append(f"{scn}   {hopname}" if i % 3 == 0 else f"{hopname}")
        y += 1
    ax.set_yticks(yt)
    ax.set_yticklabels(yl, fontsize=9)
    ax.set_ylim(y - 0.4, -1.5)
    ax.set_xlim(0, 175)
    ax.set_xticks([0, HEADER, HEADER + 47, HEADER + ONION_BODY, WIRE_PACKET])
    ax.set_xlabel("byte offset in the 128 B wire packet")
    ax.spines["left"].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.text(WIRE_PACKET + 2, -0.8, "what a sniffer reads", fontsize=9, color=INK,
            fontweight="semibold")
    ax.set_title("Inside every hop: real onion bytes vs. padding — identical on the air")

    from matplotlib.patches import Patch
    handles = [Patch(color="#52514e"), Patch(color=C_F1), Patch(color=C_F2),
               Patch(color=C_DUMMY), Patch(color="#e9e8e4"), Patch(color="#f3f2ef")]
    ax.legend(handles, ["cleartext header (6 B)", "F1's onion", "F2's onion",
                        "dummy / carrier", "random padding → 75 B", "unused tail"],
              loc="upper center", bbox_to_anchor=(0.45, -0.12), ncol=6, frameon=False,
              fontsize=8.5)
    footnote(fig, "19 B ControlMsg + 28 B per AES-256-GCM layer (12 B nonce + 16 B tag): 1 layer = 47 B, "
                  "2 layers = 75 B. Every body is padded with random bytes to 75 B and the header always says "
                  "CARRIER/75,\nso the three scenarios are byte-for-byte the same shape to an eavesdropper. "
                  "*F2 discards the dummy it received and wraps its own message — the collision rule.", y=-0.07)
    save(fig, "02_packet_anatomy.png")


# =========================================================== Monte Carlo core
def simulate(n_cycles, rate_per_min, pdr, seed=1):
    """
    Cycle-accurate model of the firmware behaviour.
    Returns per-cycle records and per-message outcomes.
    """
    rng = np.random.default_rng(seed)
    lam = rate_per_min / 60.0 * CARRIER_INTERVAL_S   # mean arrivals per node per cycle
    pending = {1: None, 2: None}                     # arrival time of queued msg
    msgs = []                                        # dicts: node, t_in, outcome, latency
    cycles = []
    for k in range(n_cycles):
        t0 = k * CARRIER_INTERVAL_S
        # arrivals during the previous interval land before this lap starts
        for node in (1, 2):
            n = rng.poisson(lam)
            times = np.sort(rng.uniform(t0 - CARRIER_INTERVAL_S, t0, n)) if k else []
            for t in times:
                if pending[node] is not None:
                    pending[node]["outcome"] = "overwritten in queue"
                m = {"node": node, "t_in": t, "outcome": None, "latency": None}
                msgs.append(m)
                pending[node] = m
        rec = {"k": k, "hops": [None, None, None], "delivered": None, "erased": None}
        ok_g1 = rng.random() < pdr
        rec["hops"][0] = "carrier"
        if not ok_g1:
            rec["hops"][0] = "carrier-lost"
            cycles.append(rec)
            continue
        content = "dummy"
        f1_msg = None
        if pending[1] is not None:
            f1_msg, pending[1] = pending[1], None
            content = "F1"
        rec["hops"][1] = content
        if rng.random() >= pdr:
            rec["hops"][1] += "-lost"
            if f1_msg:
                f1_msg["outcome"] = "radio link loss"
            cycles.append(rec)
            continue
        f2_msg = None
        if pending[2] is not None:
            f2_msg, pending[2] = pending[2], None
            if f1_msg:
                f1_msg["outcome"] = "erased by F2 (collision)"
                rec["erased"] = "F1"
                f1_msg = None
            content = "F2"
        rec["hops"][2] = content
        if rng.random() >= pdr:
            rec["hops"][2] += "-lost"
            for m in (f1_msg, f2_msg):
                if m:
                    m["outcome"] = "radio link loss"
            cycles.append(rec)
            continue
        t_rx = t0 + 3 * HOP - TURNAROUND_S
        for m in (f1_msg, f2_msg):
            if m:
                m["outcome"] = "delivered"
                m["latency"] = t_rx - m["t_in"]
        rec["delivered"] = content
        cycles.append(rec)
    for m in msgs:
        if m["outcome"] is None:
            m["outcome"] = "still queued at end"
    return cycles, msgs


# =========================================================== 3. ring timeline
def graph_ring_timeline():
    cycles, msgs = simulate(n_cycles=30, rate_per_min=4, pdr=PDR, seed=7)
    fig, (ax, ax2) = plt.subplots(2, 1, figsize=(12, 5.6), sharex=True,
                                  gridspec_kw={"height_ratios": [3, 1.1], "hspace": 0.35})
    hop_names = ["G → F1", "F1 → F2", "F2 → G"]
    cmap = {"carrier": C_DUMMY, "dummy": C_DUMMY, "F1": C_F1, "F2": C_F2}
    for rec in cycles:
        t0 = rec["k"] * CARRIER_INTERVAL_S
        for h, val in enumerate(rec["hops"]):
            if val is None:
                continue
            lost = val.endswith("-lost")
            base = val.replace("-lost", "")
            x = t0 + h * HOP
            ax.add_patch(Rectangle((x, 2 - h - 0.32), AIR * 3.2, 0.64,
                                   color=cmap[base], lw=0))
            if lost:
                ax.plot(x + AIR * 3.2 + 0.25, 2 - h, marker="x", color=C_LOST, ms=8, mew=2)
            # sniffer view — every transmission is the same grey block
            ax2.add_patch(Rectangle((x, -0.3), AIR * 3.2, 0.6, color="#8a8985", lw=0))
        if rec["erased"]:
            ax.text(t0 + 2 * HOP + AIR * 1.6, -0.62, "F1 erased", fontsize=7.5,
                    color=C_LOST, ha="center")
    for m in msgs:
        col = C_F1 if m["node"] == 1 else C_F2
        y = 1 if m["node"] == 1 else 0
        ax.plot(m["t_in"], 2.62, marker="v", color=col, ms=7, mec=SURF, mew=1)
    ax.set_yticks([2, 1, 0])
    ax.set_yticklabels(hop_names)
    ax.set_ylim(-0.85, 2.85)
    ax.tick_params(axis="y", length=0)
    ax.spines["left"].set_visible(False)
    ax.set_title("2 minutes of ring traffic — what's really inside each transmission", pad=22)
    ax.text(0, 2.78, "▼ phone message arrives over BLE", fontsize=8, color=INK2, va="bottom")

    ax2.set_yticks([0])
    ax2.set_yticklabels(["all hops"])
    ax2.set_ylim(-0.6, 0.6)
    ax2.tick_params(axis="y", length=0)
    ax2.spines["left"].set_visible(False)
    ax2.set_title("…and what an SDR eavesdropper sees: the same 128 B CARRIER frame, every time",
                  fontsize=11)
    ax2.set_xlabel("time (s)")
    ax2.set_xlim(-1, 30 * CARRIER_INTERVAL_S + 1)

    from matplotlib.patches import Patch
    from matplotlib.lines import Line2D
    handles = [Patch(color=C_DUMMY), Patch(color=C_F1), Patch(color=C_F2),
               Line2D([], [], marker="x", color=C_LOST, ls="", mew=2)]
    fig.legend(handles, ["dummy / carrier", "carries F1's message", "carries F2's message",
                         "frame lost on the radio"], loc="upper center", ncol=4,
               frameon=False, fontsize=8.5, bbox_to_anchor=(0.5, 0.0))
    footnote(fig, f"Simulated: 4 messages/min per node (Poisson), {int(PDR*100)}% per-link delivery, "
                  f"lap every {CARRIER_INTERVAL_S:.0f} s. Block widths exaggerated 3.2× so they're visible "
                  f"(real airtime {AIR*1000:.0f} ms).", y=-0.07)
    save(fig, "03_ring_timeline.png")


# =========================================================== 4. reliability
def graph_reliability():
    rates = [0.5, 1, 2, 4, 8, 15]
    causes = ["delivered", "overwritten in queue", "erased by F2 (collision)", "radio link loss"]
    colors = [C_GW, "#eda100", C_LOST, "#6250d6"]
    fig, axes = plt.subplots(1, 3, figsize=(13.5, 4.6),
                             gridspec_kw={"width_ratios": [1, 1, 1.15], "wspace": 0.32})
    for ax, node, title in ((axes[0], 1, "Messages sent from F1"),
                            (axes[1], 2, "Messages sent from F2")):
        bottoms = np.zeros(len(rates))
        for cause, col in zip(causes, colors):
            vals = []
            for r in rates:
                _, msgs = simulate(4000, r, PDR, seed=11)
                mm = [m for m in msgs if m["node"] == node and m["outcome"] != "still queued at end"]
                vals.append(100 * sum(m["outcome"] == cause for m in mm) / max(len(mm), 1))
            vals = np.array(vals)
            ax.bar(range(len(rates)), vals, bottom=bottoms, color=col, width=0.62,
                   edgecolor=SURF, linewidth=2, label=cause)
            if cause == "delivered":
                for i, v in enumerate(vals):
                    ax.text(i, v - 3, f"{v:.0f}%", ha="center", va="top", fontsize=8,
                            color="white", fontweight="semibold")
            bottoms += vals
        ax.set_xticks(range(len(rates)))
        ax.set_xticklabels([str(r) for r in rates])
        ax.set_xlabel("messages per minute, per node")
        ax.set_ylim(0, 100)
        ax.set_ylabel("% of messages")
        ax.set_title(title)
        ax.yaxis.grid(True, color=GRID, lw=0.8)
        ax.set_axisbelow(True)
    axes[0].legend(loc="upper center", bbox_to_anchor=(1.1, -0.16), ncol=4, frameon=False,
                   fontsize=8.5)

    # latency distribution at light load
    ax = axes[2]
    _, msgs = simulate(20000, 1, PDR, seed=3)
    lat = np.array([m["latency"] for m in msgs if m["latency"] is not None])
    ax.hist(lat, bins=np.arange(0, 12.5, 0.25), color=C_F1, edgecolor=SURF, linewidth=1)
    med = np.median(lat)
    p95 = np.percentile(lat, 95)
    for v, lab in ((med, "median"), (p95, "p95")):
        ax.axvline(v, color=INK2, lw=1, ls=(0, (3, 2)))
        ax.text(v + 0.12, ax.get_ylim()[1] * 0.9, f"{lab}\n{v:.1f} s", fontsize=8, color=INK)
    ax.set_xlabel("phone → gateway latency (s)")
    ax.set_ylabel("messages")
    ax.set_title("Delivery latency (light load)")
    ax.yaxis.grid(True, color=GRID, lw=0.8)
    ax.set_axisbelow(True)
    footnote(fig, f"Monte Carlo, 4000–20000 cycles, {int(PDR*100)}% per-link delivery (assumed). "
                  "F1 loses messages when F2 talks in the same lap (collision rule) and both lose them when a "
                  "2nd message\narrives before the queued one is sent (single slot, no retry). Latency = wait "
                  f"for next carrier (0–4 s) + {3*HOP-TURNAROUND_S:.2f} s lap; the tail past 4 s is carriers lost on G→F1.", y=-0.1)
    save(fig, "04_reliability_latency.png")


if __name__ == "__main__":
    print(f"airtime per {FRAME_BYTES} B frame @SF7: {AIR*1000:.1f} ms; lap: {(3*HOP-TURNAROUND_S)*1000:.0f} ms")
    graph_message_journey()
    graph_packet_anatomy()
    graph_ring_timeline()
    graph_reliability()
