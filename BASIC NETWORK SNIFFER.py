import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap
from datetime import datetime
import threading

SUSPICIOUS_PORTS = [21, 22, 23, 25, 3389, 4444]
packet_count = 0
captured_packets = []
sniffing = False

# ================= GUI =================
root = tk.Tk()
root.title("Advanced Network Sniffer | Mini IDS")
root.geometry("950x550")
root.configure(bg="#0f172a")

title = tk.Label(
    root,
    text="ADVANCED NETWORK SNIFFER + MINI IDS",
    fg="#22c55e",
    bg="#0f172a",
    font=("Consolas", 18, "bold")
)
title.pack(pady=10)

output = scrolledtext.ScrolledText(
    root,
    width=115,
    height=25,
    bg="#020617",
    fg="#e5e7eb",
    font=("Consolas", 10)
)
output.pack(padx=10)

# ===== COLORS (10+) =====
tags = {
    "ip": "#38bdf8",
    "tcp": "#22c55e",
    "udp": "#eab308",
    "icmp": "#a855f7",
    "http": "#f97316",
    "alert": "#ef4444",
    "payload": "#94a3b8",
    "count": "#10b981",
    "time": "#facc15",
    "footer": "#ec4899"
}
for tag, color in tags.items():
    output.tag_config(tag, foreground=color)

# ================= PACKET ANALYSIS =================
def analyze_packet(packet):
    global packet_count
    if not sniffing:
        return

    packet_count += 1
    captured_packets.append(packet)

    if IP in packet:
        output.insert(tk.END, f"\n[{datetime.now()}]\n", "time")
        output.insert(tk.END, f"Packet Count: {packet_count}\n", "count")
        output.insert(tk.END,
            f"Source: {packet[IP].src} → Destination: {packet[IP].dst}\n", "ip")

        if TCP in packet:
            sport, dport = packet[TCP].sport, packet[TCP].dport
            output.insert(tk.END,
                f"Protocol: TCP | {sport} → {dport}\n", "tcp")

            if sport == 80 or dport == 80:
                output.insert(tk.END, "HTTP Traffic Detected\n", "http")

            if sport in SUSPICIOUS_PORTS or dport in SUSPICIOUS_PORTS:
                output.insert(tk.END,
                    "⚠ ALERT: Suspicious Port Activity\n", "alert")

        elif UDP in packet:
            output.insert(tk.END, "Protocol: UDP\n", "udp")

        elif ICMP in packet:
            output.insert(tk.END, "Protocol: ICMP\n", "icmp")

        if Raw in packet:
            output.insert(tk.END,
                f"Payload: {packet[Raw].load[:40]}\n", "payload")

        output.see(tk.END)

# ================= THREAD =================
def sniff_thread():
    sniff(prn=analyze_packet, store=False)

def start_sniffing():
    global sniffing
    sniffing = True
    output.insert(tk.END, "\nSniffing Started...\n", "tcp")
    t = threading.Thread(target=sniff_thread, daemon=True)
    t.start()

def stop_sniffing():
    global sniffing
    sniffing = False
    output.insert(tk.END, "\nSniffing Stopped.\n", "alert")

def save_pcap():
    wrpcap("captured_traffic.pcap", captured_packets)
    output.insert(tk.END,
        "\nSaved as captured_traffic.pcap\n", "http")

# ================= BUTTONS =================
btn_frame = tk.Frame(root, bg="#0f172a")
btn_frame.pack(pady=10)

tk.Button(
    btn_frame, text="START",
    command=start_sniffing,
    bg="#16a34a", fg="white",
    font=("Consolas", 11, "bold")
).pack(side=tk.LEFT, padx=10)

tk.Button(
    btn_frame, text="STOP",
    command=stop_sniffing,
    bg="#dc2626", fg="white",
    font=("Consolas", 11, "bold")
).pack(side=tk.LEFT, padx=10)

tk.Button(
    btn_frame, text="SAVE PCAP",
    command=save_pcap,
    bg="#2563eb", fg="white",
    font=("Consolas", 11, "bold")
).pack(side=tk.LEFT, padx=10)

# ================= FOOTER =================
footer = tk.Label(
    root,
    text="Follow On Instagram :- codewithiitian",
    fg="#ec4899",
    bg="#0f172a",
    font=("Consolas", 11, "bold")
)
footer.pack(pady=5)

root.mainloop()
