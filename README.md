# Basic Network Sniffer with Mini IDS (Python)

A Python-based **Network Packet Sniffer** with a graphical interface built using **Scapy** and **Tkinter**.  
This project captures live network traffic, analyzes packets in real time, detects suspicious activity, and allows exporting traffic to PCAP format.

---

## 🚀 Features

- Live packet sniffing
- Source & Destination IP analysis
- TCP / UDP / ICMP protocol detection
- HTTP traffic filtering
- Suspicious port detection (Mini IDS)
- Real-time packet counter
- Payload preview
- Save captured traffic as `.pcap`
- GUI with multi-color logs
- Threaded sniffing (no UI freeze)

---

## 🛠️ Technologies Used

- Python 3
- Scapy
- Tkinter
- Threading

---

## ⚠️ Requirements

- Python 3.x
- Scapy
- **Npcap (Windows)** with WinPcap compatibility enabled  
- Run with **Administrator / sudo privileges**

Install dependencies:
```bash
pip install -r requirements.txt
▶️ How to Run
python sniffer.py
Click START to begin sniffing
Click STOP to stop sniffing
Click SAVE PCAP to export captured traffic

🔐 Mini IDS Logic
The sniffer flags traffic on commonly abused ports such as:

21 (FTP)

22 (SSH)

23 (Telnet)

25 (SMTP)

3389 (RDP)

4444 (Backdoor)

📸 Screenshots



⚖️ Disclaimer
This tool is for educational and ethical use only.
Do not use it on networks you do not own or have permission to analyze.

📢 Follow
Follow On Instagram :- codewithiitian


---

## 4️⃣ `LICENSE`
Use MIT (standard, no headache):

```txt
MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
