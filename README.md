# 🔥 Personal Firewall using Python

A lightweight, customizable personal firewall built in Python that filters network traffic based on user-defined rules. It uses `Scapy` for packet sniffing and offers optional system-level enforcement via `iptables` on Linux. A Tkinter GUI is also available for real-time monitoring.

---

## 📌 Features

- 🔍 **Packet Sniffing** with Scapy
- 🛡️ **Custom Rule-Based Filtering** (IP, Port, Protocol)
- 📄 **Suspicious Packet Logging**
- 🧱 **Optional `iptables` Rule Enforcement** (Linux only)
- 🖥️ **GUI Dashboard** using Tkinter (optional)

---

## 🛠️ Tools Used

- [Python 3](https://www.python.org/)
- [Scapy](https://scapy.net/)
- [iptables](https://linux.die.net/man/8/iptables)
- [Tkinter](https://docs.python.org/3/library/tkinter.html)

---

## 📁 Project Structure

```

personal\_firewall/
│
├── firewall.py           # Core firewall engine using scapy
├── rules.json            # Rule set: block IPs, ports, protocols
├── logger.py             # Packet logging system
├── iptables\_rules.sh     # Bash script for iptables enforcement
├── gui.py                # Optional GUI for live monitoring
└── README.md

````

---

## 🧰 Setup & Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/personal-firewall.git
cd personal-firewall
````

### 2. Install Dependencies

```bash
pip install scapy
```

> 🔐 **Note**: Root privileges are required for packet sniffing and iptables configuration.

---

## 🚀 Usage

### 🔹 Run the Firewall (CLI Mode)

```bash
sudo python3 firewall.py
```

### 🔹 Run the GUI Firewall (Optional)

```bash
sudo python3 gui.py
```

### 🔹 Apply System-Level Blocking with iptables

```bash
chmod +x iptables_rules.sh
sudo ./iptables_rules.sh
```

---

## 📄 Define Your Rules

Edit `rules.json` to define the filtering rules:

```json
{
  "block_ips": ["192.168.1.100"],
  "block_ports": [22, 445],
  "block_protocols": ["ICMP"]
}
```

---

## 📤 Output Examples

### ✅ Console Output

```
[*] Starting firewall...
[BLOCKED] TCP Port 22 is blocked
[ALLOWED] Packet: 10.0.0.2 -> 10.0.0.3
```

### 📂 Log File (`firewall_logs.txt`)

```
2025-06-12 15:25:44 | Blocked Port | IP / TCP 10.0.0.2:50234 > 10.0.0.3:22 S
```

---

## ⚠️ Disclaimer

This project is for **educational and research purposes only**. Do not use this firewall in production or critical environments without proper testing and validation.

---

## 🙌 Contributions

Pull requests are welcome! If you'd like to improve rule support, add new filters, or enhance the GUI, feel free to contribute.
you like me to also generate a `LICENSE`, `.gitignore`, or badge integrations for GitHub Actions / PyPI / Code Quality?
