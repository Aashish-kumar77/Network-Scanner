# 🌐 Network Security Scanner

A Python-based **network reconnaissance and risk analysis tool** that discovers devices on a local network, analyzes exposed services, and evaluates security risk based on open ports.

---

## 🧠 Overview

This tool performs automated network discovery and port scanning using **Nmap**, identifies active devices, and highlights potential security risks based on commonly exploited services (e.g., SMB, Telnet, RDP).

It provides a **graphical interface** for real-time monitoring and stores scan results for later analysis.

---

## 🚀 Features

* 🔍 **Network Discovery**

  * Detects all active devices on the local subnet
  * Retrieves IP address, MAC address, and hostname

* 🚪 **Port Scanning & Service Detection**

  * Scans for commonly exploited ports (FTP, SSH, SMB, RDP, etc.)
  * Identifies running services on each device

* ⚠️ **Risk Scoring Engine**

  * Assigns risk scores based on exposed ports
  * Highlights high-risk services (Telnet, SMB, RDP)

* 💾 **Persistent Storage**

  * Stores scan results in SQLite database
  * Tracks devices and previously detected vulnerabilities

* 🖥️ **GUI Interface (Tkinter)**

  * Interactive device list
  * Detailed inspection panel
  * Real-time scan progress

* ⚡ **Multithreaded Scanning**

  * Non-blocking UI during scans

---

## 🛠️ Tech Stack

* **Python**
* **Tkinter** (GUI)
* **Nmap** (network scanning)
* **SQLite** (data storage)

---

## ⚙️ Setup & Usage

### 1. Install Dependencies

```bash
sudo apt install nmap
pip install python-nmap
```

### 2. Run the Application

```bash
python Network_Scanner.py
```

> ⚠️ Run with administrator/root privileges for accurate scanning.

---

## 🎯 Use Cases

* 🛡️ Home / lab network security auditing
* 🕵️ Identifying unknown devices on a network
* 🔍 Detecting exposed or insecure services
* 🎓 Cybersecurity learning and experimentation

---

## ⚠️ Limitations

* Does not perform deep vulnerability scanning (port-based analysis only)
* Requires Nmap installed and proper permissions
* Limited to local network scanning

---

## 🚀 Future Improvements

* [ ] Vulnerability detection (CVE mapping)
* [ ] Real-time alerts for high-risk devices
* [ ] Integration with OSINT tools (IntelGraph)
* [ ] Export reports (PDF/JSON)
* [ ] Improved authentication (bcrypt + roles)

---

## 👨‍💻 Author

**Aashish Kumar**
