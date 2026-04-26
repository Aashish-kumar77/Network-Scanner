import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import hashlib
import nmap
import ipaddress
import socket
import platform
import datetime
import sys
import traceback
import threading

RISKY_PORTS = {
    21: "FTP (File Transfer Protocol) - Often insecure, cleartext credentials",
    22: "SSH (Secure Shell) - Essential, but needs strong authentication and updates",
    23: "Telnet (Telnet) - Sends data in plain text, highly insecure, avoid use",
    25: "SMTP (Simple Mail Transfer Protocol) - Email server, can be exploited for spam/relay",
    53: "DNS (Domain Name System) - Essential, but can be targeted for amplification attacks",
    80: "HTTP (Hypertext Transfer Protocol) - Unencrypted web traffic, sensitive data exposed",
    110: "POP3 (Post Office Protocol 3) - Unencrypted email retrieval, sensitive data exposed",
    139: "NetBIOS Session Service - Vulnerable to enumeration and attacks (e.g., SMBGhost)",
    443: "HTTPS (Hypertext Protocol Secure) - Encrypted web, but can still have vulnerabilities in certificates or web app",
    445: "SMB (Server Message Block) - Common target for exploits (e.g., WannaCry, EternalBlue)",
    3389: "RDP (Remote Desktop Protocol) - Can be brute-forced, weak credentials a major risk",
    5900: "VNC (Virtual Network Computing) - Often insecure without proper configuration or strong passwords"
}

def create_user_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def create_scan_db():
    conn = sqlite3.connect('network_scan.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            mac_address TEXT,
            hostname TEXT,
            risk_score INTEGER,
            last_scanned TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS ports (
            device_id INTEGER,
            port_number INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            state TEXT,
            service TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
            UNIQUE (device_id, port_number, protocol)
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate_user(username, password):
    if not username or not password:
        return False
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password_hash=?", (username, hash_password(password)))
    user = c.fetchone()
    conn.close()
    return user is not None

def save_scan_results(device_data):
    conn = sqlite3.connect('network_scan.db')
    c = conn.cursor()
    for ip, data in device_data.items():
        mac = data.get('mac', 'N/A')
        hostname = data.get('hostname', 'N/A')
        risk_score = data.get('risk_score', 0)
        last_scanned = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute('''
            INSERT OR REPLACE INTO devices (ip_address, mac_address, hostname, risk_score, last_scanned)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip, mac, hostname, risk_score, last_scanned))
        c.execute('SELECT id FROM devices WHERE ip_address = ?', (ip,))
        device_id = c.fetchone()[0]
        c.execute('DELETE FROM ports WHERE device_id = ?', (device_id,))
        for port_info in data.get('open_ports', []):
            port_number = port_info['port']
            protocol = port_info['protocol']
            state = port_info['state']
            service = port_info['service']
            c.execute('''
                INSERT INTO ports (device_id, port_number, protocol, state, service)
                VALUES (?, ?, ?, ?, ?)
            ''', (device_id, port_number, protocol, state, service))
    conn.commit()
    conn.close()

def load_scan_results():
    conn = sqlite3.connect('network_scan.db')
    c = conn.cursor()
    c.execute('SELECT * FROM devices')
    devices = c.fetchall()
    results = {}
    for device_row in devices:
        device_id, ip_address, mac_address, hostname, risk_score, last_scanned = device_row
        c.execute('SELECT port_number, protocol, state, service FROM ports WHERE device_id = ?', (device_id,))
        ports = c.fetchall()
        open_ports_list = []
        for p_num, proto, state, service in ports:
            open_ports_list.append({
                'port': p_num,
                'protocol': proto,
                'state': state,
                'service': service
            })
        results[ip_address] = {
            'mac': mac_address,
            'hostname': hostname,
            'risk_score': risk_score,
            'last_scanned': last_scanned,
            'open_ports': open_ports_list
        }
    conn.close()
    return results

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def get_local_ip_and_subnet(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            return local_ip, str(network.network_address), str(network.prefixlen)
        except Exception as e:
            print(f"Could not determine local IP and subnet: {e}")
            messagebox.showwarning("Network Error", "Could not determine local IP address. Scanning '127.0.0.1/24' (localhost) as fallback.")
            return "127.0.0.1", "127.0.0.1", "24"

    def scan_network(self, target_ip_range, progress_callback=None):
        all_scanned_devices = {}
        ports_to_scan_str = ','.join(map(str, RISKY_PORTS.keys()))
        try:
            print(f"Stage 1: Discovering live hosts in {target_ip_range}...")
            self.nm.scan(hosts=target_ip_range, arguments='-sn -PE -PP -PU53,67,123,135 --host-timeout 5s')
            live_hosts = [host for host in self.nm.all_hosts() if self.nm[host].state() == 'up']
            print(f"Found {len(live_hosts)} live hosts: {live_hosts}")
            if not live_hosts:
                messagebox.showinfo("Scan Results", "No live hosts found in the specified network range.")
                return {}
            total_hosts = len(live_hosts)
            for idx, host in enumerate(live_hosts):
                print(f"\nProcessing host: {host}")
                current_host_data = {
                    'mac': 'N/A',
                    'hostname': 'N/A',
                    'open_ports': [],
                    'risk_score': 0
                }
                detailed_scan_arguments = f'-sS -O -p {ports_to_scan_str} -T4 --host-timeout 10s'
                try:
                    print(f"Running detailed scan on {host} with arguments: {detailed_scan_arguments}")
                    self.nm.scan(hosts=host, arguments=detailed_scan_arguments)
                    if host in self.nm.all_hosts():
                        host_info = self.nm[host]
                        if 'addresses' in host_info and 'mac' in host_info['addresses']:
                            current_host_data['mac'] = host_info['addresses']['mac']
                            print(f"Found MAC for {host}: {current_host_data['mac']}")
                        else:
                            print(f"No MAC found in Nmap scan results for {host} (likely not on local subnet or privilege issue).")
                        if 'hostnames' in host_info and host_info['hostnames']:
                            for hostname_entry in host_info['hostnames']:
                                if hostname_entry['name'] and hostname_entry['name'] != host:
                                    current_host_data['hostname'] = hostname_entry['name']
                                    print(f"Found hostname in Nmap scan for {host}: {current_host_data['hostname']}")
                                    break
                        if current_host_data['hostname'] == 'N/A' or current_host_data['hostname'] == host:
                            try:
                                hostname_from_dns, _, _ = socket.gethostbyaddr(host)
                                if hostname_from_dns and hostname_from_dns != host:
                                    current_host_data['hostname'] = hostname_from_dns.split('.')[0]
                                    print(f"Found hostname via reverse DNS for {host}: {current_host_data['hostname']}")
                            except (socket.herror, socket.gaierror):
                                print(f"Reverse DNS lookup failed for {host}")
                        if 'tcp' in host_info:
                            for port, port_data in host_info['tcp'].items():
                                if port_data['state'] == 'open':
                                    current_host_data['open_ports'].append({
                                        'port': port,
                                        'protocol': 'tcp',
                                        'state': 'open',
                                        'service': port_data.get('name', 'N/A')
                                    })
                            current_host_data['risk_score'] = self.calculate_risk_score(current_host_data['open_ports'])
                        else:
                            print(f"No open TCP ports found on {host}")
                except nmap.PortScannerError as e:
                    print(f"Detailed scan failed for {host}: {e}")
                    continue
                except Exception as e:
                    print(f"An unexpected error occurred during detailed scan for {host}: {e}")
                    traceback.print_exc()
                    continue
                all_scanned_devices[host] = current_host_data
                print(f"Completed scan for {host}")
                if progress_callback:
                    progress_callback(idx + 1, total_hosts)
        except nmap.PortScannerError as e:
            messagebox.showerror("Nmap Error", 
                                f"Nmap scan failed. Ensure you have proper permissions (run as admin/root).\nError: {e}")
            print(f"Nmap error: {e}")
            traceback.print_exc()
            return {}
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
            print(f"Unexpected error: {e}")
            traceback.print_exc()
            return {}
        return all_scanned_devices

    def calculate_risk_score(self, open_ports_info):
        score = 0
        for p_info in open_ports_info:
            if p_info['port'] in RISKY_PORTS:
                if p_info['port'] in {23, 445, 3389}:
                    score += 5
                elif p_info['port'] in {21, 25, 110, 139, 5900}:
                    score += 3
                else:
                    score += 1
        return score

class LoginApp:
    def __init__(self, master, app_manager):
        self.master = master
        self.app_manager = app_manager
        self.frame = ttk.Frame(master, padding="40 40 40 40", style='Login.TFrame')
        self.frame.pack(expand=True, fill="both")
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('Login.TFrame', background='#e0f2f7', borderwidth=5, relief="raised")
        self.style.configure('Login.TLabel', background='#e0f2f7', foreground='#2c3e50', font=('Inter', 12, 'bold'))
        self.style.configure('Login.TEntry', fieldbackground='#ffffff', foreground='#34495e', font=('Inter', 12), borderwidth=2, relief="flat")
        self.style.configure('Login.TButton', background='#2ecc71', foreground='white', font=('Inter', 12, 'bold'), borderwidth=0, focusthickness=3, focuscolor='none', relief="raised", padding=10)
        self.style.map('Login.TButton', 
                        background=[('active', '#27ae60'), ('pressed', '#1e8449')],
                        relief=[('active', 'groove'), ('pressed', 'sunken')])
        self.title_label = ttk.Label(self.frame, text="Network Profiler", font=('Inter', 24, 'bold'), foreground='#2980b9', style='Login.TLabel')
        self.title_label.pack(pady=(20, 30))
        self.username_label = ttk.Label(self.frame, text="Username:", style='Login.TLabel')
        self.username_label.pack(pady=(10, 0))
        self.username_entry = ttk.Entry(self.frame, style='Login.TEntry')
        self.username_entry.pack(pady=(5, 20), ipadx=10, ipady=5)
        self.password_label = ttk.Label(self.frame, text="Password:", style='Login.TLabel')
        self.password_label.pack(pady=(10, 0))
        self.password_entry = ttk.Entry(self.frame, show='*', style='Login.TEntry')
        self.password_entry.pack(pady=(5, 20), ipadx=10, ipady=5)
        self.button_frame = ttk.Frame(self.frame, style='Login.TFrame')
        self.button_frame.pack(pady=20)
        self.login_button = ttk.Button(self.button_frame, text="Login", command=self.login, style='Login.TButton')
        self.login_button.grid(row=0, column=0, padx=10)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if authenticate_user(username, password):
            self.hide_login_form()
            self.app_manager.show_main_app()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    def show_login_form(self):
        self.frame.pack(expand=True, fill="both")
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def hide_login_form(self):
        self.frame.pack_forget()

class MainApp:
    def __init__(self, master, app_manager):
        self.master = master
        self.app_manager = app_manager
        self.network_scanner = NetworkScanner()
        self.main_frame = ttk.Frame(master, padding="20 20 20 20", style='Main.TFrame')
        self.style = ttk.Style()
        self.style.configure('Main.TFrame', background='#ffffff')
        self.style.configure('Main.TLabel', background='#ffffff', foreground='#34495e', font=('Inter', 11))
        self.style.configure('Main.Treeview.Heading', font=('Inter', 10, 'bold'), background='#3498db', foreground='white')
        self.style.configure('Main.Treeview', background='#ecf0f1', foreground='#2c3e50', rowheight=25, font=('Inter', 10), fieldbackground='#ecf0f1', borderwidth=1, relief="solid")
        self.style.map('Main.Treeview', background=[('selected', '#3498db')])
        self.style.configure('Main.TButton', background='#e74c3c', foreground='white', font=('Inter', 11, 'bold'), borderwidth=0, relief="raised", padding=8)
        self.style.map('Main.TButton', background=[('active', '#c0392b'), ('pressed', '#a93226')], relief=[('active', 'groove'), ('pressed', 'sunken')])
        self.style.configure('Scan.TButton', background='#2ecc71', foreground='white', font=('Inter', 11, 'bold'), borderwidth=0, relief="raised", padding=8)
        self.style.map('Scan.TButton', background=[('active', '#27ae60'), ('pressed', '#1e8449')], relief=[('active', 'groove'), ('pressed', 'sunken')])
        self.style.configure('Details.TText', background='#f8f9fa', foreground='#2c3e50', font=('Inter', 10), borderwidth=1, relief="solid")
        self.control_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        self.control_frame.pack(side="top", fill="x", pady=(0, 10))
        self.scan_button = ttk.Button(self.control_frame, text="Scan Network for Risky Ports", command=self.run_scan, style='Scan.TButton')
        self.scan_button.pack(side="left", padx=5)
        self.logout_button = ttk.Button(self.control_frame, text="Logout", command=self.logout, style='Main.TButton')
        self.logout_button.pack(side="right", padx=5)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.control_frame, variable=self.progress_var, orient="horizontal", mode="determinate", length=250)
        self.progress_bar.pack(side="left", padx=15)
        self.progress_bar['maximum'] = 100
        self.progress_bar.pack_forget()

        self.content_frame = ttk.Frame(self.main_frame, style='Main.TFrame')
        self.content_frame.pack(expand=True, fill="both")
        self.content_frame.columnconfigure(0, weight=1)
        self.content_frame.columnconfigure(1, weight=2)
        self.content_frame.rowconfigure(0, weight=1)
        self.device_list_frame = ttk.Frame(self.content_frame, style='Main.TFrame')
        self.device_list_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self.device_list_label = ttk.Label(self.device_list_frame, text="Discovered Devices:", font=('Inter', 12, 'bold'), style='Main.TLabel')
        self.device_list_label.pack(pady=(0, 5))
        self.device_tree = ttk.Treeview(self.device_list_frame, columns=("IP Address", "Hostname", "MAC Address", "Risk Score"), show="headings", style='Main.Treeview')
        self.device_tree.heading("IP Address", text="IP Address")
        self.device_tree.heading("Hostname", text="Hostname")
        self.device_tree.heading("MAC Address", text="MAC Address")
        self.device_tree.heading("Risk Score", text="Risk Score")
        self.device_tree.column("IP Address", width=100, anchor="w")
        self.device_tree.column("Hostname", width=100, anchor="w")
        self.device_tree.column("MAC Address", width=100, anchor="w")
        self.device_tree.column("Risk Score", width=60, anchor="center")
        self.device_tree.pack(expand=True, fill="both")
        self.device_tree.bind("<<TreeviewSelect>>", self.on_device_select)
        self.device_tree_scrollbar = ttk.Scrollbar(self.device_list_frame, orient="vertical", command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=self.device_tree_scrollbar.set)
        self.device_tree_scrollbar.pack(side="right", fill="y")
        self.details_frame = ttk.Frame(self.content_frame, style='Main.TFrame', relief="solid", borderwidth=1)
        self.details_frame.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.details_label = ttk.Label(self.details_frame, text="Device Details", font=('Inter', 12, 'bold'), style='Main.TLabel')
        self.details_label.pack(pady=(10, 5))
        self.details_text = tk.Text(self.details_frame, wrap="word", height=15, width=40, font=('Inter', 10), 
                                     background='#f8f9fa', foreground='#2c3e50', relief="solid", borderwidth=1)
        self.details_text.pack(expand=True, fill="both", padx=10, pady=10)
        self.details_text.insert(tk.END, "Select a device from the list to see its details.")
        self.details_text.config(state="disabled")
        self.all_scanned_devices_data = {}
        self.clear_device_display_and_prompt()
        self.watermark_label = tk.Label(self.main_frame, text="Aashish Kumar & Dhruvil kumar", 
                                         font=("Script MT Bold", 14, "italic"),
                                         fg="#a0a0a0",
                                         bg=self.style.lookup('Main.TFrame', 'background'),
                                         bd=0, relief="flat",
                                         anchor="se")
        self.watermark_label.place(relx=1.0, rely=1.0, x=-10, y=-10, anchor="se")

    def show_main_app(self):
        self.main_frame.pack(expand=True, fill="both")
        self.clear_device_display_and_prompt()

    def hide_main_app(self):
        self.main_frame.pack_forget()

    def clear_device_display_and_prompt(self):
        self.device_tree.delete(*self.device_tree.get_children())
        self.all_scanned_devices_data = {}
        self.details_text.config(state="normal")
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, "Welcome! Click 'Scan Network for Risky Ports' to begin discovering devices on your network.")
        self.details_text.config(state="disabled")

    def run_scan(self):
        self.scan_button.config(state="disabled")
        self.progress_var.set(0)
        self.progress_bar.pack(side="left", padx=15)
        self.progress_bar['value'] = 0
        self.progress_bar['mode'] = 'indeterminate'
        self.progress_bar.start(10)
        self.device_tree.delete(*self.device_tree.get_children())
        self.details_text.config(state="normal")
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, "Scanning network... This may take a few moments.\nPlease ensure Nmap is installed and you have sufficient permissions (e.g., run as administrator/root).\n")
        self.details_text.config(state="disabled")
        self.master.update_idletasks()
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self):
        local_ip, network_address, prefix_len = self.network_scanner.get_local_ip_and_subnet()
        target_range = f"{network_address}/{prefix_len}"
        print(f"Starting scan for {target_range}")
        def progress_callback(current, total):
            self.master.after(0, self._update_progress, current, total)
        self.all_scanned_devices_data = self.network_scanner.scan_network(target_range, progress_callback=progress_callback)
        print(f"Scan completed. Found {len(self.all_scanned_devices_data)} devices that responded.")
        self.master.after(0, self._scan_done)

    def _update_progress(self, current, total):
        self.progress_bar['mode'] = 'determinate'
        self.progress_bar['maximum'] = total
        self.progress_var.set(current)
        self.progress_bar.update_idletasks()

    def _scan_done(self):
        self.progress_bar.stop()
        self.progress_bar.pack_forget()
        if not self.all_scanned_devices_data:
            self.details_text.config(state="normal")
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, "No active devices found in the scanned range, or Nmap encountered an issue. Ensure Nmap is installed and permissions are correct.")
            self.details_text.config(state="disabled")
            self.scan_button.config(state="normal")
            return
        save_scan_results(self.all_scanned_devices_data)
        self.load_scan_results_into_gui(self.all_scanned_devices_data)
        self.details_text.config(state="normal")
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, "Scan completed. Select a device from the list for details.")
        self.details_text.config(state="disabled")
        self.scan_button.config(state="normal")

    def load_scan_results_into_gui(self, data_to_load):
        self.device_tree.delete(*self.device_tree.get_children())
        if not data_to_load:
            self.details_text.config(state="normal")
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, "No devices found in the scan results to display.")
            self.details_text.config(state="disabled")
            return
        for ip, data in data_to_load.items():
            hostname = data.get('hostname', 'N/A')
            mac_address = data.get('mac', 'N/A')
            risk_score = data.get('risk_score', 0)
            self.device_tree.insert("", tk.END, iid=ip, values=(ip, hostname, mac_address, risk_score))

    def on_device_select(self, event):
        selected_item_id = self.device_tree.focus()
        if selected_item_id:
            device_ip = selected_item_id
            device_data = self.all_scanned_devices_data.get(device_ip)
            if device_data:
                details = f"IP Address: {device_ip}\n"
                details += f"MAC Address: {device_data.get('mac', 'N/A')}"
                if device_data.get('mac') == 'N/A':
                    details += " (MAC address might be unavailable due to network configuration, firewalls, or device type. Ensure app is run as administrator/root.)\n"
                else:
                    details += "\n"
                details += f"Hostname: {device_data.get('hostname', 'N/A')}"
                if device_data.get('hostname') == device_ip or device_data.get('hostname') == 'N/A':
                    details += " (Hostname could not be resolved. This is common for many consumer devices.)\n"
                else:
                    details += "\n"
                details += f"Risk Score: {device_data.get('risk_score', 0)} (Higher = More Risky Ports)\n"
                details += f"Last Scanned: {device_data.get('last_scanned', 'N/A')}\n\n"
                details += "Open Risky Ports:\n"
                open_ports = device_data.get('open_ports', [])
                if open_ports:
                    for port_info in open_ports:
                        port_num = port_info['port']
                        service = port_info['service']
                        description = RISKY_PORTS.get(port_num, "No specific description available for this risky port.")
                        details += f"   - {port_num}/{port_info['protocol']} ({service}) - {description}\n"
                else:
                    details += "   No risky open ports detected.\n"
            else:
                details = "No data available for this device."
            self.details_text.config(state="normal")
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, details)
            self.details_text.config(state="disabled")

    def logout(self):
        if messagebox.askyesno("Logout", "Are you sure you want to log out?"):
            self.hide_main_app()
            self.app_manager.show_login_app()

class ApplicationManager:
    def __init__(self, master):
        self.master = master
        master.title("Network Security Application")
        master.geometry("800x600")
        master.resizable(True, True)
        self.login_app = LoginApp(master, self)
        self.main_app = MainApp(master, self)
        self.show_login_app()

    def show_login_app(self):
        self.main_app.hide_main_app()
        self.master.geometry("500x550")
        self.master.title("Login")
        self.login_app.show_login_form()

    def show_main_app(self):
        self.login_app.hide_login_form()
        self.master.geometry("800x600")
        self.master.title("Network Security Tool")
        self.main_app.show_main_app()

if __name__ == "__main__":
    create_user_db()
    create_scan_db()
    try:
        nm = nmap.PortScanner()
        nm.nmap_version()
    except nmap.PortScannerError as e:
        messagebox.showerror("Nmap Not Found", 
                             "Nmap is not found or not in your system's PATH. "
                             "Please install Nmap from nmap.org and ensure it's accessible. "
                             "The application will now exit.")
        sys.exit(1)
    except Exception as e:
        messagebox.showwarning("Nmap Check", f"Could not verify Nmap installation completely: {e}. Proceeding, but scans might fail.")
    root = tk.Tk()
    app_manager = ApplicationManager(root)
    root.mainloop()
