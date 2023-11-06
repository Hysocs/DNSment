import sys
import subprocess
import re
import time
from PyQt5.QtWidgets import QApplication, QMainWindow, QPlainTextEdit, QPushButton, QProgressBar, QLabel, QCheckBox, QDialog, QVBoxLayout, QLineEdit
from PyQt5.QtCore import Qt, QThread, pyqtSlot, pyqtSignal

class DnsScannerWorker(QThread):
    scanningFinished = pyqtSignal(list)
    progressUpdate = pyqtSignal(int, int)

    def __init__(self, dns_servers, ping_count, ping_delay, stability_threshold, scan_user_dns, parallel_scan, total_servers):
        super().__init__()
        self.dns_servers = dns_servers
        self.ping_count = ping_count
        self.ping_delay = ping_delay
        self.stability_threshold = stability_threshold
        self.scan_user_dns = scan_user_dns
        self.parallel_scan = parallel_scan
        self.total_servers = total_servers  # Store total_servers as an instance variable
        self.progress = [0, 0]

    def run(self):
        if self.parallel_scan:
            results = self.scan_dns_servers_parallel()
        else:
            results = self.scan_dns_servers()

        best_server, best_avg_ping, packet_loss_rate = self.find_best_dns_server(results)
        self.scanningFinished.emit([best_server, best_avg_ping, packet_loss_rate])


    def ping_server(self, host, count=50, delay=0.1):
        pings = []
        packet_loss_count = 0
        try:
            for i in range(count):
                result = self.ping_once(host)
                if result:
                    pings.extend(result)
                else:
                    packet_loss_count += 1
                time.sleep(delay)
            return host, pings, packet_loss_count
        except Exception as e:
            return None

    def ping_once(self, host):
        process = subprocess.Popen(f"ping -n 1 {host}", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, _ = process.communicate()
        ping_results = re.findall(r"time=(\d+)ms", output.decode())
        return [int(ping) for ping in ping_results] if ping_results else []

    def scan_dns_servers(self):
        results = []

        for i, server in enumerate(self.dns_servers, start=1):
            result = self.ping_server(server)
            if result:
                results.append(result)
                self.progressUpdate.emit(i, len(self.dns_servers))
            self.progress[0] = i
        self.progress[1] = len(self.dns_servers)
        return results
    
    def scan_dns_servers_parallel(self):
        results = []

        def scan(server):
            result = self.ping_server(server)
            if result:
                results.append(result)
                self.progressUpdate.emit(len(results), self.total_servers)

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(scan, server) for server in self.dns_servers]

        # Wait for all futures to complete
        for future in futures:
            future.result()

        return results
    
    def calculate_stability(self, pings):
        if len(pings) < 2:
            return 100.0

        total_stability = sum(1.0 - abs(pings[i] - pings[i - 1]) / 100.0 for i in range(1, len(pings)))
        return total_stability / (len(pings) - 1)

    def find_best_dns_server(self, results):
        best_server = None
        best_avg_ping = float("inf")
        best_stability = 0
        packet_loss_rate = 0

        for server, pings, packet_loss_count in results:
            if pings:
                average_ping = sum(pings) / len(pings)
                stability = self.calculate_stability(pings)
                if average_ping < best_avg_ping and stability > self.stability_threshold:
                    best_server = server
                    best_avg_ping = average_ping
                    best_stability = stability
                packet_loss_rate = (packet_loss_count / self.ping_count) * 100

        return best_server, best_avg_ping, packet_loss_rate

class DnsScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.default_dns_servers = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220"]  # Define default DNS servers
        self.init_ui()
        self.async_task = None
        self.total_servers = 0
        self.scan_user_dns = False
        self.user_dns_servers = self.get_user_dns_servers()
        self.ping_count = 25
        self.ping_delay = 0.1
        self.stability_threshold = 0.8
        self.parallel_scan = True

    def init_ui(self):
        self.setGeometry(100, 100, 400, 300)
        self.setWindowTitle("DNSment")

        self.text_edit = QPlainTextEdit(self)
        self.text_edit.setGeometry(10, 10, 380, 180)
        self.text_edit.setReadOnly(True)

        self.scan_button = QPushButton("Scan DNS Servers", self)
        self.scan_button.setGeometry(10, 200, 100, 30)
        self.scan_button.clicked.connect(self.start_scanning)
        self.is_scanning = False

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setGeometry(135, 205, 230, 20)
        self.progress_bar.setValue(0)

        self.progress_label = QLabel("0/0", self)
        self.progress_label.setGeometry(365, 205, 80, 20)

        self.settings_button = QPushButton("Settings", self)
        self.settings_button.setGeometry(320, 240, 70, 30)
        self.settings_button.clicked.connect(self.open_settings_dialog)

    def open_settings_dialog(self):
        settings_dialog = SettingsDialog(self)
        settings_dialog.include_current_dns_checkbox.setChecked(self.scan_user_dns)  # Set the state of the "Include current DNS" checkbox
        settings_dialog.parallel_scan_checkbox.setChecked(self.parallel_scan)  # Set the state of the "Scan in parallel" checkbox
        settings_dialog.exec_()

    def toggle_user_dns(self, state):
        if state == Qt.Checked:
            self.scan_user_dns = True
        else:
            self.scan_user_dns = False

        self.update_total_servers()
        self.progress_label.setText(f"0/{self.total_servers}")

    def toggle_parallel_scan(self, state):
        if state == Qt.Checked:
            self.parallel_scan = True
        else:
            self.parallel_scan = False

    def update_total_servers(self):
        if self.scan_user_dns:
            combined_servers = self.default_dns_servers + self.get_user_dns_servers()
        else:
            combined_servers = self.default_dns_servers

        print("Before update_total_servers:", combined_servers)  # Debug print
        self.total_servers = len(combined_servers)
        self.dns_servers = combined_servers
        self.progress_label.setText(f"0/{self.total_servers}")
        print("After update_total_servers:", combined_servers)  # Debug print

    def get_user_dns_servers(self):
        try:
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, shell=True)
            output = result.stdout

            # Extract DNS Servers using regular expressions for both IPv4 and IPv6
            dns_servers_ipv4 = re.findall(r'DNS Servers[ .]+: (\d+\.\d+\.\d+\.\d+)', output)
            dns_servers_ipv6 = re.findall(r'DNS Servers[ .]+: ([0-9a-fA-F:]+)', output)
            dns_servers_ipv4.extend(re.findall(r'DNS Server .+ : (\d+\.\d+\.\d+\.\d+)', output))
            dns_servers_ipv6.extend(re.findall(r'DNS Server .+ : ([0-9a-fA-F:]+)', output))

            # Combine the lists of both IPv4 and IPv6 DNS servers
            dns_servers = dns_servers_ipv4 + dns_servers_ipv6

            # Filter out duplicate addresses
            unique_dns_servers = list(set(dns_servers))

            # Filter out entries that don't match IPv4 or IPv6 format
            valid_dns_servers = [server for server in unique_dns_servers if re.match(r'(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)', server) and (':' in server or '.' in server)]

            # Debug print
            print("User DNS Servers:", valid_dns_servers)

            return valid_dns_servers
        except Exception as e:
            return []

    def update_progress(self, current, total):
        progress = int((current / total) * 100)
        self.progress_bar.setValue(progress)
        self.progress_label.setText(f"{current}/{total}")

    def start_scanning(self):
        if self.is_scanning:
            return

        self.text_edit.clear()
        self.progress_bar.setMaximum(100)
        self.update_total_servers()
        self.progress_bar.setValue(0)
        self.progress_label.setText(f"0/{self.total_servers}")

        if not self.dns_servers:
            self.text_edit.insertPlainText("No DNS servers to scan.")
            return

        self.is_scanning = True
        self.scan_button.setEnabled(False)  # Disable the button

        self.async_task = DnsScannerWorker(
            self.dns_servers, self.ping_count, self.ping_delay, self.stability_threshold, self.scan_user_dns, self.parallel_scan, self.total_servers
        )
        self.async_task.scanningFinished.connect(self.scanning_finished)
        self.async_task.progressUpdate.connect(self.update_progress)
        self.async_task.finished.connect(self.scanning_done)

        self.async_task.start()

    @pyqtSlot()
    def scanning_done(self):
        self.is_scanning = False
        self.scan_button.setEnabled(True) 

    @pyqtSlot(list)
    def scanning_finished(self, result):
        best_server, best_avg_ping, packet_loss_rate = result

        if best_server:
            message = "You are already using the best DNS server." if self.scan_user_dns and best_server in self.user_dns_servers else "Best DNS server to use:"
            self.text_edit.insertPlainText(message)
            self.text_edit.insertPlainText(f"\nDNS Server: {best_server}\nAverage Ping: {best_avg_ping:.2f} ms\nPacket Loss Rate: {packet_loss_rate:.2f}%")
        else:
            self.text_edit.insertPlainText("No DNS server could be determined")
        self.scan_button.setEnabled(True)

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent  # Store the parent as an instance variable
        self.setWindowTitle("Settings")
        self.setGeometry(200, 200, 250, 230)

        layout = QVBoxLayout()

        dns_label = QLabel("DNS Servers:", self)  # Label to inform the user
        layout.addWidget(dns_label)

        self.dns_edit = QPlainTextEdit(self)  # Use QPlainTextEdit for multiline input
        self.dns_edit.setPlainText("\n".join(parent.default_dns_servers))  # Display current DNS servers
        layout.addWidget(self.dns_edit)

        self.include_current_dns_checkbox = QCheckBox("Include current DNS", self)
        layout.addWidget(self.include_current_dns_checkbox)

        self.parallel_scan_checkbox = QCheckBox("Scan in parallel", self)
        self.parallel_scan_checkbox.setToolTip("Speeds up scanning with potential result accuracy trade-off.")
        layout.addWidget(self.parallel_scan_checkbox)

        save_button = QPushButton("Save", self)
        save_button.clicked.connect(self.save_settings)
        layout.addWidget(save_button)

        self.setLayout(layout)

    def save_settings(self):
        dns_text = self.dns_edit.toPlainText()
        dns_servers = [server.strip() for server in dns_text.split("\n")]
        self.parent.default_dns_servers = dns_servers

        # Save the state of the checkboxes in the parent
        self.parent.scan_user_dns = self.include_current_dns_checkbox.isChecked()
        self.parent.parallel_scan = self.parallel_scan_checkbox.isChecked()

        self.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DnsScannerApp()
    window.show()
    sys.exit(app.exec_())