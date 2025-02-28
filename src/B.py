import os
import pyshark
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

class TrafficAnalyzerTCP:
    def __init__(self, pcap_files):
        self.pcap_files = pcap_files
        self.data = defaultdict(lambda: defaultdict(list))

    def analyze(self):
        for app, (pcap_filename, key_filename) in self.pcap_files.items():
            pcap_path = os.path.join('src', pcap_filename)
            key_path = os.path.join('src', key_filename) if key_filename else None

            if not os.path.exists(pcap_path):
                print(f"❌ Error: PCAP file not found - {pcap_path}")
                continue

            capture = pyshark.FileCapture(pcap_path, override_prefs={"tls.keylog_file": key_path} if key_path else None)

            source_ports = []
            dest_ports = []
            seq_numbers = []
            ack_numbers = []
            window_sizes = []
            tcp_flags = defaultdict(int)

            for packet in capture:
                if 'TCP' in packet:
                    tcp_layer = packet.tcp

                    source_ports.append(int(tcp_layer.srcport))
                    dest_ports.append(int(tcp_layer.dstport))
                    seq_numbers.append(int(tcp_layer.seq))
                    ack_numbers.append(int(tcp_layer.ack))
                    window_sizes.append(int(tcp_layer.window_size))

                    for flag in ['syn', 'ack', 'fin', 'rst', 'psh', 'urg']:
                        if getattr(tcp_layer, flag, False):
                            tcp_flags[flag] += 1

            self.data[app]['source_ports'] = source_ports
            self.data[app]['dest_ports'] = dest_ports
            self.data[app]['seq_numbers'] = seq_numbers
            self.data[app]['ack_numbers'] = ack_numbers
            self.data[app]['window_sizes'] = window_sizes
            self.data[app]['tcp_flags'] = tcp_flags

            capture.close()

    def plot(self):
        apps = list(self.data.keys())

        if not apps:
            print("⚠️ No data available for plotting.")
            return

        # Source Port Distribution
        plt.figure(figsize=(10, 6))
        plt.bar(apps, [len(self.data[app]['source_ports']) for app in apps], color='skyblue')
        plt.xlabel('Applications')
        plt.ylabel('Source Port Count')
        plt.title('Source Port Distribution')
        plt.tight_layout()
        plt.show()

        # Destination Port Distribution
        plt.figure(figsize=(10, 6))
        plt.bar(apps, [len(self.data[app]['dest_ports']) for app in apps], color='lightgreen')
        plt.xlabel('Applications')
        plt.ylabel('Destination Port Count')
        plt.title('Destination Port Distribution')
        plt.tight_layout()
        plt.show()

        # Sequence Number Distribution
        plt.figure(figsize=(10, 6))
        plt.bar(apps, [np.mean(self.data[app]['seq_numbers']) for app in apps], color='lightcoral')
        plt.xlabel('Applications')
        plt.ylabel('Average Sequence Number')
        plt.title('Average Sequence Number Distribution')
        plt.tight_layout()
        plt.show()

        # Acknowledgment Number Distribution
        plt.figure(figsize=(10, 6))
        plt.bar(apps, [np.mean(self.data[app]['ack_numbers']) for app in apps], color='lightblue')
        plt.xlabel('Applications')
        plt.ylabel('Average Acknowledgment Number')
        plt.title('Average Acknowledgment Number Distribution')
        plt.tight_layout()
        plt.show()

        # Window Size Distribution
        plt.figure(figsize=(10, 6))
        plt.bar(apps, [np.mean(self.data[app]['window_sizes']) for app in apps], color='orange')
        plt.xlabel('Applications')
        plt.ylabel('Average Window Size')
        plt.title('Average TCP Window Size')
        plt.tight_layout()
        plt.show()

        # TCP Flags Distribution (SYN, ACK, FIN, etc.)
        tcp_flags = ['syn', 'ack', 'fin', 'rst', 'psh', 'urg']
        flag_counts = {app: [self.data[app]['tcp_flags'][flag] for flag in tcp_flags] for app in apps}

        plt.figure(figsize=(10, 6))
        bar_width = 0.1
        x = np.arange(len(tcp_flags))

        for i, app in enumerate(apps):
            plt.bar(x + i * bar_width, flag_counts[app], bar_width, label=app)

        plt.xlabel('TCP Flags')
        plt.ylabel('Flag Count')
        plt.title('TCP Flags Distribution (SYN, ACK, FIN, etc.)')
        plt.xticks(x + bar_width * (len(apps) / 2 - 0.5), tcp_flags, rotation=45)
        plt.legend(title='Applications')
        plt.tight_layout()
        plt.show()


# Function to run the analysis and plotting
def run_analysis(pcap_files):
    analyzer = TrafficAnalyzerTCP(pcap_files)
    analyzer.analyze()
    analyzer.plot()
