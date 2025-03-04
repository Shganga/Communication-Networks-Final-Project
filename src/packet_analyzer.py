import os
import pyshark
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict, Counter


def analyze_traffic(pcap_files):
    data = defaultdict(lambda: defaultdict(list))

    tls_versions_mapping = {
        '0x0301': 'TLS 1.0',
        '0x0302': 'TLS 1.1',
        '0x0303': 'TLS 1.2',
        '0x0304': 'TLS 1.3'
    }

    for app, (pcap_file, key_file) in pcap_files.items():
        pcap_path = os.path.join(os.getcwd(), pcap_file)
        key_path = os.path.join(os.getcwd(), key_file) if key_file else None

        if not os.path.exists(pcap_path):
            print(f"❌ Error: PCAP file not found - {pcap_path}")
            continue

        capture = pyshark.FileCapture(pcap_path, override_prefs={"tls.keylog_file": key_path} if key_file else None)

        protocol_distribution = defaultdict(int)
        packet_sizes = []
        inter_arrival_times = []
        flow_sizes = 0
        flow_volume = 0
        ttl_values = []
        tls_versions_counter = Counter()

        prev_time = None

        for packet in capture:
            if 'TCP' in packet:
                protocol_distribution['TCP'] += 1
            elif 'UDP' in packet:
                protocol_distribution['UDP'] += 1
            if 'HTTP' in packet:
                protocol_distribution['HTTP'] += 1
            if 'HTTP2' in packet:
                protocol_distribution['HTTP2'] += 1
            if 'TLS' in packet:
                protocol_distribution['TLS'] += 1
                if hasattr(packet.tls, 'handshake_version'):
                    version = tls_versions_mapping.get(packet.tls.handshake_version, 'Unknown')
                    tls_versions_counter[version] += 1

            packet_sizes.append(int(packet.length))

            if 'IP' in packet:
                if hasattr(packet.ip, 'ttl'):
                    ttl_values.append(int(packet.ip.ttl))

            if prev_time:
                inter_arrival_times.append(float(packet.sniff_time.timestamp() - prev_time))
            prev_time = float(packet.sniff_time.timestamp())

            flow_sizes += 1
            flow_volume += int(packet.length)

        capture.close()

        data[app]['packet_sizes'] = packet_sizes
        data[app]['inter_arrival_times'] = inter_arrival_times
        data[app]['flow_size'] = flow_sizes
        data[app]['flow_volume'] = flow_volume
        data[app]['protocol_distribution'] = protocol_distribution
        data[app]['avg_ttl'] = np.mean(ttl_values) if ttl_values else 0
        data[app]['tls_versions'] = dict(tls_versions_counter)

    return data


def plot_data(data):
    plot_dir = os.path.abspath(os.path.join(os.getcwd(), "..", "res", "analyzed_data_plots"))
    os.makedirs(plot_dir, exist_ok=True)  # Ensure the res/analyzed_data_plots directory exists

    apps = list(data.keys())

    # Protocol Distribution Plot - Comparing across apps with percentages
    plt.figure(figsize=(10, 6))
    # Fixed protocol order
    fixed_protocol_order = ['TCP', 'UDP', 'HTTP', 'HTTP2', 'TLS']

    # Fixed colors for each protocol
    protocol_colors = {
        'TCP': '#1f77b4',  # Blue
        'UDP': '#ff7f0e',  # Orange
        'HTTP': '#2ca02c',  # Green
        'HTTP2': '#d62728',  # Red
        'TLS': '#9467bd'  # Purple
    }

    # Ensure all protocols appear for every app
    protocol_counts = {app: {protocol: 0 for protocol in fixed_protocol_order} for app in apps}
    for app in apps:
        for protocol, count in data[app]['protocol_distribution'].items():
            protocol_counts[app][protocol] = count  # Use only fixed order

    # Convert counts to percentages
    total_packets_per_app = {app: sum(protocol_counts[app].values()) for app in apps}
    protocol_counts_percentage = {
        app: [100 * protocol_counts[app][protocol] / total_packets_per_app[app] if total_packets_per_app[app] else 0
              for protocol in fixed_protocol_order]
        for app in apps
    }

    # Plot bars in fixed order with fixed colors
    plt.figure(figsize=(10, 6))
    x = np.arange(len(apps))
    width = 0.15

    for i, protocol in enumerate(fixed_protocol_order):
        protocol_data = [protocol_counts_percentage[app][i] for app in apps]
        plt.bar(x + i * width, protocol_data, width, label=protocol, color=protocol_colors[protocol])

    plt.title('Protocol Distribution Across Applications (Percentages)')
    plt.xlabel('Application')
    plt.ylabel('Percentage of Packets (%)')
    plt.xticks(x + width * (len(fixed_protocol_order) / 2 - 0.5), apps)
    plt.legend(title='Protocol')
    plt.savefig(os.path.join(plot_dir, "protocol_distribution_comparison_percentages.png"))
    plt.close()

    # Average TTL Plot
    plt.figure(figsize=(10, 6))
    avg_ttl = [data[app]['avg_ttl'] for app in apps]
    plt.bar(apps, avg_ttl)
    plt.title('Average TTL Comparison')
    plt.xlabel('Application')
    plt.ylabel('Average TTL')
    plt.savefig(os.path.join(plot_dir, "avg_ttl.png"))
    plt.close()

    # TLS Versions Plot
    plt.figure(figsize=(10, 6))
    tls_versions = ['TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3']
    tls_counts = np.array([[data[app]['tls_versions'].get(version, 0) for version in tls_versions] for app in apps]).T

    width = 0.15  # Bar width
    x = np.arange(len(apps))

    for i, version in enumerate(tls_versions):
        plt.bar(x + i * width, tls_counts[i], width, label=version)

    plt.title('TLS Versions Used Across Applications')
    plt.xlabel('Application')
    plt.ylabel('Count')
    plt.xticks(x + width, apps)
    plt.legend(title='TLS Version')
    plt.savefig(os.path.join(plot_dir, "tls_versions.png"))
    plt.close()

    # Average Packet Sizes Plot
    plt.figure(figsize=(10, 6))
    avg_packet_sizes = [np.mean(data[app]['packet_sizes']) for app in apps]
    plt.bar(apps, avg_packet_sizes)
    plt.title('Average Packet Sizes Comparison')
    plt.xlabel('Application')
    plt.ylabel('Average Packet Size (bytes)')
    plt.savefig(os.path.join(plot_dir, "avg_packet_sizes.png"))
    plt.close()

    # Flow Size Plot
    plt.figure(figsize=(10, 6))
    flow_sizes = [data[app]['flow_size'] for app in apps]
    plt.bar(apps, flow_sizes)
    plt.title('Flow Size Comparison')
    plt.xlabel('Application')
    plt.ylabel('Flow Size')
    plt.savefig(os.path.join(plot_dir, "flow_size.png"))
    plt.close()

    # Flow Volume Plot
    plt.figure(figsize=(10, 6))
    flow_volumes = [data[app]['flow_volume'] for app in apps]
    plt.bar(apps, flow_volumes)
    plt.title('Flow Volume Comparison')
    plt.xlabel('Application')
    plt.ylabel('Flow Volume (bytes)')
    plt.savefig(os.path.join(plot_dir, "flow_volume.png"))
    plt.close()

    # Average Inter-Arrival Times Plot
    plt.figure(figsize=(10, 6))
    avg_inter_arrival = [np.mean(data[app]['inter_arrival_times']) if data[app]['inter_arrival_times'] else 0 for app in
                         apps]
    plt.bar(apps, avg_inter_arrival)
    plt.title('Average Inter-Arrival Time Comparison')
    plt.xlabel('Application')
    plt.ylabel('Average Inter-Arrival Time (s)')
    plt.savefig(os.path.join(plot_dir, "avg_inter_arrival_times.png"))
    plt.close()


def main():
    pcap_files = {
        'Spotify': ('spotify.pcapng', 'spotify.txt'),
        'Chrome': ('chrome.pcapng', 'chrome.txt'),
        'Firefox': ('firefox.pcapng', 'firefox.txt'),
        'YouTube': ('youtube.pcapng', 'youtube.txt'),
        'Zoom': ('zoom.pcapng', 'zoom.txt')
    }

    data = analyze_traffic(pcap_files)
    plot_data(data)


if __name__ == "__main__":
    main()