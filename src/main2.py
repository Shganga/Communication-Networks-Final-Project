import os
import pyshark
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict


# Function to analyze traffic and extract data for comparison
def analyze_traffic(pcap_files):
    data = defaultdict(lambda: defaultdict(list))

    for app, (pcap_file, key_file) in pcap_files.items():
        pcap_path = os.path.join(os.getcwd(), pcap_file)
        key_path = os.path.join(os.getcwd(), key_file) if key_file else None

        if not os.path.exists(pcap_path):
            print(f"❌ Error: PCAP file not found - {pcap_path}")
            continue

        capture = pyshark.FileCapture(pcap_path, override_prefs={"tls.keylog_file": key_path} if key_path else None)

        # Initialize variables to store the traffic characteristics
        protocol_distribution = defaultdict(int)  # To store the count of each protocol
        packet_sizes = []
        inter_arrival_times = []
        flow_sizes = 0
        flow_volume = 0

        prev_time = None

        # Process each packet in the capture
        for packet in capture:
            # Track protocols (Transport Layer)
            if 'TCP' in packet:
                protocol_distribution['TCP'] += 1
            elif 'UDP' in packet:
                protocol_distribution['UDP'] += 1

            # Track application layer protocols
            if 'HTTP' in packet:
                protocol_distribution['HTTP'] += 1
            if 'HTTP2' in packet:
                protocol_distribution['HTTP2'] += 1
            if 'TLS' in packet:
                protocol_distribution['TLS'] += 1

            # Packet Sizes
            packet_sizes.append(int(packet.length))

            # Inter-arrival Times
            if prev_time:
                inter_arrival_times.append(float(packet.sniff_time.timestamp() - prev_time))
            prev_time = float(packet.sniff_time.timestamp())

            # Flow Size and Flow Volume
            flow_sizes += 1
            flow_volume += int(packet.length)

        capture.close()

        # Store the data for plotting
        data[app]['packet_sizes'] = packet_sizes
        data[app]['inter_arrival_times'] = inter_arrival_times
        data[app]['flow_size'] = flow_sizes
        data[app]['flow_volume'] = flow_volume
        data[app]['protocol_distribution'] = protocol_distribution

    return data


# Function to plot data for comparison
def plot_data(data):
    apps = list(data.keys())

    # Plot Packet Sizes - Average Packet Size for each app
    plt.figure(figsize=(10, 6))
    avg_packet_sizes = [np.mean(data[app]['packet_sizes']) for app in apps]
    plt.bar(apps, avg_packet_sizes)
    plt.title('Average Packet Sizes Comparison')
    plt.xlabel('Application')
    plt.ylabel('Average Packet Size (bytes)')
    plt.show()

    # Plot Inter-arrival Times - Average Inter-arrival Time for each app
    plt.figure(figsize=(10, 6))
    avg_inter_arrival_times = [np.mean(data[app]['inter_arrival_times']) for app in apps]
    plt.bar(apps, avg_inter_arrival_times)
    plt.title('Average Inter-arrival Times Comparison')
    plt.xlabel('Application')
    plt.ylabel('Average Inter-arrival Time (seconds)')
    plt.show()

    # Plot Flow Volume
    flow_volumes = [data[app]['flow_volume'] for app in apps]
    plt.figure(figsize=(10, 6))
    plt.bar(apps, flow_volumes)
    plt.title('Flow Volume Comparison')
    plt.xlabel('Application')
    plt.ylabel('Flow Volume (bytes)')
    plt.show()

    # Plot Flow Size
    flow_sizes = [data[app]['flow_size'] for app in apps]
    plt.figure(figsize=(10, 6))
    plt.bar(apps, flow_sizes)
    plt.title('Flow Size Comparison')
    plt.xlabel('Application')
    plt.ylabel('Flow Size (Number of Packets)')
    plt.show()

    # Plot Protocol Distribution (TCP, UDP, HTTP, HTTP2, TLS)
    protocol_labels = ['TCP', 'UDP', 'HTTP', 'HTTP2', 'TLS']
    for app in apps:
        protocol_counts = [data[app]['protocol_distribution'].get(proto, 0) for proto in protocol_labels]
        total_protocols = sum(protocol_counts)
        protocol_percentages = [count / total_protocols * 100 if total_protocols > 0 else 0 for count in protocol_counts]

        # Plot the distribution
        plt.figure(figsize=(10, 6))
        plt.bar(protocol_labels, protocol_percentages)
        plt.title(f'Protocol Distribution for {app}')
        plt.xlabel('Protocol')
        plt.ylabel('Percentage Usage (%)')
        plt.show()


# Main function to run the analysis and plotting
def main():
    # Define your PCAP files and corresponding key files (if any)
    pcap_files = {
        'Spotify': ('spotify.pcapng', 'spotify.txt'),
        'Chrome': ('chrome.pcapng', 'chrome.txt'),
        'Firefox': ('firefox.pcapng', 'firefox.txt'),
        'YouTube': ('youtube.pcapng', 'youtube.txt'),
        'Zoom': ('zoom.pcapng', None)  # No key file for Zoom
    }

    # Analyze the traffic and extract the data
    data = analyze_traffic(pcap_files)

    # Plot the extracted data for comparison
    plot_data(data)


if __name__ == "__main__":
    main()
