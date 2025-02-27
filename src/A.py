import pyshark
import matplotlib.pyplot as plt
import numpy as np
import os

def analyze_ip_headers(pcap_files):
    data = {}
    for app, filename in pcap_files.items():
        capture = pyshark.FileCapture(filename)

        ip_versions = []
        ttls = []
        protocols = []
        lengths = []
        dscps = []

        for packet in capture:
            if 'IP' in packet:
                ip_layer = packet.ip
                ip_versions.append(int(ip_layer.version))
                ttls.append(int(ip_layer.ttl))
                protocols.append(int(ip_layer.proto))
                lengths.append(int(ip_layer.len))
                if hasattr(ip_layer, 'dsfield'):
                    dscps.append(int(ip_layer.dsfield, 16))
                elif hasattr(ip_layer, 'tos'):
                    dscps.append(int(ip_layer.tos, 16))
        capture.close()

        data[app] = {
            'ip_versions': ip_versions,
            'ttls': ttls,
            'protocols': protocols,
            'lengths': lengths,
            'dscps': dscps,
            'avg_ttl': np.mean(ttls) if ttls else 0,
            'avg_length': np.mean(lengths) if lengths else 0,
        }
    return data

def plot_ip_data(data):
    apps = list(data.keys())

    # 1. Average Packet Size
    plt.figure(figsize=(10, 6))
    avg_lengths = [data[app]['avg_length'] for app in apps]
    plt.bar(apps, avg_lengths, color='skyblue')
    plt.title('Average Packet Size')
    plt.ylabel('Average Packet Size (bytes)')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.show()

    # 2. Average TTL
    plt.figure(figsize=(10, 6))
    avg_ttls = [data[app]['avg_ttl'] for app in apps]
    plt.bar(apps, avg_ttls, color='lightgreen')
    plt.title('Average TTL')
    plt.ylabel('Average TTL')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.show()

    # 3. Common Protocol Distribution (TCP, UDP, HTTP, ICMP, ICMPv6, etc.)
    common_protocols = {
        1: 'ICMP',    # ICMP
        6: 'TCP',     # TCP
        17: 'UDP',    # UDP
        80: 'HTTP',   # HTTP
        443: 'HTTPS', # HTTPS
        53: 'DNS',    # DNS
        58: 'ICMPv6'  # ICMPv6
    }

    protocol_counts = {app: {proto: 0 for proto in common_protocols} for app in apps}

    # Count the common protocols for each application
    for app, app_data in data.items():
        for proto in app_data['protocols']:
            if proto in common_protocols:
                protocol_counts[app][proto] += 1

    # Prepare data for plotting
    protocols = list(common_protocols.values())
    protocol_distribution = np.array([[protocol_counts[app][proto] for proto in common_protocols] for app in apps])

    # Plotting the protocol distribution comparison
    plt.figure(figsize=(10, 6))
    bar_width = 0.15
    index = np.arange(len(protocols))

    # Plot each application's data
    for i, app in enumerate(apps):
        plt.bar(index + i * bar_width, protocol_distribution[i], bar_width, label=app)

    plt.xlabel('Protocol')
    plt.ylabel('Packet Count')
    plt.title('Common Protocol Distribution Comparison Across Applications')
    plt.xticks(index + bar_width * (len(apps) / 2 - 0.5), protocols, rotation=45)
    plt.legend(title='Applications')
    plt.tight_layout()
    plt.show()

