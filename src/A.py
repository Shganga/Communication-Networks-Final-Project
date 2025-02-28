import pyshark
import matplotlib.pyplot as plt
import numpy as np
import os


def analyze_ip_headers(pcap_files):
    data = {}

    for app, (pcap_filename, key_filename) in pcap_files.items():
        pcap_path = os.path.join('src', pcap_filename)
        key_path = os.path.join('src', key_filename) if key_filename else None

        if not os.path.exists(pcap_path):
            print(f"❌ Error: PCAP file not found - {pcap_path}")
            continue
        if key_filename and not os.path.exists(key_path):
            print(f"⚠️ Warning: TLS key file not found - {key_path}")

        ip_versions, ttls, protocols, lengths, dscps = [], [], [], [], []
        layer7_protocols = {"HTTP": 0, "HTTP2": 0, "TLS": 0, "DNS": 0, "HTTPS": 0, "Unknown": 0}

        try:
            # Decrypt if key file exists
            capture = pyshark.FileCapture(
                pcap_path,
                override_prefs={"tls.keylog_file": key_path} if key_path else None
            )

            for packet in capture:
                # ✅ Extract IP information (IPv4/IPv6)
                if 'IP' in packet:
                    ip_layer = packet.ip
                    ip_versions.append(int(ip_layer.version))
                    ttls.append(int(ip_layer.ttl))
                    protocols.append(int(ip_layer.proto))
                    lengths.append(int(ip_layer.len))
                    dscps.append(int(ip_layer.dsfield, 16) if hasattr(ip_layer, 'dsfield')
                                 else int(ip_layer.tos, 16) if hasattr(ip_layer, 'tos') else 0)

                # ✅ Identify Layer 4 Protocols (TCP, UDP, ICMP)
                if 'TCP' in packet:
                    protocols.append(6)  # TCP Protocol Number
                elif 'UDP' in packet:
                    protocols.append(17)  # UDP Protocol Number
                elif 'ICMP' in packet:
                    protocols.append(1)  # ICMP Protocol Number

                # ✅ Identify Layer 7 Protocols (HTTP, HTTP2, TLS, DNS, HTTPS)
                if 'HTTP' in packet:
                    layer7_protocols["HTTP"] += 1
                elif 'HTTP2' in packet:
                    layer7_protocols["HTTP2"] += 1
                elif 'TLS' in packet:
                    layer7_protocols["TLS"] += 1
                elif 'DNS' in packet:
                    layer7_protocols["DNS"] += 1
                elif 'HTTPS' in packet:
                    layer7_protocols["HTTPS"] += 1
                else:
                    layer7_protocols["Unknown"] += 1

            capture.close()

        except Exception as e:
            print(f"❌ Error processing {pcap_filename}: {e}")
            continue

        data[app] = {
            'ip_versions': ip_versions,
            'ttls': ttls,
            'protocols': protocols,
            'lengths': lengths,
            'dscps': dscps,
            'avg_ttl': np.mean(ttls) if ttls else 0,
            'avg_length': np.mean(lengths) if lengths else 0,
            'layer7_protocols': layer7_protocols
        }

    return data


def plot_ip_data(data):
    apps = list(data.keys())

    if not apps:
        print("⚠️ No data available for plotting.")
        return

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

    # 3. Protocol Distribution (TCP, UDP, ICMP)
    protocol_counts = {app: {6: 0, 17: 0, 1: 0} for app in apps}  # Adding ICMP (1)

    for app, app_data in data.items():
        for proto in app_data['protocols']:
            if proto in protocol_counts[app]:
                protocol_counts[app][proto] += 1

    protocols = ['TCP', 'UDP', 'ICMP']
    protocol_distribution = np.array([[protocol_counts[app][6], protocol_counts[app][17], protocol_counts[app][1]] for app in apps])

    # Adjusted bar_width to make the bars even thinner
    plt.figure(figsize=(10, 6))
    bar_width = 0.15  # Further decreased bar width
    index = np.arange(len(protocols))

    # Plot bars for each app without the extra UDP shift
    for i, app in enumerate(apps):
        plt.bar(index + i * bar_width, protocol_distribution[i], bar_width, label=app)

    plt.xlabel('Protocol')
    plt.ylabel('Packet Count')
    plt.title('Protocol Distribution')
    plt.xticks(index + bar_width * (len(apps) / 2 - 0.5), protocols, rotation=45, fontsize=12)  # Increased font size
    plt.legend(title='Applications')
    plt.tight_layout()
    plt.show()

    # 4. Layer 7 Protocol Distribution (HTTP, HTTP2, TLS, DNS, HTTPS)
    layer7_protocols = ["HTTP", "HTTP2", "TLS", "DNS", "HTTPS", "Unknown"]  # Removed QUIC from here
    layer7_counts = {app: {proto: 0 for proto in layer7_protocols} for app in apps}

    for app, app_data in data.items():
        for proto, count in app_data['layer7_protocols'].items():
            layer7_counts[app][proto] = count

    # Create bar plot where each protocol is placed next to each other
    plt.figure(figsize=(10, 6))
    bar_width = 0.15  # Adjusted bar width for clarity
    index = np.arange(len(layer7_protocols))

    for i, app in enumerate(apps):
        plt.bar(index + i * bar_width, [layer7_counts[app][proto] for proto in layer7_protocols], bar_width, label=app)

    plt.xlabel('Layer 7 Protocol')
    plt.ylabel('Packet Count')
    plt.title('Layer 7 Protocols')
    plt.xticks(index + bar_width * (len(apps) / 2 - 0.5), layer7_protocols, rotation=45, fontsize=12)  # Increased font size
    plt.legend(title='Applications')
    plt.tight_layout()
    plt.show()





