import A
import os

def main():
    src_dir = os.path.dirname(os.path.abspath(__file__))  # Get the correct directory of main.py
    print(f"Source directory: {src_dir}")

    pcap_files = {
        'Spotify': ('spotify.pcapng', 'spotify.txt'),
        'Chrome': ('chrome.pcapng', 'chrome.txt'),
        'Firefox': ('firefox.pcapng', 'firefox.txt'),
        'YouTube': ('youtube.pcapng', 'youtube.txt'),
        'Zoom': ('zoom.pcapng', None)  # No key file for Zoom
    }

    # Convert filenames to absolute paths
    for app, (pcap_file, key_file) in pcap_files.items():
        pcap_path = os.path.join(src_dir, pcap_file)  # No extra 'src'
        key_path = os.path.join(src_dir, key_file) if key_file else None

        print(f"Analyzing {app}: {pcap_path}")

        if not os.path.exists(pcap_path):
            print(f"Error: File not found - {pcap_path}")
            return  # Exit if any file is missing.

        if key_file and not os.path.exists(key_path):
            print(f"Warning: No TLS key file found for {app}, decryption might fail.")

    try:
        data = A.analyze_ip_headers({app: (os.path.join(src_dir, p), os.path.join(src_dir, k) if k else None) for app, (p, k) in pcap_files.items()})
        A.plot_ip_data(data)
        print("Analysis and plotting complete.")
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
