import A
import os

def main():
    src_dir = os.path.abspath('src')
    print(f"Source directory: {src_dir}")

    pcap_files = {
        'Spotify': os.path.join('spotify.pcapng'),
        'Chrome': os.path.join('chrome.pcapng'),
        'Firefox': os.path.join('firefox.pcapng'),
        'YouTube': os.path.join('youtube.pcapng'),
        'Zoom': os.path.join('zoom.pcapng'),
    }

    for app, filepath in pcap_files.items():
        print(f"Analyzing {app}: {filepath}")
        if not os.path.exists(filepath):
            print(f"Error: File not found - {filepath}")
            return # Exit the function if any file is missing.

    try:
        data = A.analyze_ip_headers(pcap_files) # Removed tls_key_files argument
        A.plot_ip_data(data)
        print("Analysis and plotting complete.")
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()