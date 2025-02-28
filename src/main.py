import os
import A  # Import the logic for analysis from A.py
import B  # Import the logic for analysis and plotting from B.py

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
            print(f"❌ Error: File not found - {pcap_path}")
            return  # Exit if any file is missing.

        if key_file and not os.path.exists(key_path):
            print(f"Warning: No TLS key file found for {app}, decryption might fail.")

    # Prompt the user to choose between running A or B
    choice = input("Choose an option: \n1. Run A (Analysis + Plotting)\n2. Run B (Plotting Only)\nEnter 1 or 2: ").strip()

    if choice == '1':
        # Run the analysis and plotting (A)
        try:
            data = A.analyze_ip_headers({app: (os.path.join(src_dir, p), os.path.join(src_dir, k) if k else None) for app, (p, k) in pcap_files.items()})
            A.plot_ip_data(data)
            print("Analysis and plotting complete.")
        except FileNotFoundError as e:
            print(f"❌ Error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
    elif choice == '2':
        # Run only plotting (B)
        try:
            B.run_analysis({app: (os.path.join(src_dir, p), os.path.join(src_dir, k) if k else None) for app, (p, k) in pcap_files.items()})
            print("Plotting complete.")
        except Exception as e:
            print(f"An error occurred during plotting: {e}")
    else:
        print("Invalid choice. Please enter 1 or 2.")

if __name__ == "__main__":
    main()
