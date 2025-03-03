import pyshark
import pandas as pd
import numpy as np
import os
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder


def extract_packets_from_file(pcap_file, app_label):
    """
    Extract packets from a PCAPNG file and create a DataFrame.
    Each packet's flow ID, timestamp, size, and protocol are captured.
    """
    capture = pyshark.FileCapture(pcap_file, keep_packets=False, use_json=True)
    packet_list = []
    previous_time = None

    try:
        for pkt in capture:
            flow_id = generate_flow_identifier(pkt)
            timestamp = float(pkt.sniff_time.timestamp())
            pkt_size = int(pkt.length)
            time_diff = calculate_time_diff(pkt, previous_time)
            previous_time = timestamp
            protocol_type = pkt.transport_layer if hasattr(pkt, 'transport_layer') else 'None'

            packet_list.append({
                'Flow_ID': flow_id,
                'Protocol': protocol_type,
                'Packet_Size': pkt_size,
                'Time_Diff': time_diff,
                'Timestamp': timestamp,
                'App_Label': app_label
            })
    finally:
        capture.close()

    df = pd.DataFrame(packet_list)
    label_encoder = LabelEncoder()
    df['Flow_ID'] = label_encoder.fit_transform(df['Flow_ID'].astype(str))
    return df


def generate_flow_identifier(pkt):
    """
    Generate a unique identifier for each flow based on source IP, destination IP,
    source port, destination port, and transport protocol.
    """
    try:
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        src_port = pkt[pkt.transport_layer].srcport
        dst_port = pkt[pkt.transport_layer].dstport
        protocol = pkt.transport_layer
        return f"{src_ip}_{dst_ip}_{src_port}_{dst_port}_{protocol}"
    except AttributeError:
        return None


def calculate_time_diff(pkt, last_time):
    """
    Calculate the time difference between the current packet and the previous one.
    Returns 0.0 if there is no previous packet.
    """
    if last_time is None:
        return 0.0
    return float(pkt.sniff_time.timestamp() - last_time)


def process_pcap_files(pcap_files, output_dir):
    """
    Combine multiple PCAPNG files into one DataFrame and save the result as CSV.
    Each file is processed individually with its own app label.
    """
    combined_data = []
    for pcap_file in pcap_files:
        app_label = os.path.splitext(os.path.basename(pcap_file))[0]
        print(f"Analyzing data from pcapng file: {pcap_file}")
        df = extract_packets_from_file(pcap_file, app_label)
        combined_data.append(df)
    combined_df = pd.concat(combined_data, ignore_index=True)
    output_file = os.path.join(output_dir, "all_csv_data.csv")
    combined_df.to_csv(output_file, index=False)
    print(f"pcapng file data was saved")


def build_random_forest_model(X_train, y_train):
    """
    Create and train a Random Forest model using the given training data.
    """
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    return model


def evaluate_model(model, X_test, y_test):
    """
    Evaluate the trained model using the test data.
    Returns the model's predictions and accuracy score.
    """
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions) * 100
    return predictions, accuracy


def prepare_for_comparison_plot(result_df, app_labels):
    """
    Prepare the actual and predicted counts for accuracy comparison plots.
    Returns counts for actual, predicted (with flow ID), and predicted (without flow ID).
    """
    actual_counts = result_df["Actual_Label"].value_counts().reindex(app_labels, fill_value=0)
    predicted_counts_with_flowid = result_df["Predicted_With_Flow_ID"].value_counts().reindex(app_labels, fill_value=0)
    predicted_counts_without_flowid = result_df["Predicted_Without_Flow_ID"].value_counts().reindex(app_labels, fill_value=0)
    return actual_counts, predicted_counts_with_flowid, predicted_counts_without_flowid


def plot_comparison(actual_counts, predicted_counts_with_flowid, predicted_counts_without_flowid, app_labels):
    """
    Create and save side-by-side bar plots comparing actual vs predicted results
    for both models (with and without flow ID).
    """
    position_x = np.arange(len(app_labels))
    width_of_bars = 0.25
    figure, axes = plt.subplots(1, 2, figsize=(14, 6))
    axes[0].bar(position_x - width_of_bars / 2, actual_counts, width_of_bars, label="Actual result", color="#FF0000")
    axes[0].bar(position_x + width_of_bars / 2, predicted_counts_with_flowid, width_of_bars, label="Expected result", color="#008000")
    axes[0].set_title("Model with Flow Identifier (Scenario 1)")
    axes[1].bar(position_x - width_of_bars / 2, actual_counts, width_of_bars, label="Actual result", color="#FF0000")
    axes[1].bar(position_x + width_of_bars / 2, predicted_counts_without_flowid, width_of_bars, label="Expected result", color="#008000")
    axes[1].set_title("Model without Flow Identifier (Scenario 2)")
    for ax in axes:
        ax.set_xlabel("Apps")
        ax.set_ylabel("Packet count")
        ax.set_xticks(position_x)
        ax.set_xticklabels(app_labels, rotation=45, ha="right")
        ax.legend()
        ax.grid(axis='y', linestyle='--', alpha=0.9)
    plt.tight_layout()
    # Ensure 'attacker_plots' folder exists
    plot_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'res', 'attacker_plots')
    os.makedirs(plot_directory, exist_ok=True)
    plot_filename = os.path.join(plot_directory, "Accuracy_Comparison_Graph.png")
    plt.savefig(plot_filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Graph saved")



def prepare_features_for_training(dataframe):
    """
    Prepare the features (with and without flow ID) for training the model.
    Splits the data into training and testing sets.
    """
    dataframe = pd.get_dummies(dataframe, columns=['Protocol'], drop_first=True)
    features_with_flowid = ["Packet_Size", "Time_Diff", "Flow_ID"] + [col for col in dataframe.columns if col.startswith('Protocol_')]
    features_without_flowid = ["Packet_Size", "Time_Diff"]
    target_column = "App_Label"
    training_data_with_flowid, testing_data_with_flowid, label_train_with_flowid, label_test_with_flowid = train_test_split(
        dataframe[features_with_flowid], dataframe[target_column], test_size=0.2, random_state=42
    )
    training_data_without_flowid, testing_data_without_flowid, label_train_without_flowid, label_test_without_flowid = train_test_split(
        dataframe[features_without_flowid], dataframe[target_column], test_size=0.2, random_state=42
    )
    return (training_data_with_flowid, testing_data_with_flowid, label_train_with_flowid, label_test_with_flowid), (training_data_without_flowid, testing_data_without_flowid, label_train_without_flowid, label_test_without_flowid)


def main_process(pcap_files, output_dir):
    """
    Main process for reading PCAP files, training models, and generating plots.
    """
    process_pcap_files(pcap_files, output_dir)
    combined_data_file = os.path.join(output_dir, "all_csv_data.csv")
    dataset = pd.read_csv(combined_data_file)
    (X_train_with_flowid, X_test_with_flowid, y_train_with_flowid, y_test_with_flowid), (X_train_without_flowid, X_test_without_flowid, y_train_without_flowid, y_test_without_flowid) = prepare_features_for_training(dataset)
    model_with_flowid = build_random_forest_model(X_train_with_flowid, y_train_with_flowid)
    model_without_flowid = build_random_forest_model(X_train_without_flowid, y_train_without_flowid)
    predictions_with_flowid, accuracy_with_flowid = evaluate_model(model_with_flowid, X_test_with_flowid, y_test_with_flowid)
    predictions_without_flowid, accuracy_without_flowid = evaluate_model(model_without_flowid, X_test_without_flowid, y_test_without_flowid)
    print(f"Accuracy with Flow Identifier (Scenario 1): {accuracy_with_flowid:.2f}%")
    print(f"Accuracy without Flow Identifier (Scenario 2): {accuracy_without_flowid:.2f}%")
    # Preparing results for the comparison plot
    result_df = X_test_with_flowid.copy()
    result_df["Actual_Label"] = y_test_with_flowid
    result_df["Predicted_With_Flow_ID"] = predictions_with_flowid
    result_df["Predicted_Without_Flow_ID"] = predictions_without_flowid
    app_labels = sorted(result_df["Actual_Label"].unique())
    actual_counts, predicted_counts_with_flowid, predicted_counts_without_flowid = prepare_for_comparison_plot(result_df, app_labels)
    plot_comparison(actual_counts, predicted_counts_with_flowid, predicted_counts_without_flowid, app_labels)


# Entry point of the script
if __name__ == "__main__":
    pcap_files_list = [
        "chrome.pcapng",
        "youtube.pcapng",
        "zoom.pcapng",
        "spotify.pcapng",
        "firefox.pcapng"
    ]

    output_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'res')
    main_process(pcap_files_list, output_directory)
