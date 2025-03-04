# Traffic Analysis and Visualization

The project has two parts:
1. **Packet Analyzer**: This part analyzes data from PCAPNG files and their corresponding key files.
2. **Attacker Perspective**: This part simulates an attacker's perspective by using a model to determine if an attacker can identify which application you used based on two scenarios: 
   - Scenario 1: With Flow ID.
   - Scenario 2: Without Flow 

## Requirements

Ensure you have the following Python libraries installed:
- `os`
- `pyshark`
- `matplotlib`
- `numpy`
- `collections` (defaultdict, Counter)
- `pandas`
- `sklearn`

You can install the necessary libraries using the following command:
```bash
pip install pyshark matplotlib numpy pandas scikit-learn
````



Input Files
The following PCAP files and corresponding key files (if available) should be placed in the ````src```` directory:
```
spotify.pcapng

spotify.txt

chrome.pcapng

chrome.txt

firefox.pcapng

firefox.txt

youtube.pcapng

youtube.txt

zoom.pcapng

zoom.txt
```

## How to Run

1. Clone the repository and navigate to the project directory.


2. Ensure the PCAP files and key files are placed in the src directory.


3. Run the following command to execute the analysis and generate the plots or go to the `packet_analyzer.py` file and run from the run button:

````bash
python packet_analyzer.py
````

4. To run the `attacker_pov.py script`, use the following command or go to the `attacker_pov.py` file and press the run button:
````bash
python attacker_pov.py
````



## Output
The analysis results for the `packet_analyzer.py` will be saved as plots in the res/analyzed_data_plots directory. The following plots will be generated:
````
protocol_distribution_comparison_percentages.png: Protocol distribution across applications (percentages).

avg_ttl.png: Average TTL comparison.

tls_versions.png: TLS versions used across applications.

avg_packet_sizes.png: Average packet sizes comparison.

flow_size.png: Flow size comparison.

flow_volume.png: Flow volume comparison.

avg_inter_arrival_times.png: Average inter-arrival time comparison.
````

The analysis results for the `attacker_pov.py```` will be saved as a plot and a csv containing all the pcapng data, the csv will be stored in res and the plot in res/attacker_plots:
````
Accuracy_Comparison_Graph.png: Model accuracy comparison (with and without flow ID).

all_csv_data.csv: (csv that has all the data from the pcapng files).
````

## Functions for packet_analyzer.py

### analyze_traffic(pcap_files)

This function analyzes the network traffic data from the provided PCAP files and extracts various metrics.

#### Parameters:
pcap_files (dict): Dictionary containing application names as keys and tuples of PCAP file paths and key file paths as values.

#### Returns:
data (defaultdict): Nested dictionary containing the extracted metrics for each application.

### plot_data(data)
This function generates plots based on the extracted metrics and saves them in the res/analyzed_data_plots directory.

#### Parameters:
data (defaultdict): Nested dictionary containing the extracted metrics for each application.

## Functions for attacker_pov.py

### extract_packets_from_file(pcap_file, app_label)

This function extracts packets from a PCAPNG file and creates a DataFrame. Each packet's flow ID, timestamp, size, and protocol are captured.

#### Parameters:
- `pcap_file` (str): Path to the PCAP file.
- `app_label` (str): Label for the application.

#### Returns:
- `df` (DataFrame): DataFrame containing the extracted packet data.

### generate_flow_identifier(pkt)

This function generates a unique identifier for each flow based on source IP, destination IP, source port, destination port, and transport protocol.

#### Parameters:
- `pkt` (Packet): Packet from the PCAP file.

#### Returns:
- `flow_id` (str): Unique flow identifier.

### calculate_time_diff(pkt, last_time)

This function calculates the time difference between the current packet and the previous one. Returns 0.0 if there is no previous packet.

#### Parameters:
- `pkt` (Packet): Packet from the PCAP file.
- `last_time` (float): Timestamp of the previous packet.

#### Returns:
- `time_diff` (float): Time difference between the current packet and the previous one.

### process_pcap_files(pcap_files, output_dir)

This function combines multiple PCAPNG files into one DataFrame and saves the result as CSV. Each file is processed individually with its own app label.

#### Parameters:
- `pcap_files` (list): List of PCAP file paths.
- `output_dir` (str): Directory to save the output CSV file.

### build_random_forest_model(training_features, training_labels)

This function creates and trains a Random Forest model using the given training data.

#### Parameters:
- `training_features` (DataFrame): Training features for the model.
- `training_labels` (Series): Training labels for the model.

#### Returns:
- `model` (RandomForestClassifier): Trained Random Forest model.

### evaluate_model(model, testing_features, testing_labels)

This function evaluates the trained model using the test data. Returns the model's predictions and accuracy score.

#### Parameters:
- `model` (RandomForestClassifier): Trained Random Forest model.
- `testing_features` (DataFrame): Testing features for the model.
- `testing_labels` (Series): Testing labels for the model.

#### Returns:
- `predictions` (ndarray): Model predictions.
- `accuracy` (float): Model accuracy score.

### prepare_for_comparison_plot(result_df, app_labels)

This function prepares the actual and predicted counts for accuracy comparison plots. Returns counts for actual, predicted (with flow ID), and predicted (without flow ID).

#### Parameters:
- `result_df` (DataFrame): DataFrame containing actual and predicted labels.
- `app_labels` (list): List of application labels.

#### Returns:
- `actual_counts` (Series): Actual label counts.
- `predicted_counts_with_flowid` (Series): Predicted label counts (with flow ID).
- `predicted_counts_without_flowid` (Series): Predicted label counts (without flow ID).

### plot_comparison(actual_counts, predicted_counts_with_flowid, predicted_counts_without_flowid, app_labels)

This function creates and saves side-by-side bar plots comparing actual vs predicted results for both models (with and without flow ID).

#### Parameters:
- `actual_counts` (Series): Actual label counts.
- `predicted_counts_with_flowid` (Series): Predicted label counts (with flow ID).
- `predicted_counts_without_flowid` (Series): Predicted label counts (without flow ID).
- `app_labels` (list): List of application labels.

### prepare_features_for_training(dataframe)

This function prepares the features (with and without flow ID) for training the model. Splits the data into training and testing sets.

#### Parameters:
- `dataframe` (DataFrame): DataFrame containing the extracted packet data.

#### Returns:
- `(training_data_with_flowid, testing_data_with_flowid, training_labels_with_flowid, testing_labels_with_flowid), (training_data_without_flowid, testing_data_without_flowid, training_labels_without_flowid, testing_labels_without_flowid)` (tuple): Training and testing features and labels.

### main_process(pcap_files, output_dir)

This function is the main process for reading PCAP files, training models, and generating plots.

#### Parameters:
- `pcap_files` (list): List of PCAP file paths.
- `output_dir` (str): Directory to save the output CSV file and plots.


