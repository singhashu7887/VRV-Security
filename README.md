
# Log File Analysis Tool

This tool parses a log file, analyzes its contents, and extracts key insights, such as:
- Number of requests made by each IP address, sorted in descending order of request counts.
- The most frequently accessed endpoint.
- Detection of suspicious activities, such as IPs with excessive failed login attempts.

## Features
1. **IP Request Analysis**: Counts and sorts requests made by IP addresses.
2. **Endpoint Usage**: Identifies the most accessed endpoint.
3. **Suspicious Activity Detection**: Flags IPs with failed login attempts exceeding a configurable threshold.
4. **CSV Report Generation**: Saves the analysis results to a CSV file.

## Requirements
- Python 3.x
- Log file in the appropriate format

## Installation
Clone or download this repository.

## Usage
1. Place your log file in the same directory as the script and rename it to `sample.log` (or update the `LOG_FILE` variable in the script).
2. Run the script:
    ```bash
    python script_name.py
    ```
3. The analysis results will be displayed in the terminal and saved in `log_analysis_results.csv`.

## Configuration
- **Log File**: Update the `LOG_FILE` variable to point to your log file.
- **Failed Login Threshold**: Adjust the `FAILED_LOGIN_THRESHOLD` variable to change the sensitivity of suspicious activity detection.

## Output
- **Terminal**: Displays the sorted list of IP request counts, most accessed endpoint, and any suspicious activity detected.
- **CSV File**: Includes the following sections:
  - Requests per IP (sorted by request count)
  - Most Accessed Endpoint
  - Suspicious Activity Detected

## Example
### Input Log File (`sample.log`)
```
192.168.1.1 - - [01/Dec/2024:10:15:32 +0000] "GET /home HTTP/1.1" 200
192.168.1.2 - - [01/Dec/2024:10:15:33 +0000] "POST /login HTTP/1.1" 401
192.168.1.1 - - [01/Dec/2024:10:15:34 +0000] "GET /dashboard HTTP/1.1" 200
```

### Command
```bash
python script_name.py
```

### Terminal Output
```
IP Address Request Counts (Sorted):
192.168.1.1           2              
192.168.1.2           1              

Most Frequently Accessed Endpoint:
/home (Accessed 1 times)

Suspicious Activity Detected:
192.168.1.2           1              

Results saved to log_analysis_results.csv
```

## License
This project is licensed under the MIT License.
