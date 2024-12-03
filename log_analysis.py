import re
import csv
from collections import defaultdict, Counter

# Define constants
LOG_FILE = "sample.log"
OUTPUT_CSV = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Parse the log file and extract relevant data."""
    ip_requests = Counter()
    endpoint_access = Counter()
    failed_logins = defaultdict(int)
    
    with open(file_path, 'r') as file:
        for line in file:
            # Extract IP address and endpoint
            match = re.match(r'(\d+\.\d+\.\d+\.\d+).*?"\w+ (/[\w/]+).*?" (\d+)', line)
            if match:
                ip, endpoint, status = match.groups()
                ip_requests[ip] += 1
                endpoint_access[endpoint] += 1
                if status == "401":
                    failed_logins[ip] += 1
                    
    return ip_requests, endpoint_access, failed_logins

def find_most_accessed_endpoint(endpoint_access):
    """Find the most accessed endpoint."""
    return endpoint_access.most_common(1)[0] if endpoint_access else ("None", 0)

def detect_suspicious_activity(failed_logins):
    """Detect IPs with failed login attempts exceeding the threshold."""
    return {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

def save_to_csv(ip_requests, most_accessed, suspicious_ips):
    """Save the results to a CSV file."""
    with open(OUTPUT_CSV, 'w', newline='') as file:
        writer = csv.writer(file)
        
        # Write IP requests section
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        writer.writerow([])
        
        # Write most accessed endpoint section
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])
        
        # Write suspicious activity section
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    # Parse the log file
    ip_requests, endpoint_access, failed_logins = parse_log_file(LOG_FILE)
    
    # Sort IP requests by request count in descending order
    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    
    # Most accessed endpoint
    most_accessed = find_most_accessed_endpoint(endpoint_access)
    
    # Suspicious activity
    suspicious_ips = detect_suspicious_activity(failed_logins)
    
    # Display results
    print("\nIP Address Request Counts (Sorted):")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count:<15}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20} {'Failed Login Attempts':<25}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count:<25}")
    else:
        print("No suspicious activity detected.")
    
    # Save results to CSV
    save_to_csv(dict(sorted_ip_requests), most_accessed, suspicious_ips)
    print(f"\nResults saved to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
