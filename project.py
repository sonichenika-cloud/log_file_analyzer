from datetime import datetime

class LogAnalyzer:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.failed_attempts = [] 

    def parse_logs(self):
        with open(self.log_file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue                
                parts = line.split(" ")                
                if len(parts) >= 6:
                    timestamp_str = f"{parts[0]} {parts[1]}"
                    ip_address = parts[2]
                    status_code = parts[5]
                  
                    if status_code == "401":
                        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        self.failed_attempts.append({
                            "ip": ip_address,
                            "timestamp": timestamp
                        })

    def detect_brute_force(self, threshold=5, time_window_seconds=60):
        
        ip_map = {}
        for entry in self.failed_attempts:
            ip = entry["ip"]
            if ip not in ip_map:
                ip_map[ip] = []
            ip_map[ip].append(entry["timestamp"])

        flagged_ips = {}
    
        for ip, timestamps in ip_map.items():
            timestamps.sort()
            left = 0
            for right in range(len(timestamps)):               
                while (timestamps[right] - timestamps[left]).total_seconds() > time_window_seconds:
                    left += 1
                current_window_count = right - left + 1
                if current_window_count >= threshold:
                    flagged_ips[ip] = {
                        "failed_count": current_window_count,
                        "time_span_seconds": int((timestamps[right] - timestamps[left]).total_seconds())
                    }
        return flagged_ips

if __name__ == "__main__":
    analyzer = LogAnalyzer("server.log")
    
    analyzer.parse_logs()
    
    security_alerts = analyzer.detect_brute_force(threshold=5, time_window_seconds=60)

    print("\n" + "="*45)
    print("      SECURITY ALERT REPORT")
    print("="*45)
    if security_alerts:
        for ip, details in security_alerts.items():
            print(f"[ALERT] Potential Brute-Force Attack Detected!")
            print(f" - Flagged IP: {ip}")
            print(f" - Failed Attempts: {details['failed_count']}")
            print(f" - Window Duration: {details['time_span_seconds']} seconds\n")
    else:
        print("No suspicious activity detected.")