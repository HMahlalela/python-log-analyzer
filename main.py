import ipaddress
from datetime import datetime

valid_failed_logins = 0
malformed_entries = 0
invalid_ip_entries = 0
time_based_alerts = 0
login_pattern_alerts = 0

failed_logins = {}
login_times = {}
successful_logins = {}
successful_login_times = {}

try:
    with open("auth.log", "r") as file:
        for line in file:
            if "SUCCESSFUL LOGIN" in line:
                if "IP=" in line:
                    timestamp_text = line[:19]

                    try:
                        successful_timestamp = datetime.strptime(
                            timestamp_text, "%Y-%m-%d %H:%M:%S"
                        )

                    except ValueError:
                        malformed_entries += 1
                        print("Skipping successful login with invalid timestamp:", line.strip())
                        continue

                    parts = line.split("IP=")
                    ip_address = parts[1].strip()

                    try:
                        ipaddress.ip_address(ip_address)

                    except ValueError:
                        invalid_ip_entries += 1
                        print("Invalid IP address detected:", ip_address)
                        continue

                    if ip_address in successful_logins:
                        successful_logins[ip_address] += 1
                    else:
                        successful_logins[ip_address] = 1

                    if ip_address not in successful_login_times:
                        successful_login_times[ip_address] = []

                    successful_login_times[ip_address].append(successful_timestamp)

                else:
                    malformed_entries += 1
                    print("Skipping malformed successful login entry:", line.strip())
                    continue

            if "FAILED LOGIN" in line:
                if "IP=" in line:
                    parts = line.split("IP=")
                    ip_address = parts[1].strip()

                    try:
                        ipaddress.ip_address(ip_address)

                    except ValueError:
                        invalid_ip_entries += 1
                        print("Invalid IP address detected:", ip_address)
                        continue

                    timestamp_text = line[:19]

                    try:
                        timestamp = datetime.strptime(
                            timestamp_text, "%Y-%m-%d %H:%M:%S"
                        )

                    except ValueError:
                        malformed_entries += 1
                        print("Skipping entry with invalid timestamp:", line.strip())
                        continue

                    if ip_address not in login_times:
                        login_times[ip_address] = []

                    login_times[ip_address].append(timestamp)

                    valid_failed_logins += 1

                    if ip_address in failed_logins:
                        failed_logins[ip_address] += 1
                    else:
                        failed_logins[ip_address] = 1

                else:
                    malformed_entries += 1
                    print("Skipping malformed log entry:", line.strip())
                    continue

except FileNotFoundError:
    print("Error: auth.log was not found.")
    exit()
                
def check_security_status(attempts):
    if attempts > 10:
        return "HIGH RISK"
    elif attempts >= 5:
        return "WARNING"
    else:
        return "NORMAL"
    
def detect_brute_force(attempts):    
    if attempts > 10:
        return "POTENTIAL BRUTE-FORCE ATTACK"
    elif attempts >= 5:
        return "SUSPICIOUS LOGIN ACTIVITY"
    else:
        return "NO ALERT"
    
def detect_time_window_activity(timestamps):
    timestamps.sort()

    for start_index in range(len(timestamps)):
        attempts_in_window = 0

        for current_index in range(start_index, len(timestamps)):
            time_difference = timestamps[current_index] - timestamps[start_index]

            if time_difference.total_seconds() <= 300:
                attempts_in_window += 1
            else:
                break

        if attempts_in_window >= 5:
            return True

    return False

def detect_success_after_failures(failed_timestamps, successful_timestamps):
    failed_timestamps.sort()
    successful_timestamps.sort()

    for successful_time in successful_timestamps:
        failed_attempts_before_success = 0

        for failed_time in failed_timestamps:
            if failed_time < successful_time:
                failed_attempts_before_success += 1

        if failed_attempts_before_success >= 5:
            return "SUSPICIOUS LOGIN PATTERN"

    return "NO ALERT"
      
                
print("FAILED LOGIN SUMMARY")
print("---------------------")

# Count high-risk IP addresses
high_risk_ips = 0

for ip, attempts in failed_logins.items():
    status = check_security_status(attempts)
    alert = detect_brute_force(attempts)
    
    timestamps = login_times[ip]
    time_window_alert = detect_time_window_activity(timestamps)
    
    successful_attempts = successful_logins.get(ip, 0)
    failed_timestamps = login_times.get(ip, [])
    successful_timestamps = successful_login_times.get(ip, [])
    
    login_pattern_alert = detect_success_after_failures(
        failed_timestamps, successful_timestamps
    )
       
    if status == "HIGH RISK":
        high_risk_ips += 1
        
    if time_window_alert:
        time_based_alerts += 1
        
    if login_pattern_alert == "SUSPICIOUS LOGIN PATTERN":
        login_pattern_alerts += 1    

    print("IP Address:", ip)
    print("Failed attempts:", attempts)
    print("Security status:", status)
    print("Brute-force detection:", alert)
    print("Successful login attempts:", successful_attempts)
    print("Login pattern detection:", login_pattern_alert)
    
    if time_window_alert:
        print("Time-based detection: SUSPICIOUS")
    else:
        print("Time-based detection: NO ALERT")
    
    print("---------------------")
    
print("\nOVERALL SECURITY SUMMARY")
print("-------------------------")
print("Total unique IP addresses:", len(failed_logins))
print("High-risk IP addresses:", high_risk_ips)
print("Time-based alerts:", time_based_alerts)
print("Suspicious login-pattern alerts:", login_pattern_alerts)    
    
# Identify the IP address with the most failed attempts
most_failed_ip = None
highest_attempts = 0

for ip, attempts in failed_logins.items():
    if attempts > highest_attempts:
        highest_attempts = attempts
        most_failed_ip = ip
        
print("\nMOST ACTIVE IP ADDRESS")
print("----------------------")
print("IP Address:", most_failed_ip)
print("Failed attempts:", highest_attempts)

# Calculate high-risk IP percentage
total_ips = len(failed_logins)

if total_ips > 0:
    high_risk_percentage = (high_risk_ips / total_ips) * 100
else:
    high_risk_percentage = 0
    
# Display high-risk statistics 
print("\nHIGH-RISK IP STATISTICS")
print("-----------------------")
print("High-risk IP addresses:", high_risk_ips)
print("Total unique IP addresses:", total_ips)
print(f"High-risk IP percentage: {high_risk_percentage:.2f}%")
   
# Display log analysis statistics
print("\nLOG ANALYSIS STATISTICS")
print("-----------------------")
print("Valid failed login entries:", valid_failed_logins)
print("Malformed entries skipped:", malformed_entries)
print("Invalid IP addresses rejected:", invalid_ip_entries)
    
