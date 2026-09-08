from collections import Counter

print("=" * 45)
print("        MINI SOC LOG ANALYZER")
print("=" * 45)

logs = [
    {"event": "LOGIN_FAILED", "user": "admin", "ip": "192.0.2.10"},
    {"event": "LOGIN_FAILED", "user": "admin", "ip": "192.0.2.10"},
    {"event": "LOGIN_FAILED", "user": "admin", "ip": "192.0.2.10"},
    {"event": "LOGIN_SUCCESS", "user": "amjid", "ip": "192.0.2.20"},
    {"event": "LOGIN_FAILED", "user": "admin", "ip": "192.0.2.10"},
]

failed_logins = [
    log for log in logs if log["event"] == "LOGIN_FAILED"
]

ip_counts = Counter(log["ip"] for log in failed_logins)

print(f"\nTotal Events    : {len(logs)}")
print(f"Failed Logins   : {len(failed_logins)}")

print("\nFailed Login Sources:")

for ip, count in ip_counts.items():
    if count >= 4:
        severity = "HIGH"
    elif count >= 2:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    print(f"IP: {ip} | Attempts: {count} | Severity: {severity}")

print("\nAnalysis completed successfully.")
