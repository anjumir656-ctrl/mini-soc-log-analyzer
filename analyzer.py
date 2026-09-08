from collections import Counter


LOG_FILE = "sample_logs/auth.log"
FAILED_LOGIN = "LOGIN_FAILED"


def load_logs(filename):
    logs = []

    with open(filename, "r") as file:
        for line in file:
            parts = line.strip().split()

            if len(parts) < 5:
                continue

            logs.append({
                "timestamp": f"{parts[0]} {parts[1]}",
                "event": parts[2],
                "user": parts[3].split("=")[1],
                "ip": parts[4].split("=")[1]
            })

    return logs


def analyze_logs(logs):
    failed = [
        log for log in logs
        if log["event"] == FAILED_LOGIN
    ]

    ip_counts = Counter(log["ip"] for log in failed)

    alerts = []

    for ip, count in ip_counts.items():

        if count >= 5:
            severity = "HIGH"
        elif count >= 3:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        alerts.append({
            "ip": ip,
            "failed_attempts": count,
            "severity": severity
        })

    return failed, alerts


def main():
    print("=" * 50)
    print("          MINI SOC LOG ANALYZER")
    print("=" * 50)

    logs = load_logs(LOG_FILE)
    failed, alerts = analyze_logs(logs)

    print(f"\nTotal Events  : {len(logs)}")
    print(f"Failed Logins : {len(failed)}")

    print("\nSecurity Alerts")
    print("-" * 50)

    for alert in alerts:
        print(
            f"IP: {alert['ip']} | "
            f"Attempts: {alert['failed_attempts']} | "
            f"Severity: {alert['severity']}"
        )

    print("\nAnalysis completed successfully.")


if __name__ == "__main__":
    main()
