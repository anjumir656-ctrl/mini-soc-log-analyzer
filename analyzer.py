from collections import Counter
import csv
import os

LOG_FILE = "sample_logs/auth.log"
REPORT_FILE = "reports/security_report.csv"


def load_logs(filename):
    logs = []

    with open(filename, "r") as file:
        for line in file:
            parts = line.strip().split()

            if len(parts) < 5:
                continue

            logs.append({
                "timestamp": parts[0] + " " + parts[1],
                "event": parts[2],
                "user": parts[3].split("=")[1],
                "ip": parts[4].split("=")[1]
            })

    return logs


def analyze_logs(logs):
    failed = [
        log for log in logs
        if log["event"] == "LOGIN_FAILED"
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
            "attempts": count,
            "severity": severity
        })

    return alerts


def save_report(alerts):
    os.makedirs("reports", exist_ok=True)

    with open(REPORT_FILE, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow(["IP", "Failed Attempts", "Severity"])

        for alert in alerts:
            writer.writerow([
                alert["ip"],
                alert["attempts"],
                alert["severity"]
            ])


def main():
    print("=" * 50)
    print("          MINI SOC LOG ANALYZER")
    print("=" * 50)

    logs = load_logs(LOG_FILE)
    alerts = analyze_logs(logs)

    print(f"\nTotal Events : {len(logs)}")
    print("\nSecurity Alerts")
    print("-" * 50)

    for alert in alerts:
        print(
            f"IP: {alert['ip']} | "
            f"Attempts: {alert['attempts']} | "
            f"Severity: {alert['severity']}"
        )

    save_report(alerts)

    print("\nSecurity report generated successfully.")


if __name__ == "__main__":
    main()
