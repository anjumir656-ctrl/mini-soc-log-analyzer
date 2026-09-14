from collections import Counter
import csv
import os

LOG_FILE = "sample_logs/auth.log"
REPORT_FILE = "reports/security_report.csv"


def parse_log_line(line):
    parts = line.strip().split()

    if len(parts) < 5:
        return None

    try:
        timestamp = parts[0] + " " + parts[1]
        event = parts[2]

        fields = {}
        for part in parts[3:]:
            if "=" in part:
                key, value = part.split("=", 1)
                fields[key] = value

        if "user" not in fields or "ip" not in fields:
            return None

        return {
            "timestamp": timestamp,
            "event": event,
            "user": fields["user"],
            "ip": fields["ip"]
        }

    except Exception:
        return None


def load_logs(filename):
    logs = []

    try:
        with open(filename, "r") as file:
            for line in file:
                log = parse_log_line(line)

                if log is not None:
                    logs.append(log)

    except FileNotFoundError:
        print(f"Error: Log file not found: {filename}")

    return logs


def detect_failed_login_rule(logs):
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
            "rule": "Repeated Failed Login",
            "ip": ip,
            "attempts": count,
            "severity": severity,
            "reason": "Repeated failed login attempts detected"
        })

    return alerts


def detect_success_after_failures_rule(logs):
    alerts = []
    failed_by_ip = Counter()

    for log in logs:
        ip = log["ip"]

        if log["event"] == "LOGIN_FAILED":
            failed_by_ip[ip] += 1

        elif log["event"] == "LOGIN_SUCCESS":
            if failed_by_ip[ip] >= 3:
                alerts.append({
                    "rule": "Successful Login After Failures",
                    "ip": ip,
                    "attempts": failed_by_ip[ip],
                    "severity": "HIGH",
                    "reason": "Successful login detected after multiple failed attempts"
                })

            failed_by_ip[ip] = 0

    return alerts


def analyze_logs(logs):
    alerts = []

    alerts.extend(detect_failed_login_rule(logs))
    alerts.extend(detect_success_after_failures_rule(logs))

    return alerts


def save_report(alerts):
    os.makedirs("reports", exist_ok=True)

    with open(REPORT_FILE, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "Rule",
            "IP",
            "Failed Attempts",
            "Severity",
            "Reason"
        ])

        for alert in alerts:
            writer.writerow([
                alert["rule"],
                alert["ip"],
                alert["attempts"],
                alert["severity"],
                alert["reason"]
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
            f"Rule: {alert['rule']} | "
            f"IP: {alert['ip']} | "
            f"Attempts: {alert['attempts']} | "
            f"Severity: {alert['severity']}\n"
            f"Reason: {alert['reason']}"
        )

    save_report(alerts)

    print("\nSecurity report generated successfully.")


if __name__ == "__main__":
    main()

