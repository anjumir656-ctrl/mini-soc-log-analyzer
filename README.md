# Mini SOC Log Analyzer

A Python-based defensive cybersecurity project that analyzes sample authentication logs and identifies suspicious failed-login activity.

## 🔐 Features

- Parses authentication logs
- Detects failed login attempts
- Counts failed attempts by IP address
- Assigns severity levels
- Generates a CSV security report
- Uses synthetic sample data for safe testing

## 🛠️ Technologies

- Python
- CSV
- Log Analysis
- Basic SOC Concepts
- Cybersecurity Fundamentals

## 📁 Project Structure

mini-soc-log-analyzer/
├── analyzer.py
├── sample_logs/
│   └── auth.log
├── reports/
│   └── security_report.csv
└── README.md

## ▶️ How to Run

python analyzer.py

## 📊 Example Detection

A source IP with multiple failed login attempts is identified and assigned a severity level based on the configured detection rules.

## 🎯 Purpose

This project was created to practice Python, log analysis, and basic Security Operations Center (SOC) concepts using safe, synthetic data.

## ⚠️ Disclaimer

This project is for educational and defensive cybersecurity purposes only. It uses synthetic sample logs and does not target real systems.

## 👤 Author

Amjid Ahmed
