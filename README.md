# Python Log Analyzer

## Overview

Python Log Analyzer is a beginner-level cybersecurity project developed using Python.

The program analyses authentication log files to identify suspicious login activity, detect potential brute-force attacks, and generate a security report based on failed and successful login attempts.

The project focuses on applying Python programming concepts to a practical cybersecurity scenario.

## Features

- Counts failed login attempts for each IP address.
- Classifies IP addresses based on failed login activity.
- Detects potential brute-force attacks.
- Identifies suspicious login patterns by checking whether multiple failed attempts occurred before a successful login.
- Detects repeated failed login attempts within a five-minute window.
- Validates IP addresses and timestamps.
- Handles malformed log entries without stopping the program.
- Generates an overall security summary.
- Calculates the percentage of high-risk IP addresses.
- Identifies the IP address with the highest number of failed login attempts.

## Technologies Used

- Python 3
- Python standard library:
  - `datetime` — timestamp parsing and time-based analysis.
  - `ipaddress` — IP address validation.
  - File handling — reading authentication logs.

## How to Run

### Requirements

- Python 3 installed on your computer.
- A code editor such as Visual Studio Code.

### Instructions

1. Clone or download this repository.
2. Open the project folder in Visual Studio Code.
3. Make sure `main.py` and `auth.log` are in the same folder.
4. Open the terminal.
5. Run the following command:

```bash
python main.py
```

## Limitations

This project is an educational implementation designed to demonstrate basic log analysis and cybersecurity concepts.

- It analyses sample authentication logs rather than monitoring a live system.
- Its detection rules use predefined thresholds.
- It does not use machine learning to classify suspicious activity.
- Its alerts indicate potentially suspicious behaviour and do not confirm that a security breach has occurred.

## Example Output

When the program runs, it generates a report containing:

- Failed login attempts grouped by IP address.
- Security classifications such as NORMAL, WARNING, and HIGH RISK.
- Potential brute-force alerts.
- Time-based suspicious activity alerts.
- Suspicious login-pattern alerts.
- Overall log analysis statistics.

The report also identifies the IP address with the highest number of failed login attempts.