# 🛡️ Log File Analyzer & Threat Detection Engine

A lightweight Python security tool designed to parse raw server logs and detect potential **Brute-Force attacks** using an optimal **Sliding Window algorithm**.

---

## 🎯 Project Overview

In web applications, automated brute-force attacks generate high volumes of failed login attempts in short time frames. Traditional nested-loop approaches to analyze time-series log data require $O(N^2)$ time complexity, which becomes slow on large datasets.

This project implements an efficient two-pointer **Sliding Window** technique to process chronological log timestamps in **$O(N)$ time**, identifying high-frequency authentication failures within a rolling 60-second window and flagging suspicious IP addresses in real time.

---

## ✨ Key Features

* **Log Parsing & Cleaning:** Extracts IP addresses, request methods, timestamps, and HTTP status codes from raw server log files using Python string manipulation.
* **Algorithmic Threat Detection:** Implements a sliding window data structure to count failed attempts (`401 Unauthorized`) within a dynamic time window.
* **Configurable Alert Thresholds:** Triggers security alerts when an IP address exceeds $5$ failed attempts within $60$ seconds.
* **Optimal Efficiency:** Processes time-series data in $O(N)$ linear time complexity.

---

## ⚙️ How It Works

1. **Extraction:** Reads `server.log` line-by-line and filters for failed authentication requests (`401` status code).
2. **Grouping:** Maps each unique IP address to its corresponding list of failed attempt timestamps using a dictionary structure.
3. **Sliding Window Analysis:**
   * Two pointers (`left` and `right`) traverse the timestamps array.
   * If the time gap between `timestamps[right]` and `timestamps[left]` exceeds 60 seconds, the window shrinks by incrementing `left`.
   * If the current window size `(right - left + 1)` reaches the threshold ($\ge 5$), an alert is flagged for that IP.

---

## 📊 Complexity Analysis

| Metric | Complexity | Explanation |
| :--- | :--- | :--- |
| **Time Complexity** | **$O(N)$** | Each log timestamp is processed at most twice (once by the `right` pointer and once by the `left` pointer). |
| **Space Complexity** | **$O(U \cdot M)$** | $U$ is the number of unique IP addresses and $M$ is the maximum failed attempts stored per IP. |

---

## 🚀 Getting Started

### Prerequisites
* Python 3.x installed on your system.

### Running the Project

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/sonichenika-cloud/log_file_analyzer
   cd log-file-analyzer