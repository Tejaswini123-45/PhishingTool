# PhishGuard – Phishing Detection Web Application

## Introduction
PhishGuard is a web-based tool designed to help users detect phishing links and suspicious messages. It provides instant analysis and clear explanations to support safer browsing.

## Features
* **Single Input Analysis:** Enter a URL or text to check if it is safe or potentially phishing.
* **Explainable Results:** Displays verdicts (**Safe**/**Phishing**), confidence scores, and reasons for each detection.

## How It Works
PhishGuard uses a hybrid approach:
* **Machine Learning:** A trained Logistic Regression model analyzes input using TF-IDF features.
* **Rule-Based Checks:** Applies security rules such as HTTPS presence, suspicious keywords, domain patterns, and more.
* **Combined Verdict:** Both methods contribute to the final decision for higher accuracy.

## Usage
To run the application, use the following commands:
```bash
# This is a placeholder command, replace with your actual command
python app.py
