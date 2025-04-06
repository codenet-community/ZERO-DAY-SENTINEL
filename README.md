# Zero-Day Sentinel

A network security analysis tool that uses Google's Gemini AI to detect and analyze potential security threats in network logs.

## Features

- Analyzes network log entries to identify various attack types including:
  - SQL Injection
  - DDoS Attacks
  - XSS
  - Brute Force Attempts
  - Port Scanning
  - Malware Communication
  - Phishing Attempts
  - DNS Spoofing
  - MITM Attacks
  - Zero-day Exploits
  - Other suspicious anomalies
- Web interface for visualizing and monitoring threats
- Detailed analysis of each detected threat

## Prerequisites

- Python 3.6+
- Google Generative AI (Gemini) API key

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/codenet-community/ZERO-DAY-SENTINEL.git
   cd ZERO-DAY-SENTINEL
   ```

2. Install the required dependencies:
   ```
   pip install google-generativeai
   ```

3. Configure your API key:
   - Open `analyze_logs.py`
   - Replace the placeholder API key with your Google Gemini API key
   ```python
   API_KEY = "your-api-key-here"
   ```

## Running the Project

### Command Line Analysis

To analyze a CSV log file using the command line:

```
python analyze_logs.py log_data.csv
```

Replace `log_data.csv` with the path to your network log file. The script expects CSV files with columns such as No., Time, Source IP, Dest IP, Protocol, Length, and Info.

### Web Interface

To run the web interface locally:

1. Start the local server:
   ```
   python server.py
   ```

2. Open your browser and navigate to:
   ```
   http://localhost:8000
   ```

3. Interact with the dashboard to visualize and analyze network security threats.

## File Structure

- `analyze_logs.py` - Core script for analyzing network logs using Gemini AI
- `server.py` - Simple HTTP server for serving the web interface
- `index.html` - Main landing page
- `dashboard.html` - Security dashboard interface
- `script.js` - JavaScript for the web interface
- `styles.css` - Styling for the web interface
- `log_data.csv` - Sample network log data

## Usage Notes

- The analysis script includes a rate limit delay between API calls to avoid hitting API limits
- For large log files, analysis may take some time due to the API rate limiting
- The web interface provides a more user-friendly way to visualize the analysis results

## Troubleshooting

- If you encounter API errors, check your API key and internet connection
- For "File not found" errors, ensure the log file path is correct
- If the web server fails to start, make sure no other process is using port 8000

## License

[Include license information here]
