import csv
import google.generativeai as genai
import sys
import os
import time

# --- Configuration ---
API_KEY = "AIzaSyB2yIESuvnB_VDYMQgTXR6_vGLpeot2_iw"  # Replace with your API key
MODEL_NAME = "gemini-1.5-flash-latest"
RATE_LIMIT_DELAY = 1  # Seconds between API calls

# Initialize Gemini
genai.configure(api_key=API_KEY)
model = genai.GenerativeModel(MODEL_NAME)

def analyze_log_entry(entry):
    """Analyze log entry using Gemini API for various attack types"""
    prompt = f"""Analyze this network log entry for security threats and anomalies. 
Consider these attack types:
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
- Suspicious Anomalies

Return response STRICTLY in this format:

Attack Type: [Specific attack category]
Timestamp: {entry['Time']}
Source IP: {entry['Source IP']}
Destination IP: {entry['Dest IP']}
Protocol: {entry['Protocol']}
Packet Length: {entry['Length']}
Attack Indicator: {entry['Info']}
Severity: [Low/Medium/High/Critical]
Details: [Brief technical explanation]

If no threat found, use:
Attack Type: Normal Traffic

Log entry:
{entry}"""

    try:
        response = model.generate_content(
            prompt,
            safety_settings={
                "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
                "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
                "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
                "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE"
            }
        )
        return response.text.strip()
    except Exception as e:
        return f"API Error: {str(e)}"

def process_csv(file_path):
    """Process CSV file and print analysis results"""
    print(f"Analyzing log file: {file_path}\n{'='*40}")
    
    with open(file_path, 'r', newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for idx, row in enumerate(reader, 1):
            print(f"\nAnalyzing Entry #{row['No.']}...")
            analysis = analyze_log_entry(row)
            
            if "Normal Traffic" not in analysis:
                print(f"\n{'='*40}")
                print(f"🚨 THREAT DETECTED - ENTRY {idx}")
                print(analysis)
                print(f"{'='*40}")
            
            time.sleep(RATE_LIMIT_DELAY)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <csv_file>")
        sys.exit(1)

    csv_file = sys.argv[1]
    
    if not os.path.exists(csv_file):
        print(f"Error: File {csv_file} not found")
        sys.exit(1)

    process_csv(csv_file)
    print("\nAnalysis complete. Review above findings.")

if __name__ == "__main__":
    main()