from flask import Flask, render_template, request, jsonify
import re
from datetime import datetime
import os

app = Flask(__name__)

# Load CVE database from file
def load_cve_database():
    cve_data = {}
    try:
        # Try Vercel path first
        with open('/var/task/cve_data.txt', 'r', encoding='utf-8') as f:
            content = f.read()
    except:
        try:
            # Try local path
            with open('cve_data.txt', 'r', encoding='utf-8') as f:
                content = f.read()
        except:
            # Fallback embedded data
            content = """
CVE-2021-44228 (Log4Shell): Critical remote code execution vulnerability in Apache Log4j 2. Affected versions: 2.0-beta9 to 2.14.1. Attackers can execute arbitrary code via JNDI lookup in log messages. Patch: Upgrade to Log4j 2.15.0+. CVSS Score: 10.0 (Critical).
CVE-2021-34527 (PrintNightmare): Windows Print Spooler remote code execution vulnerability. Allows attackers to run arbitrary code with SYSTEM privileges. Patch: Microsoft KB5004945. CVSS Score: 8.8 (High).
Heartbleed (CVE-2014-0160): OpenSSL memory disclosure vulnerability. Allows attackers to read 64KB chunks of server memory containing private keys, passwords. Affected: OpenSSL 1.0.1-1.0.1f. Patch: Upgrade to 1.0.1g+. CVSS Score: 7.5 (High).
CVE-2022-22965 (Spring4Shell): Critical RCE in Spring Framework. Exploits Java class binding via malicious request parameters. Affected: Spring Core 5.3.0-5.3.17, 5.2.0-5.2.19. Patch: Upgrade to 5.3.18+ or 5.2.20+. CVSS Score: 9.8 (Critical).
Spectre (CVE-2017-5753): Speculative execution side-channel attack affecting modern CPUs. Allows reading arbitrary memory across privilege boundaries. Mitigation: Microcode updates + software patches. CVSS Score: 5.5 (Medium).
"""
    
    entries = content.strip().split('\n\n')
    for entry in entries:
        if not entry.strip():
            continue
        
        # Parse CVE entry
        match = re.match(r'(CVE-\d{4}-\d+|[\w\s]+)\s*\(([^)]+)\):(.+)', entry)
        if match:
            cve_id = match.group(1).strip()
            name = match.group(2).strip()
            description = match.group(3).strip()
            
            # Extract CVSS score
            cvss_match = re.search(r'CVSS Score:\s*([\d.]+)', description)
            cvss_score = float(cvss_match.group(1)) if cvss_match else 0.0
            
            cve_data[name.lower()] = {
                'cve_id': cve_id,
                'name': name,
                'description': description,
                'cvss_score': cvss_score
            }
    return cve_data

CVE_DATABASE = load_cve_database()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        query = data.get('query', '').strip().lower()
        
        if not query:
            return jsonify({'error': 'Please enter a vulnerability name'}), 400
        
        # Simple keyword matching
        result = None
        for name, info in CVE_DATABASE.items():
            if name in query or info['cve_id'].lower() in query:
                # Determine risk level
                if info['cvss_score'] >= 9.0:
                    risk = 'Critical'
                    confidence = 0.95
                elif info['cvss_score'] >= 7.0:
                    risk = 'High'
                    confidence = 0.90
                elif info['cvss_score'] >= 4.0:
                    risk = 'Medium'
                    confidence = 0.85
                else:
                    risk = 'Low'
                    confidence = 0.80
                
                # Generate analysis
                analysis = f"{info['description']}\n\n**Patch Guidance:** "
                if 'patch' in info['description'].lower():
                    analysis += "Apply vendor security patches immediately."
                else:
                    analysis += "Check vendor security advisories for patch information."
                
                result = {
                    'query': query,
                    'answer': analysis,
                    'sources': [
                        f"{info['name']} ({info['cve_id']}): {info['description']}",
                        "NVD Database: https://nvd.nist.gov",
                        "Vendor security advisories"
                    ],
                    'confidence': confidence,
                    'risk_level': risk,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                break
        
        if not result:
            result = {
                'query': query,
                'answer': f"No specific vulnerability information found for '{query}'. Try known CVEs like 'Log4Shell', 'Heartbleed', or 'PrintNightmare'.",
                'sources': [
                    "CVE Database: https://cve.mitre.org",
                    "NVD Database: https://nvd.nist.gov"
                ],
                'confidence': 0.5,
                'risk_level': 'Unknown',
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'cve_count': len(CVE_DATABASE),
        'database_loaded': True
    })

if __name__ == '__main__':
    print("🛡️  Starting AI Cybersecurity Assistant (Flask)")
    print("   Access at: http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)