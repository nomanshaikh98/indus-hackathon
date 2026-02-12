from flask import Flask, request, jsonify
import os
import re
from datetime import datetime

# Load CVE database
def load_cve_database():
    cve_data = {}
    try:
        # Try Vercel path first
        with open('/var/task/cve_data.txt', 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        try:
            # Try local path
            with open('cve_data.txt', 'r', encoding='utf-8') as f:
                content = f.read()
        except:
            # Fallback embedded data
            content = """
CVE-2021-44228 (Log4Shell): Critical remote code execution vulnerability in Apache Log4j 2. Affected versions: 2.0-beta9 to 2.14.1. Attackers can execute arbitrary code via JNDI lookup in log messages. Patch: Upgrade to Log4j 2.15.0+. CVSS Score: 10.0 (Critical). Exploitation observed in wild since December 2021.

CVE-2021-34527 (PrintNightmare): Windows Print Spooler remote code execution vulnerability. Allows attackers to run arbitrary code with SYSTEM privileges. Patch: Microsoft KB5004945. CVSS Score: 8.8 (High). Affects Windows 10/11 and Server editions.

Heartbleed (CVE-2014-0160): OpenSSL memory disclosure vulnerability. Allows attackers to read 64KB chunks of server memory containing private keys, passwords. Affected: OpenSSL 1.0.1-1.0.1f. Patch: Upgrade to 1.0.1g+. CVSS Score: 7.5 (High). Discovered April 2014.

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
        else:
            # Fallback parsing
            parts = entry.split(':', 1)
            if len(parts) == 2:
                name = parts[0].strip()
                description = parts[1].strip()
                
                cvss_match = re.search(r'CVSS Score:\s*([\d.]+)', description)
                cvss_score = float(cvss_match.group(1)) if cvss_match else 0.0
                
                cve_data[name.lower()] = {
                    'cve_id': 'N/A',
                    'name': name,
                    'description': description,
                    'cvss_score': cvss_score
                }
    
    return cve_data

# Load CVE database
CVE_DATABASE = load_cve_database()

def analyze_vulnerability(query):
    """Simple keyword matching analysis"""
    query_lower = query.lower()
    
    # Find best matching CVE
    best_match = None
    best_score = 0
    
    for cve_name, cve_info in CVE_DATABASE.items():
        score = 0
        
        # Check if query contains CVE name
        if cve_name in query_lower:
            score += 10
        
        # Check if query contains CVE ID
        if cve_info['cve_id'].lower() in query_lower:
            score += 15
        
        # Check partial matches
        if any(word in query_lower for word in cve_name.split()):
            score += 5
        
        if score > best_score:
            best_score = score
            best_match = cve_info
    
    if best_match and best_score > 0:
        # Determine risk level based on CVSS score
        cvss = best_match['cvss_score']
        if cvss >= 9.0:
            risk_level = 'Critical'
            confidence = 0.95
        elif cvss >= 7.0:
            risk_level = 'High'
            confidence = 0.90
        elif cvss >= 4.0:
            risk_level = 'Medium'
            confidence = 0.85
        else:
            risk_level = 'Low'
            confidence = 0.80
        
        # Generate analysis
        analysis = f"{best_match['description']}\n\n"
        analysis += f"**Patch Guidance:** "
        
        if 'patch' in best_match['description'].lower():
            analysis += "Apply vendor security patches immediately."
        else:
            analysis += "Check vendor security advisories for patch information."
        
        return {
            'query': query,
            'answer': analysis,
            'sources': [
                f"{best_match['name']} ({best_match['cve_id']}): {best_match['description']}",
                "NVD Database: https://nvd.nist.gov",
                "Vendor security advisories"
            ],
            'confidence': confidence,
            'risk_level': risk_level,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    else:
        # No match found
        return {
            'query': query,
            'answer': f"No specific vulnerability information found for '{query}'. Please try a known CVE name like 'Log4Shell', 'Heartbleed', or 'PrintNightmare'.",
            'sources': [
                "CVE Database: https://cve.mitre.org",
                "NVD Database: https://nvd.nist.gov"
            ],
            'confidence': 0.5,
            'risk_level': 'Unknown',
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

# Flask app for Vercel
app = Flask(__name__)

@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        query = data.get('query', '').strip()
        
        if not query:
            return jsonify({'error': 'Please enter a vulnerability name or CVE ID'}), 400
        
        result = analyze_vulnerability(query)
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

# Vercel handler
def handler(request):
    return app(request.environ, lambda *args: None)