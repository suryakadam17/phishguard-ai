from datetime import datetime
from urllib.parse import urlparse
import re
import whois
import os
import base64
import requests
from dotenv import load_dotenv
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
print("API KEY:", VT_API_KEY)

def parse_email_header(header):

    results = {
        "From": "Unknown",
        "Subject": "Unknown",
        "Return-Path": "Unknown",
        "SPF": "Unknown",
        "DKIM": "Unknown",
        "DMARC": "Unknown",
        "SenderIP": "Unknown",
        "Domain": "Unknown",

        "Registrar": "Unknown",
        "CreationDate": "Unknown",
        "ExpirationDate": "Unknown",
        "Country": "Unknown",
        "City": "Unknown",
        "Region": "Unknown",
        "ISP": "Unknown",
        "Organization": "Unknown",
        "VT_Malicious": 0,
        "VT_Suspicious": 0,
        "VT_Harmless": 0,
        "VT_Reputation": "Unknown",

        "URL_Intelligence": [],
        
        "ThreatScore": 0,
        "Risk": "Low",
        "Recommendation": "",
        "IOCs": [],
        "MITRE": [],
        "SpoofingRisk": "Low",
        "SpoofingReasons": [],
    }

    # ------------------------------------
    # FROM
    # ------------------------------------

    match = re.search(r"From:\s*(.*)", header, re.IGNORECASE)

    if match:
        results["From"] = match.group(1).strip()

        email = re.search(r"@([A-Za-z0-9.-]+)", results["From"])

        if email:
            results["Domain"] = email.group(1)

    # ------------------------------------
    # SUBJECT
    # ------------------------------------

    match = re.search(r"Subject:\s*(.*)", header, re.IGNORECASE)

    if match:
        results["Subject"] = match.group(1).strip()

    # ------------------------------------
    # RETURN PATH
    # ------------------------------------

    match = re.search(r"Return-Path:\s*(.*)", header, re.IGNORECASE)

    if match:
        results["Return-Path"] = match.group(1).strip()

    # ------------------------------------
    # SPF
    # ------------------------------------

    if "spf=pass" in header.lower():
        results["SPF"] = "PASS"

    elif "spf=fail" in header.lower():
        results["SPF"] = "FAIL"

    # ------------------------------------
    # DKIM
    # ------------------------------------

    if "dkim=pass" in header.lower():
        results["DKIM"] = "PASS"

    elif "dkim=fail" in header.lower():
        results["DKIM"] = "FAIL"

    # ------------------------------------
    # DMARC
    # ------------------------------------

    if "dmarc=pass" in header.lower():
        results["DMARC"] = "PASS"

    elif "dmarc=fail" in header.lower():
        results["DMARC"] = "FAIL"

    # ------------------------------------
    # EMAIL SPOOFING DETECTION
    # ------------------------------------

    spoof_score = 0

    # Extract sender domain
    from_domain = "Unknown"

    email_match = re.search(r'@([A-Za-z0-9.-]+)', results["From"])

    if email_match:
        from_domain = email_match.group(1).lower()

    # Extract Return-Path domain
    return_domain = "Unknown"

    return_match = re.search(r'@([A-Za-z0-9.-]+)', results["Return-Path"])

    if return_match:
        return_domain = return_match.group(1).lower()

    # Compare domains
    if (
        from_domain != "Unknown"
        and return_domain != "Unknown"
        and from_domain != return_domain
    ):
        spoof_score += 40
        results["SpoofingReasons"].append(
            "From domain and Return-Path domain do not match."
        )

    # SPF
    if results["SPF"] == "FAIL":
        spoof_score += 20
        results["SpoofingReasons"].append(
            "SPF authentication failed."
        )

    # DKIM
    if results["DKIM"] == "FAIL":
        spoof_score += 20
        results["SpoofingReasons"].append(
            "DKIM authentication failed."
        )

    # DMARC
    if results["DMARC"] == "FAIL":
        spoof_score += 20
        results["SpoofingReasons"].append(
            "DMARC authentication failed."
        )

    # Final spoofing risk
    if spoof_score >= 60:
        results["SpoofingRisk"] = "High"

    elif spoof_score >= 30:
        results["SpoofingRisk"] = "Medium"

    else:
        results["SpoofingRisk"] = "Low"

    # ------------------------------------
    # SENDER IP
    # ------------------------------------

    ip = re.search(r"Received:.*?(\d+\.\d+\.\d+\.\d+)", header)

    if ip:
        results["SenderIP"] = ip.group(1)

    # ------------------------------------
    # THREAT SCORE
    # ------------------------------------

    score = 0

    if results["SPF"] == "FAIL":
        score += 30

    if results["DKIM"] == "FAIL":
        score += 25

    if results["DMARC"] == "FAIL":
        score += 25

    suspicious_words = [
        "urgent",
        "verify",
        "locked",
        "password",
        "login",
        "bank",
        "amazon",
        "security",
        "update",
        "confirm",
        "account"
    ]

    subject = results["Subject"].lower()

    for word in suspicious_words:
        if word in subject:
            score += 5

    score = min(score, 100)

    results["ThreatScore"] = score

    # ------------------------------------
    # RISK LEVEL
    # ------------------------------------

    if score >= 80:
        results["Risk"] = "High"

    elif score >= 50:
        results["Risk"] = "Medium"

    else:
        results["Risk"] = "Low"


    # ------------------------------------
    # RECOMMENDATION
    # ------------------------------------

    recommendations = []

    if results["Risk"] == "High":

        recommendations.append("🚫 Do NOT click any links.")
        recommendations.append("📎 Do NOT open attachments.")
        recommendations.append("🛡 Report the email to your SOC or IT team.")
        recommendations.append("📧 Verify the sender through another communication channel.")

        if results["SpoofingRisk"] == "High":
            recommendations.append("🎭 Email spoofing detected. Treat the sender as untrusted.")

        if results.get("URL_Intelligence"):

            for url in results["URL_Intelligence"]:

                if url["risk"] == "High":
                    recommendations.append(
                        f"🌐 Block or investigate the domain: {url['domain']}"
                    )

                if url["short"] == "Yes":
                    recommendations.append(
                        f"🔗 Expand shortened URLs before visiting:{url['url']}"
                    )

    elif results["Risk"] == "Medium":

        recommendations.append("⚠ Verify the sender before replying.")
        recommendations.append("🔍 Inspect URLs before clicking.")
        recommendations.append("📎 Scan attachments before opening.")

    else:

        recommendations.append("✅ No major phishing indicators detected.")
        recommendations.append("🛡 Continue following safe email practices.")

    results["Recommendation"] = recommendations

    # ------------------------------------
    # WHOIS LOOKUP
    # ------------------------------------

    try:

        if results["Domain"] != "Unknown":

            info = whois.whois(results["Domain"])

            if info.registrar:
                results["Registrar"] = str(info.registrar)

            if info.creation_date:

                if isinstance(info.creation_date, list):
                    results["CreationDate"] = str(info.creation_date[0].date())
                else:
                    results["CreationDate"] = str(info.creation_date.date())

            if info.expiration_date:

                if isinstance(info.expiration_date, list):
                    results["ExpirationDate"] = str(info.expiration_date[0].date())
                else:
                    results["ExpirationDate"] = str(info.expiration_date.date())

            if hasattr(info, "country") and info.country:
                results["Country"] = str(info.country)

    except Exception as e:
        print("WHOIS Error:", e)

    import requests

    try:

        if results["SenderIP"] != "Unknown":

            url = f"https://ipapi.co/{results['SenderIP']}/json/"

            response = requests.get(url, timeout=5)

            if response.status_code == 200:

                data = response.json()

                results["Country"] = data.get("country_name", "Unknown")
                results["City"] = data.get("city", "Unknown")
                results["Region"] = data.get("region", "Unknown")
                results["ISP"] = data.get("org", "Unknown")
                results["Organization"] = data.get("asn", "Unknown")

    except Exception as e:

        print("IP Lookup Error:", e)

    # ------------------------------------
    # VIRUSTOTAL DOMAIN LOOKUP
    # ------------------------------------

    try:

        if results["Domain"] != "Unknown" and VT_API_KEY:

            print("Checking VirusTotal for:", results["Domain"])

            headers = {
                "x-apikey": VT_API_KEY
            }

            url = f"https://www.virustotal.com/api/v3/domains/{results['Domain']}"

            response = requests.get(
                url,
                headers=headers,
                timeout=10
            )

            print("Status Code:", response.status_code)
            print("Response:")
            print(response.text)

            if response.status_code == 200:

                data = response.json()

                stats = data["data"]["attributes"]["last_analysis_stats"]

                results["VT_Malicious"] = stats.get("malicious", 0)
                results["VT_Suspicious"] = stats.get("suspicious", 0)
                results["VT_Harmless"] = stats.get("harmless", 0)

                if results["VT_Malicious"] > 0:
                    results["VT_Reputation"] = "Dangerous"

                elif results["VT_Suspicious"] > 0:
                    results["VT_Reputation"] = "Suspicious"

                else:
                    results["VT_Reputation"] = "Safe"

            else:
 
                print("VirusTotal API Error!")

    except Exception as e:

        print("VirusTotal Exception:", e)


    # ------------------------------------
    # URL INTELLIGENCE
    # ------------------------------------

    url_pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(url_pattern, header)

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "is.gd",
        "rebrand.ly",
        "cutt.ly"
    ]

    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "update",
        "bank",
        "confirm",
        "password",
        "account"
    ]

    for url in urls:
      
        malicious = 0
        suspicious = 0

        # HTTPS
        https = "Yes" if url.startswith("https://") else "No"

        # Short URL
        short = "No"
        for s in shorteners:
            if s in url.lower():
                short = "Yes"
                break

        # Suspicious Keywords
        found_keywords = []

        for keyword in suspicious_keywords:
            if keyword in url.lower():
                found_keywords.append(keyword)

        if found_keywords:
            keywords = ", ".join(found_keywords)
        else:
            keywords = "None"

        # Status
        if short == "Yes":
            status = "Shortened"

        elif keywords != "None":
            status = "Suspicious"

        else:
            status = "Safe"

        parsed = urlparse(url)
        domain = parsed.netloc

        if domain.startswith("www."):
            domain = domain[4:]
        # ----------------------------
        # VirusTotal URL Intelligence
        # ----------------------------

        age = "Unknown"
        vt = "Unknown"

        try:

            headers = {
                "x-apikey": VT_API_KEY
            }
 
            vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"

            response = requests.get(
                vt_url,
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:

                data = response.json()

                attributes = data["data"]["attributes"]

                # --------------------
                # Domain Age
                # --------------------

                if "creation_date" in attributes:

                    timestamp = attributes["creation_date"]

                    created = datetime.fromtimestamp(timestamp)

                    days = (datetime.now() - created).days

                    if days < 30:
                        age = f"{days} Days"

                    elif days < 365:
                        age = f"{days // 30} Months"

                    else:
                        age = f"{days // 365} Years"

                # --------------------
                # VirusTotal Score
                # --------------------

                stats = attributes["last_analysis_stats"]

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                
                print(f"{domain} -> {stats}")

                if malicious > 0:
                    vt = f"🔴 {malicious} Malicious"

                elif suspicious > 0:
                    vt = f"🟡 {suspicious} Suspicious"
               
                else:
                    vt = "🟢 Clean"


        except Exception as e:

            print("URL VT Error:", e)
       
       
        # ----------------------------
        # Calculate Risk
        # ----------------------------

        risk_points = 0

        # HTTPS
        if https == "No":
            risk_points += 20

        # Shortened URL
        if short == "Yes":
            risk_points += 30

        # Suspicious Keywords
        if keywords != "None":
            risk_points += 30

        # Domain Age
        if "Days" in age:
            risk_points += 40

        elif "Months" in age:
            risk_points += 20

        # VirusTotal detections
        if malicious > 0:
            risk_points += 50

        elif suspicious > 0:
            risk_points += 25


        # Final Risk
        if risk_points >= 60:
            risk = "High"

        elif risk_points >= 30:
            risk = "Medium"

        else:
            risk = "Low"

        results["URL_Intelligence"].append({

            "url": url,
            "domain": domain,

            "https": https,
            "short": short,
            "keywords": keywords,

            "status": status,

            "age": age,

            "vt": vt,

            "risk": risk
      })

        # ------------------------------------
        # Overall VirusTotal Summary
        # ------------------------------------

        malicious_links = 0
        suspicious_links = 0

        for item in results["URL_Intelligence"]:

            vt = item["vt"]

            if "Malicious" in vt:
                malicious_links += 1

            elif "Suspicious" in vt:
                suspicious_links += 1

        if malicious_links > 0:
            results["VT_Summary"] = f"🔴 {malicious_links} Malicious URL(s)"

        elif suspicious_links > 0:
            results["VT_Summary"] = f"🟡 {suspicious_links} Suspicious URL(s)"

        else:
            results["VT_Summary"] = "🟢 Clean"

        # ------------------------------------
        # IOC COLLECTION
        # ------------------------------------

        iocs = []

        # Sender Email
        if results["From"] != "Unknown":
            iocs.append({
                "type": "Email",
                "value": results["From"]
            })

        # Sender Domain
        if results["Domain"] != "Unknown":
            iocs.append({
                "type": "Domain",
                "value": results["Domain"]
            })
 
        # Sender IP
        if results["SenderIP"] != "Unknown":
            iocs.append({
                "type": "IP Address",
                "value": results["SenderIP"]
            })

        # Subject
        if results["Subject"] != "Unknown":
            iocs.append({
                "type": "Subject",
                "value": results["Subject"]
            })

        # URLs
        for url in results["URL_Intelligence"]:

            iocs.append({
                "type": "URL",
                "value": url["url"]
            })

            iocs.append({
                "type": "Domain",
                "value": url["domain"]
            })

        results["IOCs"] = iocs

        # ------------------------------------
        # MITRE ATT&CK MAPPING
        # ------------------------------------

        mitre = []

        # T1566 - Phishing
        if results["Risk"] in ["High", "Medium"]:

            mitre.append({
                "id": "T1566",
                "technique": "Phishing",
                "tactic": "Initial Access"
            })

        # T1566.002 - Spearphishing Link
        for url in results["URL_Intelligence"]:

            if url["risk"] == "High":

                mitre.append({
                    "id": "T1566.002",
                    "technique": "Spearphishing Link",
                    "tactic": "Initial Access"
                })

                break

        # T1036 - Masquerading
        if results["SpoofingRisk"] == "High":

            mitre.append({
                "id": "T1036",
                "technique": "Masquerading",
                "tactic": "Defense Evasion"
            })

        # T1583.001 - Domain Acquisition
        for url in results["URL_Intelligence"]:

            if "Days" in url["age"]:

                mitre.append({
                    "id": "T1583.001",
                    "technique": "Acquire Infrastructure: Domains",
                    "tactic": "Resource Development"
                })

                break

        results["MITRE"] = mitre

    results["AI_Report"] = generate_ai_report(results)

    return results


def generate_ai_report(results):

    report = []

    # -----------------------------
    # Overall Risk
    # -----------------------------

    report.append("Overall Security Assessment")
    report.append("")

    if results["Risk"] == "High":
        report.append(
            "This email is highly suspicious and displays multiple phishing indicators."
        )

    elif results["Risk"] == "Medium":
        report.append(
            "This email contains several suspicious indicators and should be verified before interacting with it."
        )

    else:
        report.append(
            "No major phishing indicators were detected during analysis."
        )

    report.append("")

    # -----------------------------
    # Authentication
    # -----------------------------

    report.append("Authentication Analysis")

    if results["SPF"] == "FAIL":
        report.append(
            "• SPF authentication failed. The sender is not authorized to send emails for this domain."
        )
    else:
        report.append(
            "• SPF authentication passed."
        )

    if results["DKIM"] == "FAIL":
        report.append(
            "• DKIM signature validation failed."
        )
    else:
        report.append(
            "• DKIM authentication passed."
        )

    if results["DMARC"] == "FAIL":
        report.append(
            "• DMARC authentication failed."
        )
    else:
        report.append(
            "• DMARC authentication passed."
        )

    report.append("")

    # -----------------------------
    # Domain Intelligence
    # -----------------------------

    report.append("Domain Intelligence")

    report.append(
        f"• Domain: {results['Domain']}"
    )

    report.append(
        f"• Registrar: {results['Registrar']}"
    )

    report.append(
        f"• Domain Created: {results['CreationDate']}"
    )

    report.append("")

    # -----------------------------
    # Threat Intelligence
    # -----------------------------

    report.append("Threat Intelligence")

    report.append(
        f"• Sender Domain Reputation: {results['VT_Reputation']}"
    )

    report.append("")
    
    urls = results.get("URL_Intelligence", [])

    report.append(f"• URLs Found: {len(urls)}")
   
    malicious_urls = 0
    suspicious_urls = 0
    short_urls = 0

    for url in urls:

        vt = url.get("vt", "")

        if "Malicious" in vt:
            malicious_urls += 1

        elif "Suspicious" in vt:
            suspicious_urls += 1

        if url.get("short") == "Yes":
            short_urls += 1

    report.append(f"• Malicious URLs: {malicious_urls}")
    report.append(f"• Suspicious URLs: {suspicious_urls}")
    report.append(f"• Shortened URLs: {short_urls}")

    if malicious_urls > 0:

        report.append(
            "• One or more URLs are flagged as malicious."
        )

    elif suspicious_urls > 0:

        report.append(
            "• One or more URLs appear suspicious."
        )

    else:

        report.append(
            "• No malicious URLs detected."
        )

    report.append("")

    # -----------------------------
    # IP Analysis
    # -----------------------------

    report.append("Sender Infrastructure")

    report.append(
        f"• Source IP: {results['SenderIP']}"
    )

    report.append(
        f"• Country: {results['Country']}"
    )

    report.append(
        f"• ISP: {results['ISP']}"
    )

    report.append("")

    # -----------------------------
    # MITRE ATT&CK
    # -----------------------------

    report.append("")
    report.append("MITRE ATT&CK Mapping")

    for attack in results["MITRE"]:

        report.append(
            f"• {attack['id']} - {attack['technique']} ({attack['tactic']})"
        )

    report.append("")

    # -----------------------------
    # Recommendation
    # -----------------------------

    report.append("Recommended Actions")

    if results["Risk"] == "High":

        report.append(
            "• Do NOT click links."
        )

        report.append(
            "• Do NOT open attachments."
        )

        report.append(
            "• Report the email immediately."
        )
        
        if malicious_urls > 0:
            report.append(
                "• Do NOT open the malicious URL(s) detected by VirusTotal."
            )

        if short_urls > 0:
            report.append(
                "• Expand shortened URLs before visiting them."
            )

    elif results["Risk"] == "Medium":

        report.append(
            "• Verify the sender before responding."
        )

        report.append(
            "• Avoid clicking unknown links."
        )

    else:

        report.append(
            "• Continue exercising normal email security practices."
        )

    return "\n".join(report)
