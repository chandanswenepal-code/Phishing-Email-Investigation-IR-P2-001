# Phishing Email Investigation - IR-P2-001

**Analyst:** Chandan Yadav | **Team:** MustangShell
**Severity:** HIGH | **Verdict:** TRUE POSITIVE - CONFIRMED PHISHING
**Date:** September 2026

---

## Objective

Perform a complete end-to-end phishing email investigation using a real-world sample from the rf-peixoto/phishing_pot repository. Prove the spoof via email header analysis, validate SPF/DKIM/DMARC authentication failures, analyse all malicious URLs and IOCs, map the blast radius, and produce a professional SOC incident report.

---

## Summary of Findings

| Field | Finding |
|-------|---------|
| Email claiming to be | McAfee Support |
| Actual sender domain | sweeterpasta.de |
| Delivery method | Zapier automation via Azure IP 4.227.1.199 |
| SPF | FAIL - No SPF record on sending domain |
| DKIM | FAIL - No signature present |
| DMARC | FAIL - No DMARC record on sending domain |
| Phishing destination | wheeltiefoot.com |
| VirusTotal detections | 3/90 - Malicious (alphaMountain, CRDF, Fortinet) |
| Campaign scale | 704+ confirmed victim interactions |
| Objective | Payment card harvesting and credential theft |
| Target | German-speaking Microsoft Outlook users |

---

## Investigation Steps

### Step 1 - Sample Acquisition

- Sourced real phishing .eml file from rf-peixoto/phishing_pot repository
- Selected McAfee subscription scam targeting German-speaking users
- Safe handling - opened only via terminal text tools, never executed

### Step 2 - Header Analysis

- Extracted and parsed full email headers using Python
- Identified sender/From/Return-Path mismatch - classic spoofing indicator
- Traced 4-hop relay chain through Microsoft infrastructure
- Used Google Admin Toolbox for visual hop trace
- Discovered email sent via Zapier automation abusing trusted Azure IP

| Header | Expected | Actual |
|--------|----------|--------|
| From domain | mcafee.com | sweeterpasta.de |
| Sender field | mcafee.com | mcafee.com spoofed |
| Return-Path | mcafee.com | sweeterpasta.de |
| Message-ID domain | mcafee.com | amazonses.com |
| Sent via | McAfee mail servers | zapier.com |

### Step 3 - SPF / DKIM / DMARC Verification

| Check | sweeterpasta.de sender | mcafee.com impersonated |
|-------|------------------------|--------------------------|
| SPF | FAIL - No record found | PASS - v=spf1 -all strict |
| DKIM | FAIL - No record found | PASS - Fully configured |
| DMARC | FAIL - No record found | PASS - p=reject sp=reject |

McAfee enforces strict p=reject DMARC policy. The attacker deliberately used sweeterpasta.de which has zero authentication configured to bypass this protection.

### Step 4 - IOC Analysis

| URL | Destination | Verdict |
|-----|-------------|---------|
| t.co/noqm4SZyTz | wheeltiefoot.com | Malicious - 3/90 VT detections |
| t.co/YQ2EaF2AXJ | hxzf4er.com | Twitter flagged unsafe |
| pbs.twimg.com image | Twitter CDN | Fake McAfee logo |

**wheeltiefoot.com analysis:**
- VirusTotal: 3/90 - alphaMountain.ai, CRDF, Fortinet all flagged malicious
- URLscan.io: 704 total scans - confirmed large-scale bulk phishing campaign
- Page title: We are sorry to see you go - fake McAfee cancellation page
- TLS cert issued April 2026 - freshly registered for this campaign
- Infrastructure: Cloudflare CDN - built to handle high victim traffic

**Sender IP 4.227.1.199 analysis:**
- ISP: Microsoft Corporation Azure AS8075
- Location: Phoenix Arizona USA
- AbuseIPDB: 0% confidence score - never previously reported
- Attacker abused Zapier automation platform running on Azure to appear trusted

### Step 5 - Blast Radius

- Target: German-speaking Microsoft Outlook users in DE/AT/CH
- Campaign type: Bulk mass phishing - NOT targeted spearphishing
- Confirmed scale: 704+ victim page interactions on URLscan.io
- Primary objective: Payment card harvesting
- Secondary objective: McAfee credential theft

Social engineering techniques identified:
1. Brand impersonation - McAfee trusted security software brand
2. Urgency - 24-hour countdown timer in German
3. Fear - threats of viruses, malware, and identity theft
4. False legitimacy - fake Account ID and fake Serial Number
5. Fake discount - 95.99% OFF to strongly incentivize clicking
6. Personalization - victim email address used throughout email body
7. Unsubscribe trap - both the main CTA and unsubscribe link go to phishing page

---

## Attack Chain

1. Attacker sets up Zapier automation using Azure infrastructure
2. Email sent from sweeterpasta.de - zero SPF/DKIM/DMARC
3. Microsoft Outlook receives it - SCL score 5 - delivered to junk
4. Victim sees McAfee display name and opens email
5. Victim clicks shortened t.co URL inside email
6. t.co redirects to wheeltiefoot.com phishing page
7. Fake McAfee cancellation page loads asking for payment card
8. Victim enters card details - attacker harvests credentials

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Description |
|-------------|------|-------------|
| T1566.002 | Phishing Spearphishing Link | Malicious URLs embedded in email body |
| T1598 | Phishing for Information | Payment card harvesting via fake renewal page |
| T1036 | Masquerading | Impersonating McAfee brand with fake display name |
| T1204.001 | User Execution Malicious Link | Attack requires victim to click embedded URL |
| T1071.003 | Application Layer Protocol Mail | Bulk SMTP delivery via Zapier |
| T1583.001 | Acquire Infrastructure Domains | wheeltiefoot.com registered for this campaign |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| phishing_pot GitHub repository | Real-world phishing sample source |
| Kali Linux Terminal | Safe .eml analysis without execution |
| Google Admin Header Analyzer | Visual email hop trace |
| MXToolbox SuperTool | SPF DKIM DMARC verification |
| VirusTotal | URL and domain malware detection |
| URLscan.io | Phishing page screenshot and campaign scope |
| AbuseIPDB | Sender IP reputation check |

---

## Repository Structure

- README.md
- report/IR-P2-001_Phishing_Investigation.txt
- evidence/suspicious_email.eml
- evidence/headers_extracted.txt
- evidence/email_body.txt
- evidence/extracted_urls.txt
- evidence/step2_header_analysis.txt
- evidence/step3_spf_dkim_dmarc.txt
- evidence/step4_ioc_analysis.txt
- evidence/step5_blast_radius.txt
- screenshots/ (24 evidence screenshots across all investigation steps)

---

## Verdict and Recommendations

**VERDICT: TRUE POSITIVE - Confirmed Bulk Phishing Campaign**

Immediate actions required:
1. Block sender domain sweeterpasta.de in email gateway
2. Block sending IP 4.227.1.199 in email gateway
3. Block wheeltiefoot.com and hxzf4er.com in DNS firewall and web proxy
4. Submit all IOCs to MISP threat intelligence platform
5. Submit wheeltiefoot.com to Google Safe Browsing
6. Alert all users who may have received this campaign
7. Reset credentials for any user who clicked the link
8. Check payment card statements for any user who entered details

Long-term recommendations:
1. Enforce SPF DKIM DMARC on all organizational email domains
2. Deploy email gateway with URL rewriting and sandboxing
3. Implement phishing awareness training for all staff
4. Block URL shorteners in email gateway or force URL expansion
5. Configure DMARC aggregate reporting to detect spoofing attempts
6. Raise Microsoft SCL quarantine threshold

---
