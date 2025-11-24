# Security Stack Definition

Tell Claude what security controls you HAVE so it gives relevant recommendations.

## What We Have (Deployed Controls)

### Endpoint Security
- **[Tool Name]** - [Capabilities - e.g., CrowdStrike Falcon, Microsoft Defender, Carbon Black]
  - Antivirus/Anti-malware
  - EDR (Endpoint Detection & Response)
  - Application control
  - Coverage: [Percentage - e.g., 95% of endpoints]
  - Deployment: [Managed/Unmanaged, Auto-update status]

### Network Security
- **Firewall:** [Tool - e.g., Palo Alto, Fortinet, pfSense]
  - Next-gen firewall features
  - IPS/IDS capabilities
  - SSL inspection: [Yes/No/Selective]
- **Network Monitoring:** [Tool - e.g., Zeek, Suricata, Darktrace]
  - East-west traffic visibility: [Yes/No]
  - North-south traffic visibility: [Yes/No]

### Identity & Access
- **Identity Provider:** [Tool - e.g., Okta, Azure AD, Google Workspace]
  - SSO deployment: [Percentage of applications]
  - MFA enforcement: [Required/Optional/None]
  - MFA methods: [Push, TOTP, SMS, Biometric]
- **Privileged Access:** [Tool - e.g., CyberArk, BeyondTrust, Teleport]
  - Admin account management
  - Session recording: [Yes/No]

### Email Security
- **Email Gateway:** [Tool - e.g., Proofpoint, Mimecast, Microsoft EOP]
  - Spam filtering
  - Malware scanning
  - URL rewriting/sandboxing
  - DMARC/DKIM/SPF: [Deployment status]

### SIEM & Logging
- **SIEM Platform:** [Tool - e.g., Splunk, Elastic, Sentinel, Chronicle]
  - Log retention: [Days - e.g., 90 days hot, 365 days cold]
  - Data sources: [List key sources]
  - Use cases deployed: [Number of active detection rules]
- **Log Management:** [Centralized/Distributed]

### Vulnerability Management
- **Scanner:** [Tool - e.g., Tenable, Qualys, Rapid7]
  - Scan frequency: [Weekly, Monthly]
  - Coverage: [Internal/External/Both]
- **Patch Management:** [Tool - e.g., WSUS, SCCM, Jamf]
  - Critical patch SLA: [Days to deploy]

### Cloud Security
- **CASB:** [Tool - e.g., Netskope, Zscaler, Microsoft Defender for Cloud Apps]
  - Shadow IT discovery: [Yes/No]
- **CSPM:** [Tool - e.g., Prisma Cloud, Wiz, Orca]
  - Misconfiguration detection
  - Compliance monitoring

### Security Awareness
- **Training Platform:** [Tool - e.g., KnowBe4, Proofpoint, Internal]
  - Training frequency: [Quarterly, Annual]
  - Phishing simulations: [Yes/No, Frequency]

---

## What We Monitor

Active monitoring and alerting in place:

- Failed login attempts (threshold: [X attempts])
- Privilege escalation events
- Lateral movement indicators
- Data exfiltration patterns (>= [X GB] transfers)
- Endpoint malware detections
- Network IDS/IPS alerts
- Cloud misconfigurations
- Certificate expiration (alert at [X days])

### Alert Fatigue Status:
- Average alerts per day: [Number]
- True positive rate: [Percentage]
- Mean time to acknowledge: [Minutes/Hours]

---

## What We Block

Preventive controls actively in place:

- Known malicious IPs/domains (threat feed sources: [List])
- Suspicious file types via email (.exe, .scr, macro-enabled docs)
- Unapproved cloud applications
- Tor/VPN/Proxy traffic: [Block/Monitor/Allow]
- Cryptomining connections
- Command & control (C2) communications
- Geoblocked countries: [List countries if applicable]

### Allow-List Approach:
- Application whitelisting: [Yes/No, Scope]
- Network segmentation: [Fully/Partially/Not implemented]

---

## Known Gaps (What We DON'T Have)

Be honest about limitations so Claude can prioritize compensating controls:

- ❌ **[Gap 1]** - [Why this creates risk]
- ❌ **[Gap 2]** - [Why this creates risk]
- ❌ **[Gap 3]** - [Why this creates risk]

### Example Gaps:
- ❌ **No EDR on Linux servers** - Limited visibility into server compromises
- ❌ **No email sandboxing** - Advanced malware can bypass static analysis
- ❌ **Legacy systems without logging** - Blind spots in incident investigations
- ❌ **No network segmentation** - Flat network enables rapid lateral movement
- ❌ **MFA not enforced** - Credential stuffing attacks possible

---

## Detection Coverage

### MITRE ATT&CK Coverage
**Overall Coverage:** ~[Percentage - e.g., 65%]
**Confidence Level:** [High/Medium/Low]

**Strong Detection Areas:**
- Initial Access (phishing, exploits)
- Execution (malware, scripts)
- Credential Access (dumping, brute force)

**Weak Detection Areas:**
- Defense Evasion (especially process injection)
- Lateral Movement (east-west traffic gaps)
- Command & Control (encrypted C2 channels)
- Exfiltration (large data transfers via approved apps)

### Detection Confidence by Environment:
- **Windows:** [High/Medium/Low]
- **Linux:** [High/Medium/Low]
- **macOS:** [High/Medium/Low]
- **Cloud (AWS/Azure/GCP):** [High/Medium/Low]
- **SaaS Applications:** [High/Medium/Low]
- **OT/ICS Systems:** [High/Medium/Low]

---

## Response Capabilities

### Incident Response Readiness
- **IR Plan:** [Yes/No, Last tested: Date]
- **IR Team:** [Dedicated/Part-time/Outsourced]
- **Retainer with IR Firm:** [Yes/No, Firm name]
- **Forensic Tools Available:** [List tools]
- **Tabletop Exercises:** [Frequency]

### Containment Speed
- **Endpoint Isolation:** [Manual/Automated, Typical time]
- **Network Isolation:** [Manual/Automated, Typical time]
- **Account Disablement:** [Manual/Automated, Typical time]

### Recovery Capabilities
- **Backup Solution:** [Tool - e.g., Veeam, Commvault, AWS Backup]
  - Backup frequency: [Daily, Hourly]
  - Retention: [Days/Months]
  - Off-site/Air-gapped: [Yes/No]
  - Last restore test: [Date]
- **Disaster Recovery Plan:** [Yes/No, Last tested: Date]

---

**Last Updated:** [Date]
**Next Review:** [Date] (quarterly or after major security changes)
**Owner:** [Security operations contact]

---

## Notes for Claude

When analyzing threats, please:
- Consider what we HAVE before recommending new tools
- Prioritize actions that use existing capabilities
- Flag gaps that create specific risk for the threat being analyzed
- Suggest quick wins with current stack before major investments
- Acknowledge when a threat bypasses our controls (be honest about exposure)

## Detection Engineering Priorities

Based on our gaps, focus detection rules on:
1. [Priority 1 detection area]
2. [Priority 2 detection area]
3. [Priority 3 detection area]

## Budget Context

**Annual Security Budget:** [Rough range - helps Claude understand constraints]
- [Small: <$100k, Medium: $100k-$1M, Large: $1M-$10M, Enterprise: >$10M]

**Appetite for New Tools:** [High/Medium/Low]
**Preference:** [Best-of-breed vs. Consolidated platform]

---

## Tips for Customizing This File

1. **Be Brutally Honest:** Overstating capabilities leads to bad recommendations
2. **Include Versions:** "Splunk" vs "Splunk Enterprise 9.x" matters for features
3. **Note Coverage Gaps:** "EDR on 95% of endpoints" tells Claude where blind spots are
4. **Update After Changes:** New tool deployments, decommissions, major config changes
5. **Include Constraints:** Budget, staff, technical debt - helps Claude be realistic

## Community Examples

Looking for examples? Check `/examples` directory for:
- Startup security stack (limited budget)
- Mid-market security stack (growing team)
- Enterprise security stack (mature program)
- Cloud-first security stack
- Hybrid/on-prem security stack

Or contribute your stack to help others benchmark!
