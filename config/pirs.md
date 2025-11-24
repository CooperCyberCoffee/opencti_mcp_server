# Priority Intelligence Requirements (PIRs)

Update this file to tell Claude what matters to YOUR organization.

## Organization Profile

**Industry:** [Your Industry - e.g., Healthcare, Finance, Manufacturing, Retail]
**Size:** [Number of employees - e.g., 100-500, 500-2000, 2000+]
**Geography:** [Primary locations - e.g., North America, EMEA, Asia-Pacific]
**Business Model:** [B2B, B2C, B2G, Hybrid]

## Strategic Priorities

What keeps leadership up at night:

1. **[Priority 1]** - [Why it matters to your business]
2. **[Priority 2]** - [Why it matters to your business]
3. **[Priority 3]** - [Why it matters to your business]

### Example Strategic Priorities:
- **Data Privacy Compliance** - GDPR/CCPA requirements with significant financial penalties
- **Supply Chain Security** - Third-party vendor risks affecting production
- **Intellectual Property Protection** - R&D secrets critical to competitive advantage
- **Customer Trust** - Brand reputation directly tied to security posture

## Threat Actors We Care About

Focus threat intelligence on these groups:

- **[Actor 1]** - [Why they're relevant to your organization]
- **[Actor 2]** - [Why they're relevant to your organization]
- **[Actor 3]** - [Why they're relevant to your organization]

### Example Threat Actors by Industry:
- **Healthcare:** ALPHV/BlackCat, LockBit 3.0, Hive (ransomware targeting healthcare)
- **Finance:** APT38, Lazarus Group, FIN7 (financial crime focus)
- **Manufacturing:** APT41, Volt Typhoon (industrial espionage)
- **Retail:** Magecart groups, FIN8 (POS/payment card theft)

## Technology Stack

What we actually use (helps Claude give relevant recommendations):

- **Cloud:** [AWS, Azure, GCP, On-Prem, Hybrid]
- **Endpoints:** [Windows 10/11, macOS, Linux, Mobile - Android/iOS]
- **Identity:** [Okta, Azure AD, Google Workspace, On-Prem AD]
- **Development:** [GitHub, GitLab, Bitbucket, Jenkins]
- **Email:** [Microsoft 365, Google Workspace, On-Prem Exchange]
- **Collaboration:** [Slack, Teams, Zoom]

## Geographic Risk Areas

Regions we operate in or interact with:

- **Primary Operations:** [Regions where you have offices/employees]
- **Customer Base:** [Regions where your customers are located]
- **Supply Chain:** [Regions where vendors/partners operate]
- **Data Residency:** [Where sensitive data is stored]

### Why This Matters:
Claude can prioritize threats from adversaries known to target these regions.

## Intelligence Collection Priorities

What we want to know (ranked by priority):

1. **[Topic 1]** - [Critical/High/Medium priority] - [Why]
2. **[Topic 2]** - [Critical/High/Medium priority] - [Why]
3. **[Topic 3]** - [Critical/High/Medium priority] - [Why]

### Example Collection Priorities:
- **Ransomware Indicators** - Critical - Need 24-48hr advance warning
- **Zero-Day Exploits in Microsoft Products** - High - 80% Windows environment
- **Cloud Misconfigurations** - High - Rapid cloud expansion creates risk
- **Insider Threat Patterns** - Medium - Growing concern post-acquisitions

## Compliance & Regulatory Requirements

Frameworks we must comply with:

- **[Framework 1]** - [e.g., PCI-DSS, HIPAA, SOC 2, CMMC]
- **[Framework 2]** - [Compliance deadline or audit schedule]
- **[Framework 3]** - [Specific requirements affecting threat response]

### Why This Matters:
Claude can highlight threats that impact compliance and suggest controls that satisfy requirements.

## Crown Jewels (Critical Assets)

What we absolutely cannot afford to lose:

- **[Asset 1]** - [e.g., Customer PII database, Payment processing system]
- **[Asset 2]** - [e.g., Intellectual property, Trade secrets]
- **[Asset 3]** - [e.g., Manufacturing control systems, Source code]

### Why This Matters:
Claude prioritizes threats targeting these specific assets.

## Risk Tolerance

How much risk can we accept:

- **Downtime Tolerance:** [Hours/days before critical business impact]
- **Data Loss Tolerance:** [Recovery Point Objective - how much data loss acceptable]
- **Public Disclosure Impact:** [How sensitive is breach disclosure for your org]
- **Third-Party Risk Acceptance:** [Vendor security requirements]

---

**Last Updated:** [Date]
**Next Review:** [Date] (quarterly updates recommended)
**Owner:** [Security team contact]

---

## Tips for Customizing This File

1. **Be Specific:** "Ransomware" is less useful than "Ransomware targeting our ERP system"
2. **Explain Why:** Help Claude understand your unique context
3. **Update Regularly:** Quarterly reviews keep intelligence relevant
4. **Be Honest:** Acknowledge gaps - better recommendations
5. **Think Strategically:** This isn't just tech - it's business risk

## Community Examples

Looking for examples? Check the `/examples` directory for:
- Healthcare PIRs template
- Financial services PIRs template
- Manufacturing PIRs template
- Retail PIRs template

Or contribute your anonymized PIRs to help others in your industry!
