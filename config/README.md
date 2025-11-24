# Cooper Cyber Coffee - Configuration Guide

Customize your threat intelligence analysis in three simple files. No Python required!

---

## Quick Start (15-45 minutes)

### Step 1: Define Your Priorities (15 min)
Edit `config/pirs.md` to tell Claude what matters to YOUR organization:
- Industry and business priorities
- Threat actors you're concerned about
- Technology stack you use
- Geographic regions that matter

**Example:**
```markdown
Industry: Healthcare
Threat Actors: ALPHV/BlackCat, LockBit 3.0 (ransomware targeting healthcare)
Technology Stack: Microsoft 365, Epic EHR, AWS
```

**Update frequency:** Quarterly or when business priorities change

---

### Step 2: Document Your Security Stack (30 min)
Edit `config/security_stack.md` to tell Claude what controls you have:
- Security tools deployed (EDR, SIEM, firewall, etc.)
- What you monitor and block
- Known gaps in coverage
- Current detection capabilities

**Example:**
```markdown
EDR: CrowdStrike Falcon (95% coverage)
SIEM: Splunk Enterprise (90-day retention)
Known Gaps: No email sandboxing, limited Linux server visibility
```

**Update frequency:** After major security changes or quarterly reviews

---

### Step 3: Choose Your Output Format (Optional)
Review existing templates in `config/templates/*.md`:
- `executive_briefing.md` - Board-ready summaries
- `technical_analysis.md` - Deep technical dives
- `incident_response.md` - Response playbooks
- `trend_analysis.md` - Strategic assessments

**Customization:** Edit templates to match your organization's reporting standards

**Update frequency:** As needed when reporting requirements change

---

## Why This Matters

### Without Customization
```
You: "Analyze APT28 TTPs"
Claude: *Generic analysis applicable to any organization*
```

### With Customization
```
You: "Analyze APT28 TTPs"
Claude:
- Prioritizes techniques targeting YOUR tech stack (Microsoft 365)
- Notes gaps in YOUR defenses (no email sandboxing = phishing risk)
- Recommends actions using YOUR existing tools (Splunk detection rules)
- Focuses on threats to YOUR industry (healthcare-specific risks)
```

**Result:** Context-aware, actionable intelligence instead of generic advice.

---

## Configuration Files Explained

### 1. pirs.md - Priority Intelligence Requirements

**What it is:** Your organization's "intelligence wishlist" - what threats you care about and why.

**What Claude does with it:**
- Prioritizes threats relevant to your industry
- Highlights actors targeting your geography
- Focuses on technology you actually use
- Aligns recommendations with business priorities

**Key sections:**
- Organization Profile (industry, size, geography)
- Strategic Priorities (what keeps leadership up at night)
- Threat Actors We Care About (focus intelligence collection)
- Technology Stack (what you use, not what you might use someday)
- Intelligence Collection Priorities (ranked topics)

**Pro tip:** Be specific! "Ransomware" is less useful than "Ransomware targeting Epic EHR systems"

---

### 2. security_stack.md - Security Posture

**What it is:** Honest inventory of security controls you HAVE (not what you want).

**What Claude does with it:**
- Recommends actions using existing tools first
- Identifies gaps that specific threats exploit
- Suggests quick wins before major investments
- Provides realistic recommendations within constraints

**Key sections:**
- What We Have (deployed controls by category)
- What We Monitor (active alerting)
- What We Block (preventive controls)
- Known Gaps (be honest - helps Claude prioritize)
- Detection Coverage (MITRE ATT&CK mapping)

**Pro tip:** Honesty is critical. Overstating capabilities leads to bad recommendations.

---

### 3. templates/*.md - Output Formats

**What they are:** Structure templates that guide Claude's analysis format.

**Available templates:**

#### executive_briefing.md
**For:** Executive leadership, board presentations, strategic decisions
**Focus:** High-level summaries, business impact, strategic recommendations
**Typical length:** 1-2 pages

#### technical_analysis.md
**For:** Security operations teams, threat hunters, incident responders
**Focus:** Detailed attribution, TTPs, detection/response guidance
**Typical length:** 3-5 pages

#### incident_response.md
**For:** Active incident response, crisis management
**Focus:** Immediate actions, investigation priorities, containment steps
**Typical length:** 2-3 pages

#### trend_analysis.md
**For:** Security strategy planning, investment prioritization
**Focus:** Emerging patterns, predictive insights, long-term recommendations
**Typical length:** 3-4 pages

**Pro tip:** Create custom templates for your specific needs (compliance reports, vendor assessments, etc.)

---

## Advanced Customization

### Creating Custom Templates

1. Copy an existing template:
   ```bash
   cp config/templates/executive_briefing.md config/templates/my_custom_template.md
   ```

2. Edit the Markdown file to match your needs

3. Use it by referencing the filename (without .md):
   ```
   You: "Analyze this threat using my_custom_template"
   ```

### Industry-Specific Configurations

Create industry-tailored configs by focusing your PIRs:

**Healthcare Example:**
- Threat Actors: ALPHV, LockBit, Hive
- Crown Jewels: PHI databases, Epic EHR
- Compliance: HIPAA breach notification timelines

**Finance Example:**
- Threat Actors: APT38, Lazarus, FIN7
- Crown Jewels: Transaction systems, customer PII
- Compliance: PCI-DSS, SOX, GLBA

**Manufacturing Example:**
- Threat Actors: APT41, Volt Typhoon
- Crown Jewels: CAD files, manufacturing IP
- Compliance: CMMC, ITAR

### Role-Specific Templates

Create templates for different audiences:
- **CISO Update Template:** Weekly executive summary
- **Board Template:** Quarterly risk reporting
- **SOC Analyst Template:** Tactical hunting guidance
- **Compliance Template:** Audit-ready documentation

---

## Best Practices

### 1. Start Simple, Iterate
Don't try to fill out every field perfectly on day one:
- **Week 1:** Basic PIRs (industry, threat actors, tech stack)
- **Week 2:** Security stack inventory (what you have)
- **Week 3:** Refine based on actual analysis quality
- **Month 2:** Add known gaps and detection coverage

### 2. Keep It Current
Stale configuration = irrelevant recommendations:
- **Quarterly reviews:** Update PIRs and security stack
- **After major changes:** New tools, architecture shifts, incidents
- **Annual strategy:** Align with business priorities

### 3. Version Control (Optional)
Track changes to understand how your program evolves:
```bash
git add config/
git commit -m "Q1 2025: Added cloud security stack, updated PIRs for merger"
```

### 4. Share With Your Team
Configuration should reflect team knowledge:
- Security team reviews `security_stack.md`
- Leadership reviews `pirs.md`
- Analysts create custom templates for recurring analyses

### 5. Protect Sensitive Info
If your config contains internal details:
```bash
# Create private versions
cp config/pirs.md config/pirs.local.md
cp config/security_stack.md config/security_stack.local.md

# Edit .gitignore to exclude
echo "config/*.local.md" >> .gitignore
```

---

## Community Contributions

### Share Your Configurations
Help others in your industry by contributing anonymized configs:

1. Remove sensitive details (company names, specific IPs, etc.)
2. Create PR with your template in `/examples/industry-name/`
3. Help others learn from your approach

### Request Industry Templates
Need a starting point? Check `/examples/` for:
- Healthcare PIRs template
- Financial services PIRs template
- Manufacturing PIRs template
- Retail PIRs template
- Startup security stack (limited budget)
- Enterprise security stack (mature program)

Don't see your industry? Open an issue requesting it!

---

## Troubleshooting

### "Claude isn't using my configuration"

**Check:**
1. Files are in correct location (`config/pirs.md`, not `config/PIRS.md`)
2. Files are valid Markdown (no syntax errors)
3. ConfigManager is loading files (check logs)
4. You're using the right MCP server instance

### "Configuration seems ignored"

**Common causes:**
- Config is too generic (be specific!)
- Missing key sections (Organization Profile, Technology Stack)
- Outdated information (quarterly review needed)

### "Analysis quality decreased after customization"

**Try:**
- Simplify config (less is sometimes more)
- Remove ambiguous priorities (conflicting guidance)
- Ensure honesty in security stack (overselling backfires)

---

## Examples

### Example 1: Healthcare Organization

**pirs.md excerpt:**
```markdown
Industry: Healthcare (Regional hospital system)
Size: 2,500 employees, 3 facilities
Threat Actors: ALPHV/BlackCat, LockBit 3.0, Hive
Technology Stack: Epic EHR, Microsoft 365, Cisco network gear
Crown Jewels: Patient PHI database (2M records), Medical imaging systems
Compliance: HIPAA, mandatory breach notification
```

**security_stack.md excerpt:**
```markdown
EDR: CrowdStrike Falcon (98% coverage, missing medical devices)
SIEM: Splunk Enterprise (90-day retention, 45 use cases)
Email Security: Proofpoint (URL rewriting, attachment sandboxing)
Known Gaps: No segmentation between clinical and corporate networks
```

**Result:** Claude prioritizes ransomware threats to healthcare, suggests Splunk detection rules for lateral movement toward EHR, notes email sandboxing protects against common infection vectors.

---

### Example 2: Startup Tech Company

**pirs.md excerpt:**
```markdown
Industry: SaaS (Cloud-based project management)
Size: 150 employees, fully remote
Threat Actors: APT groups targeting SaaS platforms, insider threats
Technology Stack: AWS, GitHub, Google Workspace, Stripe
Crown Jewels: Source code, customer data, Stripe API keys
Strategic Priority: Maintain SOC 2 compliance for enterprise sales
```

**security_stack.md excerpt:**
```markdown
EDR: Microsoft Defender (free tier, basic coverage)
SIEM: None (using CloudTrail + CloudWatch)
Known Gaps: No EDR on Linux servers, limited log retention (7 days)
Budget: Small (<$100k annually), prefer open-source where possible
```

**Result:** Claude recommends free/cheap detection tools (osquery, Wazuh), focuses on AWS-native security (GuardDuty, Security Hub), suggests SOC 2-aligned controls, acknowledges budget constraints.

---

## Need Help?

**Questions about configuration:**
- Email: matt@coopercybercoffee.com
- Open a GitHub issue
- Check `/examples` directory for templates

**Want to contribute:**
- Submit anonymized configs for your industry
- Create role-specific templates
- Improve documentation

---

**Time Investment:**
- Initial setup: 45 minutes
- Quarterly updates: 15 minutes
- Major changes: 30 minutes

**Return on Investment:**
- 10x more relevant threat intelligence
- Actionable recommendations using existing tools
- Faster decision-making with context-aware analysis
- Better alignment between security and business priorities

---

*Configuration is documentation that makes AI smarter. Invest 45 minutes now, save hours on every analysis.*
