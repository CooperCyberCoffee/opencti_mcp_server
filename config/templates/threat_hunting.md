# Threat Hunting Campaign Template

## Executive Summary

**Hunt Mission:** Based on threat intelligence for {{THREAT_ACTOR}}, conduct proactive hunt across {{ENVIRONMENT_TYPE}} environment to detect potential compromise or precursor activity.

**Hunt Objectives:**
- Validate threat actor TTPs against organizational baseline
- Identify indicators of compromise or suspicious patterns
- Test detection coverage for high-priority techniques
- Generate new detection rules for identified gaps

**Success Metrics:**
- Percentage of priority TTPs hunted
- New detections implemented
- False positive rate
- Hunt completion time

**Resource Requirements:**
- Lead Hunter: Senior threat intelligence analyst
- Duration: {{HUNT_DURATION}}
- Tools Required: SIEM, EDR, threat intelligence platform
- Data Sources: {{REQUIRED_DATA_SOURCES}}

---

## Intelligence Preparation

### Known Threat Actor TTPs

**MITRE ATT&CK Techniques Associated with {{THREAT_ACTOR}}:**

{{TTP_LIST}}

**Kill Chain Distribution:**
{{KILL_CHAIN_ANALYSIS}}

**Priority Techniques for Hunting:**

{{PRIORITY_TTPS}}

---

### Hunt Hypothesis Development

**Primary Hypothesis:**
"We believe {{THREAT_ACTOR}} may be present in {{ENVIRONMENT_TYPE}} based on {{INTELLIGENCE_DRIVER}}. We will test this hypothesis by hunting for {{SPECIFIC_BEHAVIORS}} in {{DATA_SOURCES}}."

**Testing Methodology:**
1. Establish baseline of normal activity for targeted data sources
2. Execute hunt queries across baseline period (30-90 days)
3. Identify anomalies and deviations from baseline
4. Correlate suspicious findings across multiple data sources
5. Validate findings against threat intelligence
6. Document and escalate confirmed threats

---

## Hunt Queries

### Platform: Splunk

**Query 1: Suspicious PowerShell Execution**
```spl
index=windows EventCode=4688 
| where match(CommandLine, "(?i)(powershell.*-enc|powershell.*-e |invoke-expression|iex|downloadstring)")
| eval suspicion_score = case(
    match(CommandLine, "(?i)-enc"), 3,
    match(CommandLine, "(?i)invoke-expression"), 2,
    match(CommandLine, "(?i)downloadstring"), 3,
    1=1, 1
)
| stats count values(CommandLine) as commands sum(suspicion_score) as total_suspicion by host, user
| where total_suspicion > 5 OR count > 10
| sort - total_suspicion
```

**Expected Results:** PowerShell activity with encoded commands or remote download capabilities  
**Baseline Comparison:** Compare against known administrative scripts  
**False Positive Sources:** Legitimate automation, software deployment, patch management  
**Escalation Threshold:** Suspicion score > 10 or activity from non-admin accounts

---

**Query 2: Lateral Movement Detection**
```spl
index=windows (EventCode=4688 OR EventCode=5145 OR EventCode=4624)
| eval is_lateral = case(
    match(CommandLine, "(?i)(wmic|psexec|winrs|winrm|schtasks.*\\\\)"), "yes",
    EventCode=5145 AND ShareName="ADMIN$", "yes",
    EventCode=4624 AND LogonType=3, "yes",
    1=1, "no"
)
| where is_lateral="yes"
| stats count dc(ComputerName) as target_count by user, CommandLine, SourceIP
| where target_count > 3
| sort - target_count
```

**Expected Results:** Remote execution attempts across multiple systems  
**Baseline Comparison:** Verify against authorized system administrator activity  
**False Positive Sources:** IT helpdesk, systems management tools  
**Escalation Threshold:** Non-IT accounts with lateral movement to 3+ systems

---

**Query 3: Credential Access Behavior**
```spl
index=windows (EventCode=4688 OR EventCode=4663 OR EventCode=10)
| eval is_cred_access = case(
    match(CommandLine, "(?i)(mimikatz|sekurlsa|lsadump|procdump.*lsass)"), "yes",
    TargetFilename="C:\\Windows\\System32\\config\\SAM", "yes",
    TargetImage="C:\\Windows\\System32\\lsass.exe" AND GrantedAccess="0x1010", "yes",
    1=1, "no"
)
| where is_cred_access="yes"
| stats count by host, user, CommandLine, TargetFilename
| sort - count
```

**Expected Results:** LSASS memory access, SAM database access, credential dumping tools  
**Baseline Comparison:** Should be ZERO in most environments  
**False Positive Sources:** Legitimate security tools, forensic investigations (authorized)  
**Escalation Threshold:** ANY instance from non-security team should escalate immediately

---

### Platform: Microsoft KQL (Sentinel/Defender)

**Query 1: Suspicious Process Execution with Scoring**
```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "cmd.exe", "wmic.exe", "psexec.exe", "schtasks.exe")
| where ProcessCommandLine has_any ("-enc", "-e ", "invoke-expression", "iex", "downloadstring", "\\\\", "admin$")
| extend SuspicionScore = 
    case(
        ProcessCommandLine has_cs "-enc", 3,
        ProcessCommandLine has "invoke-expression", 2,
        ProcessCommandLine has "downloadstring", 3,
        ProcessCommandLine has "\\\\", 2,
        ProcessCommandLine has "admin$", 2,
        1
    )
| summarize 
    TotalExecutions = count(),
    TotalSuspicion = sum(SuspicionScore),
    UniqueCommands = make_set(ProcessCommandLine, 5)
    by DeviceId, DeviceName, AccountName, InitiatingProcessFileName
| where TotalSuspicion > 5 or TotalExecutions > 10
| order by TotalSuspicion desc
```

---

**Query 2: Credential Dumping Detection**
```kql
DeviceProcessEvents
| where FileName in~ ("mimikatz.exe", "procdump.exe", "dumpert.exe")
    or ProcessCommandLine has_any ("sekurlsa", "lsadump", "sam", "credentials", "lsass")
| join kind=inner (
    DeviceEvents
    | where ActionType == "ProcessPrimaryTokenModified" 
        or ActionType == "LsassMemoryAccess"
) on DeviceId, Timestamp
| project 
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    ActionType,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

---

**Query 3: Lateral Movement via WMI/PSExec**
```kql
DeviceNetworkEvents
| where RemotePort in (135, 445, 5985, 5986)
| where InitiatingProcessFileName in~ ("wmic.exe", "psexec.exe", "winrs.exe")
| summarize 
    TargetCount = dcount(RemoteIP),
    Connections = count(),
    TargetSystems = make_set(RemoteIP, 10)
    by DeviceName, AccountName, InitiatingProcessCommandLine
| where TargetCount >= 3
| order by TargetCount desc
```

---

## Analysis Procedures

### Phase 1: Baseline Establishment

**Critical: Always establish baseline BEFORE running hunt queries**

**Step 1: Define Normal Behavior**
- What PowerShell usage is expected in this environment?
- Which users/systems routinely use these tools?
- What scheduled tasks involve these processes?
- Peak usage times and typical execution patterns?

**Step 2: Baseline Data Collection**
Run historical queries (30-90 days prior to hunt period):
- Process execution frequency by user/system
- Network connection patterns
- Authentication timing and sources
- File system access patterns

**Step 3: Statistical Analysis**
Calculate baseline statistics:
- Mean/median execution counts
- Standard deviation for activity volumes
- Common parent-child process relationships
- Typical command line patterns

---

### Phase 2: Hunt Execution

**Hour 1-2: Initial Sweep**
- Execute all hunt queries across environment
- Quick triage to identify critical findings
- Flag immediate threats for escalation
- Document query execution success/failures

**Hour 3-4: Data Correlation**
- Cross-reference findings across data sources
- Build timeline of suspicious activity
- Map observed behaviors to MITRE ATT&CK
- Identify patterns suggesting coordinated activity

**Hour 5-6: Deep Dive Investigation**
- Focus on highest suspicion score findings
- Collect additional forensic context
- Build comprehensive event timeline
- Determine if activity is isolated or widespread

**Hour 7-8: Validation and Documentation**
- Verify findings against threat intelligence
- Rule out false positives
- Confirm malicious intent
- Document chain of evidence
- Prepare briefing for leadership

---

### Suspicion Scoring Methodology

**Scoring Formula:**
```
Total Suspicion Score = 
    (Temporal Anomaly Points × 1) +
    (Behavioral Anomaly Points × 2) +
    (Network Anomaly Points × 3) +
    (User Context Points × 2) +
    (TTP Match Points × 3)
```

**Scoring Thresholds:**
- **Critical (≥15 points)**: Immediate escalation to incident response
- **High (10-14 points)**: Escalate within 4 hours, priority investigation
- **Medium (5-9 points)**: Investigate during business hours, document findings
- **Low (<5 points)**: Log for trending analysis, no immediate action

---

## Findings Documentation Template

### Finding #{NUMBER}: {{FINDING_TITLE}}

**Classification:** 
- [ ] Benign (False Positive)
- [ ] Suspicious (Requires Monitoring)
- [ ] Confirmed Malicious

**Confidence Level:** {{HIGH/MEDIUM/LOW}}

**Evidence Chain:**
```
Process Execution:
- Process: {{PROCESS_NAME}}
- Command Line: {{COMMAND_LINE}}
- Parent Process: {{PARENT_PROCESS}}
- User: {{USER_ACCOUNT}}
- Host: {{HOSTNAME}}
- Timestamp: {{TIMESTAMP}}

Network Activity:
- Source IP: {{SOURCE_IP}}
- Destination IP: {{DEST_IP}}
- Port: {{PORT}}
- Protocol: {{PROTOCOL}}

File System Activity:
- Files Created: {{FILE_PATHS}}
- Files Modified: {{MODIFIED_FILES}}
```

**MITRE ATT&CK Mapping:**
- Tactics: {{TACTIC_IDS}}
- Techniques: {{TECHNIQUE_IDS}}
- Sub-techniques: {{SUB_TECHNIQUE_IDS}}

**Analysis:**
This activity is {{BENIGN/SUSPICIOUS/MALICIOUS}} because:
1. {{REASON_1}}
2. {{REASON_2}}
3. {{REASON_3}}

**Recommended Actions:**

**Immediate (0-4 hours):**
- [ ] {{IMMEDIATE_ACTION_1}}
- [ ] {{IMMEDIATE_ACTION_2}}

**Short-term (1-2 weeks):**
- [ ] Create detection rule: {{DETECTION_LOGIC}}
- [ ] Enhance monitoring for: {{MONITORING_ENHANCEMENT}}

---

## Detection Engineering Recommendations

### New Detection Rules to Create

**Rule #1: {{DETECTION_NAME}}**
```
Description: {{DESCRIPTION}}
Data Source: {{DATA_SOURCE}}
Logic: {{DETECTION_LOGIC}}
Severity: {{HIGH/MEDIUM/LOW}}
False Positive Rate: {{ESTIMATED_FP_RATE}}
```

---

### Coverage Gaps Identified

**Gap #1: {{GAP_DESCRIPTION}}**
- Current State: {{WHAT_WERE_MISSING}}
- Risk: {{WHY_THIS_MATTERS}}
- Recommendation: {{HOW_TO_FIX}}
- Priority: {{HIGH/MEDIUM/LOW}}

---

## Lessons Learned

### What Worked Well

1. {{SUCCESS_1}}
2. {{SUCCESS_2}}
3. {{SUCCESS_3}}

### What Could Be Improved

1. {{CHALLENGE_1}} → {{HOW_TO_IMPROVE}}
2. {{CHALLENGE_2}} → {{HOW_TO_IMPROVE}}

### New Hunting Opportunities Discovered

1. **{{HUNT_OPPORTUNITY_1}}**
   - Rationale: {{WHY_THIS_IS_INTERESTING}}
   - Data Requirements: {{WHAT_YOULL_NEED}}

---

## Next Steps

### Immediate Actions (24-48 Hours)

1. **Deploy High-Priority Detections**
   - [ ] {{DETECTION_1}} - Owner: {{OWNER}}
   - [ ] {{DETECTION_2}} - Owner: {{OWNER}}

2. **Brief Leadership**
   - [ ] Prepare executive summary
   - [ ] Schedule debrief meeting

3. **Threat Intelligence Updates**
   - [ ] Update threat actor profile with new TTPs observed
   - [ ] Share findings with threat intel team

---

### Short-term Actions (1-2 Weeks)

4. **Fill Coverage Gaps**
   - [ ] {{GAP_1}} - Owner: {{OWNER}}
   - [ ] {{GAP_2}} - Owner: {{OWNER}}

5. **Conduct Follow-up Hunt**
   - [ ] Focus area: {{RELATED_TTPS}}
   - [ ] Lead: {{ANALYST_NAME}}

---

## Validation Checklist

**Before Finalizing Hunt Report:**

- [ ] All findings documented with evidence chain
- [ ] Confidence levels assigned with justification
- [ ] MITRE ATT&CK mapping completed
- [ ] False positives identified and documented
- [ ] Recommended detections are specific and actionable
- [ ] Coverage gaps prioritized by risk
- [ ] Lessons learned captured
- [ ] Next steps assigned with owners and due dates
- [ ] Executive summary prepared
- [ ] Report reviewed by peer analyst

---

## CRITICAL SECURITY REMINDER

**This is a threat hunting template powered by AI analysis.**

**ALWAYS validate findings before taking action:**
- [ ] Confirmed findings against original raw data
- [ ] Ruled out all false positive scenarios
- [ ] Verified with multiple independent data sources
- [ ] Consulted with threat intelligence team
- [ ] Assessed organizational context and business impact
- [ ] Documented complete chain of evidence
- [ ] Obtained approval before containment actions

**AI-generated analysis is a starting point, not a conclusion.**

**Human expertise and validation are MANDATORY for all security decisions.**

---

**Hunt Campaign Classification:** TLP:CLEAR

**Report Generated By:** Cooper Cyber Coffee AI-Augmented Threat Hunting  
**Generation Date:** {{REPORT_DATE}}
