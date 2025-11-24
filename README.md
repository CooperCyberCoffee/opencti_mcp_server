# Cooper Cyber Coffee OpenCTI MCP Server

**Connect Claude Desktop to OpenCTI for AI-augmented threat intelligence analysis**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-0.4.2-blue.svg)](CHANGELOG.md)
[![OpenCTI](https://img.shields.io/badge/OpenCTI-6.x-green.svg)](https://www.opencti.io/)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![Claude Desktop](https://img.shields.io/badge/Claude-Desktop-purple.svg)](https://claude.ai/)

[![TLP Support](https://img.shields.io/badge/TLP-filtering-green.svg)](SECURITY.md)
[![Local Deploy](https://img.shields.io/badge/air--gapped-capable-blue.svg)](README.md#air-gapped-deployment)
[![Deps Pinned](https://img.shields.io/badge/dependencies-pinned-blue.svg)](requirements.txt)

> **🎉 What's New in v0.4.2**
> **Expanded IOC Enrichment:** The `search_observable` tool now auto-detects and searches **6 observable types** - IPv4, IPv6, domains, URLs, emails, and file hashes (MD5, SHA1, SHA256). No more guessing which tool to use!
> **[Quick Links](#-quick-links)** | **[Release Notes](#-v042---ioc-enrichment-expansion-release)**

---

## 🔗 Quick Links

**⚡ Getting Started (First Time Users):**
- [Installation & Setup](#installation--setup) - 15 minute quickstart
- [What This Is](#what-this-is) - High-level overview
- [Why This Matters](#why-this-matters) - The problem this solves
- [Who This Is For](#who-this-is-for) - Is this right for you?

**🎯 Core Functionality:**
- [Available Tools](#available-tools) - 13 threat intelligence tools
- [Usage Examples](#usage-examples) - Real-world queries with expected outputs
- [How It Works](#how-it-works-architecture) - System architecture explained
- [What's New in v0.4.2](#-v042---ioc-enrichment-expansion-release) - Latest features

**🔧 Configuration & Customization:**
- [Configuration Overview](#configuration--customization) - **START HERE** to make this tool yours
- [Priority Intelligence Requirements (PIRs)](#1-priority-intelligence-requirements-pirs) - Define your threat priorities
- [Security Stack Profile](#2-security-stack-profile) - Document your tools and environment
- [Analysis Templates](#3-analysis-templates) - Standardize professional outputs
- [Before/After Examples](#example-before-and-after-customization) - See the transformation

**🔒 Security & Compliance (CRITICAL):**
- [Data Governance Notice](#️-critical-data-governance-notice) - **READ FIRST** - What gets sent to Claude
- [TLP Filtering](#traffic-light-protocol-tlp-filtering) - Prevent sensitive data leakage
- [Compliance Considerations](#compliance-considerations) - CMMC, NIST, HIPAA, SOC 2
- [Recommended Use Cases](#recommended-use-cases-safe) - What's safe to query
- [NOT Recommended Use Cases](#not-recommended-unsafe-use-cases) - What to avoid
- [Security Features](#security) - Input validation, audit logging, air-gap support

**🏢 Enterprise & Air-Gapped Deployment:**
- [Air-Gapped Overview](#-air-gapped-deployment--local-llm-support) - Local LLM deployment
- [Cloud vs Local Comparison](#cloud-options-compared) - Decision matrix
- [Local LLM Setup](#setting-up-local-llm-deployment) - Installation guide
- [Hardware Requirements](#hardware-requirements) - What you need for local deployment
- [CMMC Compliance](#cmmc-cui-in-cloud) - Defense contractor requirements

**📋 Reference & Support:**
- [Troubleshooting](#troubleshooting) - Common issues and solutions
- [Audit Logging](#audit-logging) - SIEM integration, compliance logging
- [Contributing](#contributing) - How to contribute code or docs
- [CHANGELOG.md](CHANGELOG.md) - Full release history
- [MIGRATION.md](MIGRATION.md) - Upgrade guides
- [SECURITY.md](SECURITY.md) - Security policy and vulnerability reporting

**🎯 By Use Case:**
- **Defense Contractors:** [CMMC](#cmmc-cui-in-cloud) | [Air-Gapped](#-air-gapped-deployment--local-llm-support) | [CUI Handling](#compliance-considerations)
- **Healthcare:** [HIPAA](#hipaa) | [Data Governance](#️-data-governance--security-considerations) | [Local LLM](#local-llm-air-gapped)
- **Financial Services:** [Compliance](#financial-services-pci-dss-glba) | [SOC 2](#soc-2-type-ii--iso-27001-data-governance)
- **Small Organizations:** [Who This Is For](#who-this-is-for) | [Time Savings](#time-comparison) | [Getting Started](#installation--setup)

---

## ⚠️ CRITICAL: Data Governance Notice

**This tool sends threat intelligence queries to an AI service for analysis.**

**Default Configuration:** Claude Desktop → Anthropic API (cloud)
**Current TLP Policy:** Only **TLP:CLEAR** data allowed by default

### Cloud LLM Options

**Claude Pro (Default):**
- ✅ **Safe for:** Public OSINT threat intelligence (TLP:CLEAR/WHITE)
- ⚠️ **Filtered out:** TLP:RED, TLP:AMBER, TLP:GREEN, and unmarked data
- 🔒 **Configurable:** Edit `config/tlp_policy.yaml` to customize

**Claude Enterprise (Organizational Accounts):**
- ⚠️ **Enhanced security** over Claude Pro, but still cloud-based
- ⚠️ **May be suitable for:** TLP:AMBER (with organizational approval)
- ❌ **Still NOT for:** CUI, classified, ITAR-controlled data

### Local LLM (For Sensitive Data)

- 🔒 **For sensitive data:** Use local LLM (Llama, Mistral, etc.) instead of any cloud option
- ✅ **Suitable for:** TLP:AMBER, TLP:RED, classified, CUI, proprietary intelligence
- 🏢 **Air-gapped:** Deploy completely offline for classified environments
- 📋 **See:** [Air-Gapped Deployment & Local LLM Support](#-air-gapped-deployment--local-llm-support)

**📋 Review:** [Data Governance & Security Considerations](#️-data-governance--security-considerations) section before production use

**You are responsible for ensuring queries comply with your organization's data handling policies.**

---

An open-source educational project demonstrating how to bridge Claude Desktop with OpenCTI's threat intelligence platform using the Model Context Protocol (MCP). Ask questions about threats in natural language and get instant, contextualized answers from your threat intelligence database.

---

## 🎉 v0.4.2 - IOC Enrichment Expansion Release!

**Latest release:** Expanded IOC enrichment with automatic observable type detection

### 🔍 Multi-Observable Search (Automatic Type Detection)
- ✅ **6 observable types** - IPv4, IPv6, domains, URLs, emails, file hashes (MD5, SHA1, SHA256)
- ✅ **Auto-detection** - No need to specify type, just provide the value
- ✅ **Type-specific recommendations** - Firewall rules for IPs, DNS blocking for domains, etc.
- ✅ **Backward compatible** - All previous hash searches work identically
- 🎯 **One tool for all IOCs** - Unified `search_observable` replaces hash-only search

**Example queries:**
```
"Search for 192.168.1.1"           → Auto-detects IPv4
"Search for evil.com"               → Auto-detects domain
"Search for 44d88612fea8a8f36..."  → Auto-detects MD5 hash
"Search for http://malicious.com"   → Auto-detects URL
"Search for attacker@evil.com"      → Auto-detects email
```

### Previous Features (v0.4.0-0.4.1)

**📊 Progress Reporting** - Real-time status updates for long operations
**⛔ Operation Cancellation** - User can abort at any time with clean cleanup
**⚡ Server-Side TLP Filtering** - Filters data before sending to LLM context window (v0.4.0)
**🛡️ Rate Limiting** - DoS protection (60 calls/minute default, v0.4.0)
**📊 Audit Logging** - ISO 8601 timestamps, SIEM-compatible JSON format (v0.4.0)

📖 **Configuration Guide:** [config/README.md](config/README.md) - Quick start in 15 minutes
🔄 **Migration Guide:** [MIGRATION.md](MIGRATION.md) - Upgrade from v0.1.0 in 30 seconds
📋 **Changelog:** [CHANGELOG.md](CHANGELOG.md) - See what's new

---

## What This Is

This MCP server connects Claude Desktop to your OpenCTI threat intelligence platform, enabling you to:

- **Ask questions in plain English** instead of writing complex database queries
- **Get instant threat intelligence** without clicking through multiple dashboards
- **Analyze relationships** between threat actors, malware, campaigns, and TTPs
- **Search across your entire threat database** using names, aliases, or MITRE IDs

Think of it as giving Claude direct access to your threat intelligence database, so you can have natural conversations about threats instead of hunting through data.

---

## Why This Matters

**The Problem:** Traditional threat intelligence platforms require:
- Complex query languages to find information
- Multiple clicks through dashboards to see relationships
- Manual correlation of threat data
- Time-intensive analysis processes

**The Solution:** With this MCP server, you can:

```
You: "What TTPs does APT28 use?"
Claude: *Instantly shows 47 MITRE ATT&CK techniques with descriptions*

You: "Which ones target email?"
Claude: *Filters to spearphishing techniques with kill chain phases*

You: "Show me recent indicators for those campaigns"
Claude: *Retrieves IOCs with context and analysis templates*
```

---

## Who This Is For

**Organizations below the cyber poverty line:**
- Small companies in critical supply chains
- Resource-constrained security teams
- Organizations that need CTI but can't afford enterprise platforms

**Requirements:**
- Security professional with CTI fundamentals
- OpenCTI 6.x (free, self-hosted)
- Claude Pro ($20/month) or local LLM
- Basic Linux/cloud infrastructure

**What you get:**
- AI-augmented threat analysis
- Professional analyst templates
- Natural language queries
- No vendor lock-in

**What you trade off:**
- No enterprise support contracts
- No SLAs or compliance certifications
- DIY setup and maintenance

---

## Time Comparison

**Threat Actor TTP Analysis:**
- Manual: 1-2 hours (MITRE ATT&CK lookup, spreadsheet, analysis, report)
- AI-Assisted: 10-15 minutes (query + validation + customization)
- **Time Saved: ~85%**

**Incident Response Playbook:**
- Manual: 4-8 hours (research, template adaptation, review)
- AI-Assisted: 15-20 minutes (generation + validation + org-specific edits)
- **Time Saved: ~90%**

**Strategic Comparison (APT28 vs APT29):**
- Manual: 2-4 hours (dual research, comparison matrix, analysis)
- AI-Assisted: 10-15 minutes (query + validation + context)
- **Time Saved: ~85%**

*Note: Times include human validation - critical for accuracy*

---

## Quick Example: Before vs After

**Before (Traditional OpenCTI Workflow):**
1. Log into OpenCTI web interface
2. Navigate to Threat Actors section
3. Search for "APT28"
4. Click through to entity page
5. Scroll to find TTPs section
6. Click on "Attack Patterns" relationship
7. Manually read through each TTP
8. Open separate tab for MITRE ATT&CK reference
9. Cross-reference techniques
10. Copy/paste into analysis document

**After (With OpenCTI MCP Server):**
```
You: "What are APT28's main techniques?"
Claude: *Shows comprehensive TTP list with MITRE IDs and descriptions in seconds*
```

---

## Available Tools

The MCP server provides 13 tools organized by function:

### Core Tools

#### 1. validate_opencti_connection
**What it does:** Checks if OpenCTI is reachable, validates credentials, and verifies version compatibility.

**Example query:** "Check my OpenCTI connection"

**What you get:**
- OpenCTI version number
- Connection status
- Database health
- Active connectors

---

#### 2. get_recent_indicators_with_analysis
**What it does:** Retrieves recent Indicators of Compromise (IOCs) with professional analysis templates.

**Example query:** "Show me IOCs from the last 7 days"

**What you get:**
- Recent indicators (IPs, domains, hashes, URLs)
- Confidence scores
- Threat context
- Analysis templates for investigation

---

#### 3. search_observable
**What it does:** Searches for threat intelligence indicators by observable value with automatic type detection. Supports IPv4/IPv6 addresses, domain names, URLs, email addresses, and file hashes (MD5, SHA1, SHA256).

**Example queries:**
- "Search for IP 192.168.1.1"
- "Search for domain evil.com"
- "Search for hash 44d88612fea8a8f36de82e1278abb02f"

**What you get:**
- Indicator details with auto-detected type
- Related malware families
- Associated threat actors
- Type-specific recommended actions (firewall rules for IPs, DNS blocking for domains, etc.)

---

#### 4. search_entities
**What it does:** Universal search across all OpenCTI entities (threat actors, malware, campaigns, vulnerabilities, etc.)

**Example query:** "Search for entities related to ransomware"

**What you get:**
- Matching entities with entity IDs
- Entity types (Malware, Campaign, Threat-Actor, etc.)
- MITRE IDs (when applicable)
- Aliases and alternative names
- Usage hints for querying relationships

---

#### 5. get_entity_relationships
**What it does:** Gets all inbound and outbound relationships for any entity in your threat database.

**Example query:** "Show me all relationships for APT28"

**What you get:**
- Inbound relationships (what targets this entity)
- Outbound relationships (what this entity targets/uses)
- Relationship types (uses, targets, attributed-to, etc.)
- Connected entity details

---

### Threat Actor Tools

#### 6. get_threat_actor_ttps
**What it does:** Gets all MITRE ATT&CK techniques (TTPs) used by a specific threat actor.

**Example query:** "What techniques does APT28 use?"

**What you get:**
- Complete list of TTPs
- MITRE ATT&CK IDs
- Technique descriptions
- Kill chain phases
- Threat actor aliases

**Accepts:** Threat actor name, alias, MITRE ID (G0007), or entity ID

---

### Malware Tools

#### 7. get_malware
**What it does:** Searches for malware entities in your threat database.

**Example query:** "Find information about Emotet"

**What you get:**
- Malware details
- Alternative names and aliases
- Associated threat actors
- Malware family information

---

#### 8. get_malware_techniques
**What it does:** Gets all MITRE ATT&CK techniques used by specific malware.

**Example query:** "What techniques does Emotet use?"

**What you get:**
- MITRE ATT&CK techniques
- Technique descriptions
- Kill chain phases
- Malware aliases

**Accepts:** Malware name, alias, or entity ID

---

### Campaign Tools

#### 9. get_campaign_details
**What it does:** Gets comprehensive information about a threat campaign including attributed threat actors, malware used, and TTPs.

**Example query:** "Tell me about the SolarWinds compromise"

**What you get:**
- Campaign description
- First seen / last seen dates
- Attributed threat actors
- Malware used in campaign
- Attack patterns (TTPs)
- Campaign aliases

**Accepts:** Campaign name, alias, or entity ID

---

### MITRE ATT&CK Tools

#### 10. get_attack_patterns
**What it does:** Searches for MITRE ATT&CK techniques and tactics.

**Example query:** "Show me attack patterns for spearphishing"

**What you get:**
- Attack pattern details
- MITRE ATT&CK IDs
- Tactic and technique information
- Kill chain phases
- Descriptions and context

---

### Vulnerability Tools

#### 11. get_vulnerabilities
**What it does:** Searches for CVEs and vulnerability information.

**Example query:** "Search for Log4j vulnerabilities"

**What you get:**
- CVE identifiers
- Vulnerability descriptions
- CVSS scores
- Affected systems
- Related exploits and malware

---

### Strategic Analysis

#### 12. get_threat_landscape_summary
**What it does:** Generates a strategic overview of the current threat landscape based on recent activity.

**Example query:** "Give me a threat landscape summary for the last 30 days"

**What you get:**
- Recent threat trends
- Active threat actors
- Emerging malware families
- Common attack patterns
- Strategic recommendations

---

### Report Intelligence

#### 13. get_reports
**What it does:** Searches and retrieves analytical threat intelligence reports from OpenCTI with filtering capabilities.

**Example queries:**
- "Find reports about APT28"
- "Show me recent ransomware reports"
- "Get high-confidence reports from the last 30 days"

**What you get:**
- Report title and description
- Published date and confidence score
- Report types (threat-report, internal-report, etc.)
- Labels and tags
- Count of referenced entities (IOCs, threat actors, malware)
- Creation and modification timestamps

**Filters:**
- **Keywords:** Search by threat actor, malware, campaign names
- **Date range:** Reports published after specific date (YYYY-MM-DD)
- **Confidence:** Minimum confidence level (0-100%)
- **Limit:** Up to 50 reports per query

**Use cases:**
- Find all reports about specific threat actors
- Discover recent threat intelligence analysis
- Identify high-confidence strategic reports
- Track campaign documentation over time

---

## Prerequisites

Before you begin, make sure you have:

### 1. Python 3.9 or Higher

**Check your version:**
```bash
python --version
# or
python3 --version
```

**Expected output:** `Python 3.9.x` or higher

**Don't have Python?** Download from [python.org](https://www.python.org/downloads/)

---

### 2. Claude Desktop

**What it is:** A desktop application that runs Claude AI locally and supports MCP servers.

**Download:** [claude.ai/download](https://claude.ai/download)

**Supported platforms:** macOS, Windows

**Note:** You'll need a Claude Pro subscription ($20/month) to use MCP servers.

---

### 3. OpenCTI 6.x Instance

**What it is:** An open-source threat intelligence platform for storing and managing threat data.

**You have two options:**

**Option A: Use Existing OpenCTI Instance**
- If your organization already has OpenCTI deployed, get the URL and API token from your admin
- Make sure it's version 6.x (earlier versions not supported)

**Option B: Set Up Your Own OpenCTI**
- Follow the [OpenCTI installation guide](https://docs.opencti.io/latest/deployment/overview/)
- Quickest method: Use Docker Compose
- Minimum requirements: 4GB RAM, 10GB disk space

**Quick OpenCTI setup with Docker:**
```bash
git clone https://github.com/OpenCTI-Platform/docker.git opencti-docker
cd opencti-docker
docker-compose up -d
```

Wait 2-3 minutes for startup, then access OpenCTI at `http://localhost:8080`

Default credentials: `admin@opencti.io` / `admin`

**Get your API token:**
1. Log into OpenCTI web interface
2. Click your profile (top right)
3. Go to "Settings" → "API Access"
4. Create a new token or copy existing token

---

### 4. Git

**Check if installed:**
```bash
git --version
```

**Don't have Git?** Download from [git-scm.com](https://git-scm.com/downloads)

---

## Installation & Setup

### Step 1: Clone the Repository

```bash
# Clone the repository
git clone https://github.com/CooperCyberCoffee/opencti_mcp_server.git
cd opencti_mcp_server
```

**Expected output:**
```
Cloning into 'opencti_mcp_server'...
remote: Counting objects: 100% ...
Resolving deltas: 100% ...
```

---

### Step 2: Install Python Dependencies

**Create a virtual environment (recommended):**

```bash
# Create virtual environment
python -m venv venv

# Activate it
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

**Your prompt should change to show `(venv)` at the beginning.**

**Install dependencies:**

```bash
pip install -r requirements.txt
```

**Expected output:**
```
Successfully installed mcp pycti aiohttp python-dotenv ...
```

**Troubleshooting:**
- If you get "pip: command not found", try `python -m pip install -r requirements.txt`
- If you see permission errors, make sure your virtual environment is activated

---

### Step 3: Configure Environment Variables

**Create a `.env` file** in the project root directory:

```bash
# Create .env file
touch .env

# Edit with your favorite text editor
nano .env  # or vim, code, notepad, etc.
```

**Add these variables:**

```bash
# OpenCTI Configuration
OPENCTI_URL=http://localhost:8080
OPENCTI_TOKEN=your-api-token-here
OPENCTI_SSL_VERIFY=false

# Optional: Enable debug logging
# DEBUG=true
```

**Replace these values:**
- `OPENCTI_URL`: Your OpenCTI instance URL (e.g., `https://opencti.yourcompany.com`)
- `OPENCTI_TOKEN`: Your API token from OpenCTI (from Prerequisites step 3)
- `OPENCTI_SSL_VERIFY`: Set to `false` for local dev, `true` for production with valid SSL

**Save and close the file.**

**Security note:** Never commit `.env` to git (it's already in `.gitignore`)

---

### Step 4: Test the MCP Server

**Run the server directly to verify it works:**

```bash
python main.py
```

**Expected output:**
```
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║          Cooper Cyber Coffee OpenCTI MCP Server                       ║
║                                                                       ║
║  Version: 0.4.2                                                       ║
║  OpenCTI: 6.x                                                         ║
...
[INFO] Connected to OpenCTI at http://localhost:8080
[INFO] OpenCTI validation successful (version: 6.x.x, data: available, connectors: X active)
```

**Press Ctrl+C to stop the test.**

**If you see errors:**
- "Connection refused" → Check that OpenCTI is running
- "Authentication failed" → Verify your API token in `.env`
- "Module not found" → Run `pip install -r requirements.txt` again

---

### Step 5: Configure Claude Desktop

**Locate your Claude Desktop config file:**

**macOS:**
```
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

**Linux:**
```
~/.config/Claude/claude_desktop_config.json
```

**Edit the config file** (create if it doesn't exist):

```json
{
  "mcpServers": {
    "opencti": {
      "command": "/full/path/to/venv/bin/python",
      "args": [
        "-m",
        "opencti_mcp"
      ],
      "env": {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "your-api-token-here",
        "OPENCTI_SSL_VERIFY": "false"
      }
    }
  }
}
```

**Important: Replace these values:**

1. **`command` path:** Full path to Python in your virtual environment
   ```bash
   # Find the full path:
   # macOS/Linux:
   which python

   # Windows:
   where python
   ```

   Example paths:
   - macOS: `/Users/yourname/opencti_mcp_server/venv/bin/python`
   - Windows: `C:\\Users\\yourname\\opencti_mcp_server\\venv\\Scripts\\python.exe`
   - Linux: `/home/yourname/opencti_mcp_server/venv/bin/python`

2. **Environment variables:** Use the same values from your `.env` file

**Save the file.**

---

### Step 6: Restart Claude Desktop

**Completely quit and restart Claude Desktop:**

**macOS:**
- Press Cmd+Q or right-click dock icon → Quit
- Reopen from Applications

**Windows:**
- Right-click system tray icon → Exit
- Reopen from Start Menu

**Linux:**
- Close all windows and kill process if needed
- Relaunch application

---

### Step 7: Verify the Connection

**Open Claude Desktop and look for the MCP indicator:**

1. Open a new conversation
2. Look for a small tools icon or "MCP" indicator in the interface
3. You should see "opencti" listed as an available server

**Test with a simple query:**

```
You: "Check my OpenCTI connection"
```

**Expected response:**
```
Claude: I'll check your OpenCTI connection...

✅ Connected to OpenCTI
Version: 6.x.x
Status: Ready
Database: Contains threat intelligence data
Active connectors: X
```

**If the server doesn't appear:**
1. Check Claude Desktop config file for JSON syntax errors
2. Verify the Python path is correct and absolute (not relative)
3. Check Claude Desktop logs (Help → Show Logs)
4. Make sure you fully quit and restarted Claude Desktop

---

## Usage Examples

Once connected, you can ask Claude questions about your threat intelligence in natural language:

### Simple Queries

**Threat Actor Information:**
```
You: "What is APT28?"

Claude: *Shows threat actor details, aliases (Fancy Bear, Sofacy),
        country of origin, and summary of activities*
```

**Malware Details:**
```
You: "Tell me about Emotet"

Claude: *Provides malware family information, capabilities,
        distribution methods, and associated threat actors*
```

**CVE Lookup:**
```
You: "Search for CVE-2021-44228"

Claude: *Shows Log4Shell vulnerability details, CVSS score,
        affected systems, and related threats*
```

---

### Technical Queries

**TTP Analysis:**
```
You: "What techniques does Akira ransomware use?"

Claude: *Lists MITRE ATT&CK techniques with IDs, descriptions,
        and kill chain phases*
```

**Observable Search (Multi-Type Auto-Detection):**
```
You: "Search for 192.168.1.100"

Claude: *Auto-detects IPv4, shows threat intel + firewall blocking rules*

You: "Search for evil-domain.com"

Claude: *Auto-detects domain, shows threat intel + DNS blocking recommendations*

You: "Search for 44d88612fea8a8f36de82e1278abb02f"

Claude: *Auto-detects MD5 hash, shows associated malware and threat context*

You: "Search for http://malicious-site.com/payload.exe"

Claude: *Auto-detects URL, shows threat intel + web filtering guidance*

You: "Search for attacker@phishing.com"

Claude: *Auto-detects email, shows threat intel + email security recommendations*

You: "Search for 2001:0db8:85a3::8a2e:0370:7334"

Claude: *Auto-detects IPv6, shows threat intel + network blocking rules*
```

**Relationship Mapping:**
```
You: "Show me relationships for APT29"

Claude: *Displays all connections: used malware, targeted sectors,
        associated campaigns, and TTPs*
```

---

### Analysis Queries

**Campaign Analysis:**
```
You: "Analyze the SolarWinds compromise campaign"

Claude: *Provides comprehensive campaign details: timeline,
        attributed actors, malware used, TTPs, and impact*
```

**Threat Landscape:**
```
You: "Give me a threat landscape summary for retail organizations"

Claude: *Generates strategic overview: active threats to retail,
        common attack patterns, and defensive recommendations*
```

**IOC Retrieval:**
```
You: "Show me recent indicators from the last 7 days with high confidence"

Claude: *Lists recent IOCs with analysis templates,
        confidence scores, and investigation guidance*
```

**Report Research:**
```
You: "Find reports about ransomware published in the last 90 days with high confidence"

Claude: *Returns analytical reports with summaries, confidence scores,
        referenced entities, and direct links to full reports*
```

---

### Complex Queries (Chaining Multiple Tools)

**Multi-Step Investigation:**
```
You: "Find APT28, show me their TTPs, then search for recent
      indicators related to those techniques"

Claude: *Chains multiple tool calls:*
        1. Resolves APT28 entity
        2. Gets their TTPs
        3. Searches for related IOCs
        4. Correlates findings
```

**Comparative Analysis:**
```
You: "Compare the techniques used by Emotet and TrickBot"

Claude: *Retrieves TTPs for both malware families and
        highlights similarities and differences*
```

---

## How It Works (Architecture)

```
┌─────────────────┐
│  Claude Desktop │
│                 │
│  "What TTPs     │
│   does APT28    │
│   use?"         │
└────────┬────────┘
         │
         │ MCP Protocol
         │ (JSON-RPC)
         ▼
┌─────────────────┐
│   OpenCTI MCP   │
│     Server      │
│                 │
│  • Entity       │
│    Resolution   │
│  • Caching      │
│  • Tool Routing │
└────────┬────────┘
         │
         │ pycti Library
         │ (Python API)
         ▼
┌─────────────────┐
│   OpenCTI 6.x   │
│    Platform     │
│                 │
│  • PostgreSQL   │
│  • Elasticsearch│
│  • Redis        │
└─────────────────┘
```

**Key Components:**

1. **Claude Desktop** - User interface for natural language queries
2. **MCP Protocol** - Standard protocol for AI model context
3. **OpenCTI MCP Server** (this project) - Translation layer with:
   - Universal entity resolution (names, aliases, MITRE IDs, UUIDs)
   - Smart caching (15-minute TTL)
   - 13 specialized tools
   - Pure pycti implementation (no GraphQL)
4. **OpenCTI Platform** - Threat intelligence database

**What happens when you ask a question:**

1. You type a question in Claude Desktop
2. Claude decides which MCP tools to call
3. MCP server receives tool call via JSON-RPC
4. Server resolves entity (e.g., "APT28" → UUID)
5. Server queries OpenCTI using pycti library
6. Results are formatted and cached
7. Claude receives structured data
8. Claude presents information in natural language

---

## Configuration & Customization

### Understanding the Config Files

This MCP server becomes **organizationally aware** through three key configuration files in the `config/` directory. These files encode your organization's security priorities, environment, and analysis preferences - transforming generic AI responses into tailored intelligence.

---

### 1. Priority Intelligence Requirements (PIRs)

**File:** `config/pirs.md`

**What it is:** A structured document defining what threat intelligence questions matter most to YOUR organization.

**Why it matters:** 
- Focuses AI analysis on threats relevant to your business
- Provides context about your industry, geography, tech stack
- Guides AI to prioritize certain threat actors or attack types
- Ensures recommendations align with organizational priorities

**Example PIR structure:**
```markdown
# Priority Intelligence Requirements

## Organizational Context
- Industry: Healthcare / Regional hospital system
- Geography: Southeast United States
- Revenue: $500M annually
- Critical assets: Patient records (EHR), medical devices, pharmacy systems

## Priority Questions

### PIR 1: Ransomware Targeting Healthcare
**Question:** What ransomware groups are actively targeting healthcare organizations?
**Why it matters:** Primary threat to operations and patient safety
**Decision supported:** Ransomware defense investment prioritization

### PIR 2: Medical Device Vulnerabilities
**Question:** What vulnerabilities affect our deployed medical devices?
**Why it matters:** Patient safety risk, regulatory compliance (FDA)
**Decision supported:** Device patching and replacement priorities

### PIR 3: State-Sponsored Threats to Healthcare Data
**Question:** Are nation-state actors targeting healthcare research or patient data?
**Why it matters:** Intellectual property protection, HIPAA compliance
**Decision supported:** Enhanced monitoring for APT activity
```

**How Claude uses this:**
When you query threat intelligence, Claude references your PIRs to:
- Filter relevant threats (focuses on healthcare ransomware, not retail POS malware)
- Prioritize analysis (emphasizes threats to medical devices)
- Provide context-aware recommendations (understands your regulatory environment)
- Connect threats to business impact (explains risk to patient safety, not just "system compromise")

**Customization:**
Edit `config/pirs.md` to reflect your organization's:
- Industry and sector
- Geographic footprint
- Critical assets and crown jewels
- Regulatory requirements
- Threat concerns (ransomware, IP theft, supply chain, etc.)
- Technology stack and vendors

---

### 2. Security Stack Profile

**File:** `config/security_stack.md`

**What it is:** A description of your security environment, tools, and defensive posture.

**Why it matters:**
- AI provides recommendations compatible with YOUR tools
- Suggests detection rules for YOUR SIEM/EDR platform
- Accounts for existing controls (doesn't recommend what you already have)
- Provides realistic guidance based on your capabilities

**Example Security Stack:**
```markdown
# Security Stack Profile

## Detection & Response
- SIEM: Splunk Enterprise (version 9.x)
- EDR: CrowdStrike Falcon (deployed on 1,200 endpoints)
- Network: Palo Alto NGFWs, no IDS/IPS
- Email Security: Proofpoint (TAP module enabled)

## Threat Intelligence
- OpenCTI (this MCP server)
- MISP feeds: AlienVault OTX, abuse.ch
- Commercial feeds: None (budget constraints)

## Identity & Access
- Active Directory (on-premises)
- Azure AD for cloud services
- MFA: Duo (deployed for VPN, not yet for all apps)

## Gaps & Limitations
- No DLP solution deployed
- Limited cloud visibility (AWS, no CSPM)
- SOC team: 2 analysts (8am-6pm coverage, no 24/7)
- No dedicated threat hunting program
```

**How Claude uses this:**
- **Detection recommendations:** "Add this Splunk search..." (not generic SIEM guidance)
- **Tool-specific queries:** Provides CrowdStrike Falcon hunt queries (not generic EDR)
- **Realistic advice:** Understands 2-person team constraints, suggests automation
- **Gap awareness:** Knows you have no DLP, recommends compensating controls
- **Platform compatibility:** Won't recommend Azure Sentinel queries for Splunk environment

**Customization:**
Document your:
- SIEM/SOAR platforms (with versions)
- EDR/XDR solutions
- Network security tools
- Cloud security posture
- Identity and access management
- Team size and coverage hours
- Budget constraints
- Known gaps in coverage

---

### 3. Analysis Templates

**Location:** `config/templates/`

**What they are:** Structured frameworks that guide Claude to produce consistent, professional threat intelligence output.

**Available templates:**

#### Executive Briefing (`executive_briefing.md`)
**Use case:** Board presentations, CISO updates, business stakeholder communication

**Structure:**
- Executive Summary (threat level, key finding, business impact)
- Threat Landscape Overview (active campaigns, attribution, targeting)
- Strategic Recommendations (short/medium/long-term actions)
- Technical Appendix (IOC summary, data sources)

**Output example:**
```
EXECUTIVE SUMMARY
Threat Level: HIGH
Key Finding: APT28 actively targeting defense contractors with spearphishing campaigns
Business Impact: Risk to CUI data, potential CMMC compliance violation
Immediate Actions Required:
  1. Enhanced email filtering for Russian infrastructure
  2. User awareness training on spearphishing
  3. Review access controls for CUI systems
```

#### Technical Analysis (`technical_analysis.md`)
**Use case:** SOC analysts, detection engineers, threat researchers

**Structure:**
- Threat Actor Analysis (attribution, TTPs, historical activity)
- Indicator Analysis (IOC breakdown, patterns, infrastructure)
- Campaign Assessment (scope, victimology, success indicators)
- Detection and Response (opportunities, hunting queries, mitigations)

**Output example:**
```
THREAT ACTOR ANALYSIS
Primary Attribution: APT28 (Fancy Bear, Sofacy, G0007)
Confidence: HIGH (TTPs match known campaigns, infrastructure patterns consistent)

Known TTPs (MITRE ATT&CK):
- T1566.001: Spearphishing Attachment (primary initial access)
- T1053.005: Scheduled Task/Job (persistence)
- T1003.001: LSASS Memory (credential access)

Detection Opportunities:
[Splunk Query] index=windows EventCode=4698 | search Task_Name="*Update*"
[CrowdStrike] ProcessRollup2 event with ImageFileName=*schtasks.exe AND CommandLine=*create*
```

#### Incident Response Playbook (`incident_response.md`)
**Use case:** Active incident response, tabletop exercises

**Structure:**
- Immediate Response Actions (containment, evidence preservation)
- Investigation Priorities (critical IOCs, systems at risk)
- Response Procedures (isolation, forensics, communications)
- Lessons Learned (detection gaps, improvements needed)

**Output example:**
```
IMMEDIATE RESPONSE ACTIONS (First 30 Minutes)

Containment:
✓ Isolate affected systems from network (DO NOT power off - preserves memory)
✓ Block known APT28 C2 IPs at perimeter firewall
✓ Revoke compromised credentials in Active Directory

Evidence Preservation:
✓ Capture memory dump from affected endpoints (priority: domain controllers)
✓ Preserve email headers and attachments from spearphishing attempts
✓ Export relevant logs (last 90 days): authentication, process execution, network
```

#### Strategic Assessment (`strategic_assessment.md`)
**Use case:** Quarterly reviews, strategic planning, risk assessments

**Structure:**
- Threat Landscape Trends (emerging patterns, actor evolution)
- Strategic Implications (industry impact, geographic shifts)
- Predictive Insights (future threat vectors, preparation strategies)
- Strategic Recommendations (policy updates, architecture changes)

---

### How Templates Work Together

**Query:** "Analyze APT28 and provide recommendations"

**Without customization (generic):**
```
APT28 is a Russian threat actor that uses spearphishing and credential theft.
Recommendations: Implement MFA, train users, monitor for suspicious activity.
```

**With PIRs + Security Stack + Templates:**
```
[Executive Briefing Template Applied]

EXECUTIVE SUMMARY
Threat Level: HIGH for defense contractors in Southeast US
Key Finding: APT28 actively targeting your sector (aerospace/defense) with 
spearphishing campaigns against CMMC-covered CUI systems

Business Impact: 
- CMMC compliance violation risk (AC.L2-3.1.13 threat-informed defense)
- Potential loss of defense contracts
- CUI exfiltration could compromise proprietary research

IMMEDIATE ACTIONS (Next 24-48 Hours):
1. Enhanced Proofpoint TAP rules for Russian infrastructure (config provided below)
2. CrowdStrike Falcon hunt for LSASS access (query provided)
3. Emergency user awareness: Spearphishing from .ru domains targeting proposals

[Technical Analysis Template Applied]

DETECTION OPPORTUNITIES - YOUR ENVIRONMENT
Splunk Search (for your v9.x deployment):
index=windows sourcetype=WinEventLog:Security EventCode=4688 
| search (CommandLine="*lsass*" OR CommandLine="*mimikatz*")
| stats count by Computer, User, CommandLine

CrowdStrike Falcon Hunt (tested on your deployment):
event_simpleName=ProcessRollup2* ImageFileName IN ("*procdump*","*mimikatz*")
| table ComputerName, UserName, CommandLine, ImageFileName

COMPENSATING CONTROLS FOR YOUR GAPS:
You have no DLP deployed. For CUI protection:
- Enable Windows Defender Application Guard on CUI workstations
- Implement PowerShell Constrained Language Mode
- Deploy CrowdStrike USB device control module

[Incident Response Template Applied]

RESPONSE PROCEDURES - YOUR 2-PERSON SOC TEAM:
Given your 8am-6pm coverage:
1. Set CrowdStrike Falcon detections to "Block" (not just Alert) for high-confidence IOCs
2. Configure Splunk alerts to page on-call person for LSASS access events
3. Pre-stage EDR memory capture commands for after-hours automated response
```

**See the difference?** Same threat actor, but analysis is:
- Contextualized to your industry and geography
- References your specific tools (Splunk, CrowdStrike, Proofpoint)
- Provides ready-to-execute queries for YOUR platforms
- Accounts for your gaps (no DLP) with realistic alternatives
- Scaled to your team size (2 analysts, not 24/7 SOC)
- Connected to your compliance requirements (CMMC)

---

### Customization Guide

**Step 1: Define Your PIRs**

Edit `config/pirs.md`:
1. Start with your industry and critical assets
2. List 3-5 priority threat questions
3. Connect each to business decisions
4. Review quarterly and update

**Step 2: Document Your Security Stack**

Edit `config/security_stack.md`:
1. List all security tools (with versions)
2. Document team size and coverage
3. Note known gaps honestly
4. Update when tools change

**Step 3: Choose Analysis Templates**

Templates are automatically available. Claude will:
- Default to Executive Briefing (general queries)
- Use Technical Analysis (when you ask for "technical details" or "TTPs")
- Apply Incident Response (when you mention "incident" or "compromise")
- Use Strategic Assessment (when you ask for "trends" or "landscape")

You can also request specific templates:
```
"Analyze APT28 using the incident response template"
"Give me an executive briefing on ransomware threats"
"Provide technical analysis of Emotet's TTPs"
```

**Step 4: Test and Refine**

1. Run test queries: "Analyze APT28"
2. Review if output matches your needs
3. Refine PIRs if priorities aren't reflected
4. Update security_stack.md if recommendations don't fit your tools
5. Iterate until outputs feel tailored to your organization

---

### Example: Before and After Customization

**Scenario:** Small regional hospital asking about ransomware threats

#### Before Customization (Generic AI Response)

**Query:** "What ransomware threats should we worry about?"

**Response:**
```
Ransomware is a significant threat to all organizations. Common groups include:
- LockBit
- ALPHV/BlackCat  
- Royal

Recommendations:
- Implement backups
- Train users
- Keep systems patched
- Deploy EDR
```

**Problem:** Generic, not actionable, doesn't consider hospital context

---

#### After Customization (With PIRs + Security Stack)

**PIRs defined:**
- Healthcare sector
- Regional hospital ($500M revenue)
- Critical: EHR system, medical devices
- HIPAA compliance required
- Small IT team (5 people)

**Security Stack documented:**
- SIEM: Splunk
- EDR: CrowdStrike on servers only (not medical devices)
- Backups: Veeam (tested quarterly)
- No dedicated security team

**Query:** "What ransomware threats should we worry about?"

**Response:**
```
[Executive Briefing - Healthcare Context]

THREAT LEVEL: CRITICAL

KEY FINDING: Three ransomware groups actively targeting regional hospitals 
in your revenue bracket ($500M):

1. LockBit 3.0 - 12 confirmed healthcare attacks (last 90 days)
   Risk: Known to target Veeam backups (you use Veeam)
   
2. Royal Ransomware - Targeting Epic EHR systems specifically
   Risk: Your EHR vendor is Epic (per security_stack.md)
   
3. Hive - Focuses on medical device networks
   Risk: Your medical devices lack EDR coverage

BUSINESS IMPACT - HIPAA PERSPECTIVE:
- OCR breach notification required within 60 days
- Average hospital downtime: 2-3 weeks (EHR offline)
- Average ransomware payment demand for your size: $2-5M
- Regulatory fines: $100-250K+ for inadequate safeguards

IMMEDIATE ACTIONS (Next 7 Days):

1. VEEAM BACKUP PROTECTION (Addresses LockBit risk):
   - Enable immutable backups in Veeam
   - Store recovery key offline (not on domain)
   - Test bare metal restore of EHR server THIS WEEK

2. EPIC EHR HARDENING (Addresses Royal risk):
   Your Splunk Search (Ready to Deploy):

   index=epic_logs (EventCode=4624 OR EventCode=4625) 
   | stats count by Account_Name, Workstation_Name
   | where count > 100
   
   Alert on abnormal Epic authentication patterns

3. MEDICAL DEVICE NETWORK SEGMENTATION (Addresses Hive risk):
   Since you can't deploy EDR on medical devices:
   - Isolate medical device VLAN from corporate network
   - Deploy Palo Alto firewall rules blocking device-to-internet
   - Monitor device VLAN for anomalies in Splunk

RESOURCE CONSTRAINTS ACKNOWLEDGED:
Your 5-person IT team can't do everything. Priority order:
1. Veeam immutability (2 hours, maximum ROI)
2. Medical device segmentation (1 day, prevents lateral movement)
3. Epic monitoring (4 hours, early warning system)

COMPLIANCE NOTE:
These actions satisfy HIPAA Security Rule 164.312(a)(1) - Access Controls
and 164.308(a)(7) - Contingency Planning
```

**See the transformation?**
- Healthcare-specific threats (not generic ransomware)
- Your tools referenced (Veeam, Splunk, Epic, Palo Alto)
- Your constraints acknowledged (5-person team, no device EDR)
- Your compliance needs addressed (HIPAA)
- Ready-to-execute actions (Splunk query, firewall rules)
- Prioritized by effort and ROI

---

### Configuration Best Practices

**1. Start Simple**
- Don't try to document everything at once
- Start with basic PIRs (3-5 questions)
- Add security stack details as you go
- Templates work out of the box

**2. Keep PIRs Current**
- Review quarterly
- Update after major incidents
- Adjust when business priorities change
- Archive outdated PIRs (don't delete - historical context)

**3. Be Honest in Security Stack**
- Document gaps and limitations
- Include tool versions (matters for queries)
- Note budget constraints
- Update when tools change

**4. Template Selection**
- Let Claude choose (usually right)
- Request specific template if needed
- Mix templates for complex analysis
- Create custom templates for special use cases

**5. Iterate Based on Feedback**
- Share outputs with stakeholders
- Ask "Was this useful? What's missing?"
- Refine PIRs based on what questions actually get asked
- Update security stack when recommendations don't fit

---

### Advanced: Custom Templates

**Want to create organization-specific templates?**

1. Copy existing template as starting point
2. Add your organization's sections
3. Include specific compliance requirements
4. Reference your terminology and processes

**Example: Defense Contractor Template**

```markdown
# Defense Contractor Incident Response Template

## CMMC Compliance Actions
- AC.L2-3.1.13: Document threat-informed defense measures taken
- IR.L2-3.6.1: Report to DoD within 72 hours if CUI affected
- AU.L2-3.3.1: Preserve audit logs for incident investigation

## DFARS 252.204-7012 Reporting
If CUI potentially affected:
- [ ] Notify DoD CIO at: https://dibnet.dod.mil within 72 hours
- [ ] Provide information required by DFARS clause
- [ ] Preserve evidence per DoD guidance

## Stakeholder Notifications
- Program Security Officer (PSO): [name]
- Government Contracting Officer: [name]
- DCSA Field Office: [contact]
- Legal: [firm name]

[Continue with standard incident response sections...]
```

Save as `config/templates/defense_contractor_ir.md` and request:
```
"Analyze this incident using the defense contractor IR template"
```

## Audit Logging

All MCP tool calls are logged to `logs/opencti_mcp_audit.log` for compliance requirements.

**Compliance Standards Supported:**
- **CMMC Level 2** (AC.L2-3.1.13: Threat-informed defense)
- **NIST 800-171** (3.1.15: Privileged user monitoring)
- **SOC 2 Type II** (Monitoring and logging requirements)

**Log Format:**
```json
{
  "timestamp": "2025-11-19T02:00:01.646Z",
  "event_type": "mcp_tool_call",
  "user": "analyst@company.com",
  "tool_name": "get_threat_actor_ttps",
  "parameters": {"actor": "APT28"},
  "data_classification": "TLP:CLEAR",
  "results_count": 91,
  "execution_time_ms": 342,
  "session_id": "abc123-uuid",
  "success": true
}
```

**SIEM Integration:**
Parse JSON logs and ingest into Splunk, Sentinel, or Elastic for centralized monitoring.

**What's Logged:**
- Tool calls with parameters
- Execution time and performance metrics
- Success/failure status
- Error details when applicable
- Unique session IDs for correlation

---

## Security

**Security features include:**
- 🔒 **TLP filtering** - CISA-compliant Traffic Light Protocol prevents unauthorized disclosure
- 🛡️ **Input validation** - All inputs sanitized (SQL, XSS, template injection prevention)
- 📋 **Audit logging** - ISO 8601 timestamps, SIEM-compatible JSON format
- 🔍 **Dependency management** - Pinned versions, regular updates
- 🏢 **Air-gap support** - Works with local LLMs for classified environments
- ⚙️ **Secure configuration** - YAML safe loading, path validation, permission checks
- 🔐 **Localhost binding** - Secure by default (v0.4.2+), network access requires explicit opt-in

### Network Binding Security (v0.4.2)

**Status:** ✅ **RESOLVED** - Default changed to localhost binding

**Previous behavior (v0.4.1 and earlier):**
- Server bound to `0.0.0.0` (all network interfaces) by default
- Bandit flagged as MEDIUM severity security issue

**Current behavior (v0.4.2+):**
- Server now binds to `127.0.0.1` (localhost only) by default
- Secure by default, users must explicitly opt-in to network exposure

**For network access (advanced use case):**
```bash
export MCP_SERVER_HOST=0.0.0.0  # ⚠️ Exposes server to network
```

**Security considerations:**
- **Localhost binding (127.0.0.1)**: Secure by default, only accessible from local machine
- **All interfaces (0.0.0.0)**: Exposes server to network, requires firewall rules and access controls
- **Best practice**: Use SSH tunneling or VPN for remote OpenCTI access instead of binding to 0.0.0.0

**Configuration:**
Set `MCP_SERVER_HOST` in your `.env` file or environment variables to customize binding address.

### Dependency Security (v0.4.2)

**Cryptography CVE Fixes:**
- Updated `cryptography` dependency to 43.0.1+ to fix 4 CVEs
- PYSEC-2024-225 (HIGH): NULL pointer crash in PKCS12
- GHSA-3ww4-gg4f-jr7f (HIGH): RSA key exchange vulnerability (TLS decrypt)
- GHSA-9v9h-cgj8-h64p (MEDIUM): PKCS12 parsing DoS
- GHSA-h4gh-qq45-vh27 (HIGH): OpenSSL vulnerability

**Impact:** pycti uses TLS for OpenCTI connections - these CVEs posed MITM/DoS risk

**Action required:** Run `pip install -r requirements.txt --upgrade` after pulling v0.4.2

### Security Review

**Version 0.3.0+ Security Review:**
- ✅ Dependency CVE scan completed
- ✅ Static analysis (Bandit) passed
- ✅ Manual code review completed
- ✅ Input validation tested
- ✅ Audit log security verified

**Full audit report:** [SECURITY_AUDIT.md](SECURITY_AUDIT.md)

### Project Status

**Version:** 0.4.2 (Active Development)
**Stability:** Beta - suitable for production use with appropriate risk assessment
**What's tested:** Security features, TLP filtering, core functionality
**What's not:** Long-term stability, edge cases, all OpenCTI 6.x variations

**Recommendation:** Test thoroughly in your environment before production deployment

### Limitations

- Self-audited (not third-party security assessment)
- Beta software (test before production)
- Local LLM required for classified/CUI data
- Claude Pro default sends data to Anthropic cloud

### Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

Email: matt@coopercybercoffee.com

**Response timeline:**
- Initial response: 48 hours
- Status update: 7 days
- Fix depends on severity (24 hours for critical, 7 days for high)

**Full security policy:** [SECURITY.md](SECURITY.md)

### Compliance Standards

This project supports technical requirements for:
- **CMMC Level 2** - When deployed with local LLM
- **NIST 800-171** - With appropriate configuration
- **SOC 2 Type II** - Audit logging and access controls
- **HIPAA** - When using local LLM (no BAA with cloud services)

See [SECURITY.md](SECURITY.md) for detailed compliance information.

---

## ⚠️ Data Governance & Security Considerations

### CRITICAL: Understand What You're Sending to Claude

**This MCP server sends threat intelligence queries to Anthropic's cloud infrastructure by default.**

**What gets sent to Claude:**
- Tool calls and parameters (e.g., "get threat actor APT28")
- Query results from OpenCTI (indicators, threat actor profiles, TTPs, reports, etc.)
- Relationship data between entities
- All text content returned by OpenCTI queries

**What stays local:**
- Your OpenCTI database contents (only queried data is sent)
- Your authentication tokens
- Cached query results
- Audit logs

**Data flow:**
1. You type a question in Claude Desktop
2. Claude's API (Anthropic cloud) decides which MCP tools to call
3. MCP server queries your local/cloud OpenCTI instance
4. Query results sent back to Claude's API for analysis
5. Claude generates response using the threat intelligence data

**Anthropic's data handling:**
- Review Anthropic's privacy policy: https://www.anthropic.com/legal/privacy
- Anthropic may use conversations to improve models (opt-out available)
- Data transmitted over TLS/HTTPS
- No control over data retention once sent to Anthropic

**⚠️ IMPORTANT:** You are sending threat intelligence data to a third-party cloud service. This may violate your organization's data handling policies, NDAs, or compliance requirements.

---

### Traffic Light Protocol (TLP) Filtering

**This server implements TLP filtering to prevent sensitive data from being sent to Claude.**

**CISA TLP Levels** (from most to least restrictive):

| TLP Level | Definition | Allowed by Default? |
|-----------|------------|---------------------|
| **TLP:RED** | For eyes and ears of individual recipients only, no further disclosure | ❌ Blocked |
| **TLP:AMBER+STRICT** | Limited disclosure, restricted to organization and its clients | ❌ Blocked |
| **TLP:AMBER** | Limited disclosure, restricted to participants' organizations | ❌ Blocked |
| **TLP:GREEN** | Limited disclosure, community wide | ❌ Blocked |
| **TLP:CLEAR** (formerly TLP:WHITE) | May be distributed without restriction | ✅ Allowed |

**Default Policy:** Only **TLP:CLEAR** objects are sent to Claude. All other TLP levels and unmarked objects are **filtered out**.

**How filtering works:**
1. MCP server queries OpenCTI
2. Results are filtered based on `config/tlp_policy.yaml`
3. Only compliant objects sent to Claude
4. Filtered objects logged to audit log
5. Clear error message if query returns no compliant data

**Verify what's being filtered:**
```bash
# Check audit logs for filtered objects
tail -f logs/opencti_mcp_audit.log | grep "filtered"
```

**CISA TLP Guidance:** https://www.cisa.gov/news-events/news/traffic-light-protocol-tlp-definitions-and-usage

---

### Compliance Considerations

**Before deploying this tool in a production environment, consider:**

#### CMMC Level 2 (Defense Contractors)
- **Issue:** Sending CUI to unauthorized cloud services violates CMMC requirements
- **Assessment:** If your OpenCTI contains CUI (Controlled Unclassified Information), do NOT use this tool with cloud-based Claude
- **Alternative:** Use Claude Desktop in air-gapped mode or local LLM deployment
- **Reference:** NIST 800-171 3.13.11 (Cryptographic mechanisms to protect CUI)

#### NIST 800-171 (Federal Contractors)
- **Issue:** CUI must be protected with cryptographic mechanisms
- **Assessment:** Sending CUI to Anthropic's cloud violates 3.13.11
- **Mitigation:** Only use with TLP:CLEAR/public data, or deploy in isolated environment

#### SOC 2 Type II / ISO 27001 (Data Governance)
- **Issue:** Data residency and third-party data sharing controls
- **Assessment:** Review your data classification policy and third-party risk assessment
- **Requirements:** Document data flows, get approval from security/compliance team
- **Audit trail:** This server logs all queries (see Audit Logging section)

#### HIPAA (Healthcare)
- **Issue:** PHI (Protected Health Information) must not be sent to unauthorized services
- **Assessment:** Do NOT use this tool if your threat intelligence contains PHI
- **Example:** Patient names in incident reports, health data in breach notifications

#### Financial Services (PCI-DSS, GLBA)
- **Issue:** Cardholder data and customer financial information restrictions
- **Assessment:** Ensure incident reports don't contain PCI data or customer PII
- **Requirement:** Data flow documentation, third-party vendor assessment

#### GDPR / Privacy Laws
- **Issue:** Personal data of EU residents sent to US-based cloud service
- **Assessment:** Check if your threat intelligence contains PII
- **Mitigation:** Anonymize/redact PII before ingestion to OpenCTI

**⚠️ Recommendation:** Consult your organization's security, compliance, and legal teams before deploying in production.

---

### Recommended Use Cases (Safe)

**These use cases are generally safe for TLP:CLEAR data:**

✅ **Public OSINT (Open Source Intelligence)**
- MISP feeds (with TLP:CLEAR/WHITE marking)
- AlienVault OTX public pulses
- abuse.ch malware databases (URLhaus, MalwareBazaar)
- VirusTotal public reports
- Public security vendor blogs and reports

✅ **MITRE ATT&CK Framework**
- Techniques, tactics, and procedures
- Software and malware descriptions
- Threat groups and campaigns
- Publicly documented TTPs

✅ **Public CVEs (Vulnerabilities)**
- NVD (National Vulnerability Database)
- CISA KEV (Known Exploited Vulnerabilities)
- Public security advisories
- Vendor patch notifications

✅ **Non-Attributed Research**
- Generic malware family analysis
- Technique research and hunting
- Educational threat analysis
- Security training scenarios

✅ **Training and Education**
- Tabletop exercises
- Purple team training
- Threat hunting practice
- Analyst skill development

**Best practice:** Mark all public data as **TLP:CLEAR** in OpenCTI to enable safe AI-assisted analysis.

---

### NOT Recommended (Unsafe Use Cases)

**Do NOT use this tool for:**

❌ **TLP:AMBER or TLP:RED Intelligence**
- Threat intelligence from commercial vendors (often TLP:AMBER)
- ISAC/ISAO member-only feeds
- Government-source intelligence
- Private threat intelligence sharing groups
- Attribution intelligence with sensitive sources

❌ **Classified Information**
- Any data classified under Executive Order 13526
- Sensitive But Unclassified (SBU)
- For Official Use Only (FOUO)
- Law Enforcement Sensitive (LES)

❌ **Proprietary Threat Intelligence**
- Paid threat intelligence feeds
- Commercial TIP vendor data
- Threat intel from security vendors (often TLP:AMBER)
- Industry-specific intelligence sharing

❌ **Company-Specific Incidents**
- Internal breach investigations
- Security incidents with attribution
- Network architecture details
- Asset inventory and criticality
- Vulnerability scan results

❌ **Active Investigations**
- Ongoing incident response
- Law enforcement coordination
- Legal hold data
- Attorney-client privileged information

❌ **CUI (Controlled Unclassified Information)**
- Defense contractor threat intelligence
- CMMC/NIST 800-171 covered data
- Export controlled information (ITAR, EAR)

**⚠️ If in doubt, DON'T send it.** Err on the side of caution.

---

### Configuring TLP Policy

**TLP policy is controlled by `config/tlp_policy.yaml`**

**Default configuration (safest):**
```yaml
# Only allow TLP:CLEAR and legacy TLP:WHITE
allowed_markings:
  - "TLP:CLEAR"
  - "TLP:WHITE"

# Block objects with no TLP marking (potentially sensitive)
allow_unmarked: false

# Reject queries if ANY object violates policy
strict_mode: true
```

**Example: Allow TLP:GREEN for community sharing**
```yaml
allowed_markings:
  - "TLP:CLEAR"
  - "TLP:WHITE"
  - "TLP:GREEN"  # Community-wide sharing acceptable

allow_unmarked: false
strict_mode: true
```

**Example: Allow unmarked objects (RISKY)**
```yaml
allowed_markings:
  - "TLP:CLEAR"
  - "TLP:WHITE"

# WARNING: This allows objects with NO TLP marking to be sent to Claude
# Only use this if you trust ALL data in your OpenCTI instance
allow_unmarked: true

strict_mode: true
```

**Example: Custom organizational markings**
```yaml
allowed_markings:
  - "TLP:CLEAR"
  - "TLP:WHITE"

# Your organization's custom markings
custom_allowed_markings:
  - "INTERNAL:PUBLIC"
  - "UNCLASSIFIED"
  - "OPEN SOURCE"

allow_unmarked: false
strict_mode: true
```

**Configuration parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `allowed_markings` | `["TLP:CLEAR", "TLP:WHITE"]` | List of TLP markings allowed to be sent to Claude |
| `allow_unmarked` | `false` | Allow objects with NO TLP marking? (dangerous) |
| `strict_mode` | `true` | Reject query if ANY object violates policy? |
| `custom_allowed_markings` | `[]` | Additional organization-specific markings |
| `log_filtered_objects` | `true` | Log filtered objects to audit log? |

**After changing policy:**
```bash
# Restart MCP server to reload configuration
# (Close and reopen Claude Desktop)
```

---

### Best Practices for Production Deployment

**Before deploying this tool:**

1. **Review your data classification policy**
   - Identify what data is safe to send to cloud LLMs
   - Document approved use cases
   - Define prohibited scenarios

2. **Assess your OpenCTI data**
   - Audit TLP markings on all objects
   - Ensure TLP:CLEAR is only on truly public data
   - Mark everything else appropriately (AMBER, RED, etc.)
   - Consider creating separate OpenCTI instance for public data only

3. **Get organizational approval**
   - Security team review
   - Compliance/legal team review
   - Data protection officer (if applicable)
   - Risk acceptance from management

4. **Configure TLP policy appropriately**
   - Start with most restrictive (TLP:CLEAR only)
   - Document any policy changes
   - Review policy quarterly
   - Keep `allow_unmarked: false` (safest)

5. **Configure monitoring**
   - Ingest audit logs into SIEM
   - Alert on filtered objects (potential policy violations)
   - Monitor for high-volume queries
   - Review logs regularly

6. **Train users**
   - Explain what data can/cannot be queried
   - Show how to check TLP markings
   - Demonstrate audit log review
   - Establish escalation procedures

7. **Document everything**
   - Data flow diagrams
   - Risk assessment
   - Approval documentation
   - Policy configuration rationale
   - Incident response procedures

---

### Technical Controls

**Additional security measures to consider:**

**Network Segmentation:**
```bash
# Run MCP server on isolated network segment
# Restrict access to OpenCTI instance
# Monitor network traffic to Anthropic endpoints
```

**Access Controls:**
```bash
# Limit who can run MCP server
# Separate Claude Desktop accounts for different roles
# Use principle of least privilege
```

**Data Sanitization:**
```bash
# Pre-process OpenCTI data to remove sensitive fields
# Redact PII from incident descriptions
# Strip internal asset names from reports
```

**Monitoring and Alerting:**
```bash
# Alert on TLP policy violations
# Monitor for unusual query patterns
# Track data exfiltration volumes
# Log all Claude Desktop sessions
```

**Alternative Architectures:**
```
Option 1: Public OSINT Only
- Deploy separate OpenCTI instance
- Only ingest TLP:CLEAR feeds
- No risk of sensitive data leakage

Option 2: Air-Gapped Deployment
- Use local LLM instead of Claude API
- Deploy entirely on-premises
- No data leaves your network

Option 3: Data Sanitization Layer
- Proxy/filter all OpenCTI responses
- Strip sensitive fields automatically
- Anonymize entity names
- Redact internal references
```

---

### Questions About Data Governance?

**This is a complex security decision. When in doubt:**

1. **Consult your security team** - They understand your organization's risk tolerance
2. **Review your data classification policy** - What's approved for cloud services?
3. **Start restrictive, expand carefully** - Begin with TLP:CLEAR only
4. **Document everything** - Maintain audit trail of decisions
5. **Monitor continuously** - Watch for policy violations

**Contact for project questions:**
- Email: matt@coopercybercoffee.com
- Note: Cannot provide organization-specific compliance advice

**Compliance resources:**
- CISA TLP Guidance: https://www.cisa.gov/tlp
- NIST 800-171: https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final
- CMMC: https://www.acq.osd.mil/cmmc/
- Anthropic Privacy: https://www.anthropic.com/legal/privacy

---

## 🔒 Air-Gapped Deployment & Local LLM Support

### The Architecture Discovery

**Key Insight:** This MCP server is **LLM-agnostic** by design - it works with ANY MCP-compatible client and model, not just Claude and Anthropic.

**What this means:**
- ✅ Use with cloud LLMs (Claude Pro, Claude Enterprise) for public threat intelligence
- ✅ Use with local models (Llama, Mistral, etc.) for sensitive/classified data
- ✅ Deploy in air-gapped environments without internet access
- ✅ Process CUI, TLP:RED, and classified intelligence safely
- ✅ No code changes needed - same MCP server works for all deployment types

**This makes it suitable for:**
- Defense contractors (CMMC compliance)
- Classified government environments
- Financial services (customer data protection)
- Healthcare (HIPAA compliance)
- Organizations with data sovereignty requirements

---

### Architecture Options

#### Option 1: Cloud LLM - Claude Pro (Default)

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   OpenCTI   │───▶│ MCP Server  │───▶│   Claude    │───▶│  Anthropic  │
│             │    │   (local)   │    │  Desktop    │    │    API      │
│   (local)   │    │             │    │  (local)    │    │   (cloud)   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

**Pros:**
- Best model quality (Claude Sonnet 4.5)
- Always up-to-date with latest AI improvements
- No local GPU or high-end hardware needed
- Simple setup (this README's default instructions)
- $20/month Claude Pro subscription

**Cons:**
- Data sent to Anthropic's cloud infrastructure
- Requires internet connectivity
- Subject to Anthropic's data retention policies
- Not suitable for classified/sensitive data

**Use for:**
- TLP:CLEAR public threat intelligence
- MITRE ATT&CK framework data
- Public CVEs and vulnerability research
- Open-source intelligence (OSINT)
- Training and education

---

#### Option 1.5: Cloud LLM - Claude Enterprise (Middle Ground)

**For organizations with enhanced security requirements:**

```
┌─────────────┐    ┌─────────────┐    ┌────────────────┐    ┌─────────────┐
│   OpenCTI   │───▶│ MCP Server  │───▶│     Claude     │───▶│  Anthropic  │
│             │    │   (local)   │    │   Enterprise   │    │ Enterprise  │
│   (local)   │    │             │    │    (local)     │    │    (cloud)  │
└─────────────┘    └─────────────┘    └────────────────┘    └─────────────┘
```

**Advantages over Claude Pro:**
- ✅ Enhanced data controls and retention policies
- ✅ SSO/SAML integration
- ✅ Centralized administration
- ✅ Priority support and SLAs
- ✅ Potentially: Business Associate Agreement (HIPAA - verify with Anthropic)
- ✅ Higher usage limits

**Still NOT suitable for:**
- ❌ **CUI (Defense contractors)** - Not FedRAMP authorized, violates CMMC
- ❌ **Classified information** - Any level (SECRET, TOP SECRET)
- ❌ **ITAR-controlled data** - Export control restrictions
- ❌ **Data sovereignty** - Some countries prohibit foreign processing
- ❌ **Highly regulated data** - Without explicit organizational approval

**Requires organizational approval for:**
- ⚠️ **TLP:AMBER intelligence** - Check your data handling policy
- ⚠️ **Proprietary research** - Need legal review and contracts
- ⚠️ **Financial services data** - Compliance team sign-off required
- ⚠️ **Corporate confidential** - Risk assessment needed

**The conservative recommendation:**
If you're asking "Can I use Claude Enterprise for this data?" - the answer is probably **use local LLM instead**. It's not worth the compliance risk.

**Cost:** Typically $30+/user/month (contact Anthropic for pricing)

---

#### Option 2: Local LLM (Air-Gapped)

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   OpenCTI   │───▶│ MCP Server  │───▶│ MCP Client  │───▶│  Local LLM  │
│             │    │   (local)   │    │             │    │   (Llama,   │
│   (local)   │    │             │    │  (local)    │    │  Mistral)   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                                                               (local GPU/CPU)
```

**Pros:**
- ✅ Fully air-gapped deployment (no internet required)
- ✅ Complete data control (nothing leaves your infrastructure)
- ✅ Suitable for classified/sensitive intelligence
- ✅ No cloud API costs (hardware investment only)
- ✅ Works offline indefinitely
- ✅ Supports CMMC technical requirements
- ✅ Full data sovereignty

**Cons:**
- Requires local compute resources (GPU recommended)
- Model quality varies (70B models competitive, smaller less so)
- Initial setup more complex
- You manage model updates and security
- Hardware costs ($2k-$15k depending on requirements)

**Use for:**
- TLP:AMBER and TLP:RED intelligence
- Classified threat intelligence (SECRET, TOP SECRET)
- CUI for defense contractors
- Proprietary threat intelligence
- Active investigations and incident response
- Customer/client threat data (HIPAA, GLBA)
- ITAR-controlled information
- Data with sovereignty requirements

---

#### Option 3: Hybrid Deployment

**Deploy separate instances by classification level:**

```
Public OpenCTI ───▶ MCP Server ───▶ Claude Pro ───▶ Anthropic (TLP:CLEAR)

Sensitive OpenCTI ───▶ MCP Server ───▶ MCP Client ───▶ Local LLM (TLP:AMBER+)
```

**Pros:**
- Best of both worlds (quality + security)
- Right tool for right data
- Cost-effective (cloud for bulk, local for sensitive)

**Cons:**
- Operational complexity (two deployments)
- User training (which system for what data)
- Potential for mistakes (query wrong system)

---

### Cloud Options Compared

| Solution | Data Location | Suitable For | NOT Suitable For | Cost |
|----------|--------------|--------------|------------------|------|
| **Claude Pro** | Anthropic cloud | TLP:CLEAR public intel | Everything else | $20/mo |
| **Claude Enterprise** | Anthropic cloud | TLP:AMBER (with approval) | CUI, Classified, HIPAA (unless BAA verified) | $30+/user/mo |
| **Local LLM** | Your infrastructure | Everything including classified | - | Hardware cost |

**Key Decision Point:** If your data requires a risk assessment before using cloud AI, use local LLM. Claude Enterprise reduces some risks but doesn't eliminate third-party processing.

---

### Setting Up Local LLM Deployment

#### Hardware Requirements

**Minimum (13B models):**
- GPU: NVIDIA with 16GB VRAM (RTX 4080, A4000, etc.)
- RAM: 32GB system RAM
- Storage: 50GB for model files

**Recommended (70B models):**
- GPU: NVIDIA with 40GB+ VRAM (A100, H100, RTX 6000)
- RAM: 64GB system RAM
- Storage: 100GB for model files

**Budget Option (7B models):**
- GPU: NVIDIA with 8GB VRAM (RTX 3060, T4)
- OR CPU: 64GB RAM (slower but works)
- Storage: 20GB for model files

---

#### Installation Steps

**1. Install Local LLM Server**

**Option A: Ollama (Easiest)**
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model (choose based on your hardware)
ollama pull llama3:70b    # Best quality (requires 40GB+ VRAM)
ollama pull llama3:13b    # Balanced (16GB VRAM)
ollama pull llama3:7b     # Fastest (8GB VRAM or CPU)

# Start Ollama server
ollama serve
```

**Option B: LM Studio (GUI)**
- Download: https://lmstudio.ai/
- Install and launch
- Download model from built-in browser
- Start local server

**Option C: vLLM (Production)**
```bash
# For production deployments requiring high throughput
pip install vllm

# Start vLLM server
python -m vllm.entrypoints.openai.api_server \
    --model meta-llama/Llama-3-70b-chat-hf \
    --host 0.0.0.0 \
    --port 8000
```

---

**2. Install OpenCTI MCP Server**

```bash
# Same as cloud setup - no changes needed
git clone https://github.com/CooperCyberCoffee/opencti_mcp_server.git
cd opencti_mcp_server
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

**3. Configure Claude Desktop for Local Model**

**Edit `claude_desktop_config.json`:**

```json
{
  "mcpServers": {
    "opencti": {
      "command": "/full/path/to/venv/bin/python",
      "args": ["-m", "opencti_mcp"],
      "env": {
        "OPENCTI_URL": "http://localhost:8080",
        "OPENCTI_TOKEN": "your-api-token-here",
        "OPENCTI_SSL_VERIFY": "false"
      }
    }
  },
  "llm": {
    "provider": "ollama",
    "model": "llama3:70b",
    "endpoint": "http://localhost:11434"
  }
}
```

**Note:** Claude Desktop configuration for local models varies. Check Anthropic's documentation for latest guidance, or use alternative MCP clients that support local models.

---

**4. Configure TLP Policy for Classified Data**

**Edit `config/tlp_policy.yaml`:**

```yaml
# For classified/CUI environments
allowed_markings:
  - "TLP:RED"
  - "TLP:AMBER+STRICT"
  - "TLP:AMBER"
  - "TLP:GREEN"
  - "TLP:CLEAR"
  - "SECRET"              # Add your classifications
  - "TOP SECRET"
  - "CONFIDENTIAL"
  - "UNCLASSIFIED"
  - "CUI"

allow_unmarked: false     # Still filter unmarked data
strict_mode: true

# Document your policy
policy_version: "1.0"
last_reviewed: "2025-01-19"
reviewed_by: "security_team@yourorg.gov"
```

---

**5. Test the Deployment**

```bash
# Start Ollama (if not already running)
ollama serve

# In another terminal, test MCP server
cd opencti_mcp_server
source venv/bin/activate
python main.py

# Should see: "Connected to OpenCTI" and "TLP filtering enabled"
# Press Ctrl+C when verified
```

**In Claude Desktop:**
```
You: "Check my OpenCTI connection"

Claude: ✅ Connected to OpenCTI
        Version: 6.x.x
        TLP Policy: Active (7 markings allowed)
        Model: llama3:70b (local)
```

---

### Recommended Models for CTI Analysis

| Model | Size | Hardware | Quality | Speed | Use Case |
|-------|------|----------|---------|-------|----------|
| **Llama 3 70B** | 70B | GPU 40GB+ | ⭐⭐⭐⭐⭐ Excellent | Moderate | Best for complex analysis, attribution |
| **Mistral Large** | 123B | GPU 80GB+ | ⭐⭐⭐⭐⭐ Excellent | Slow | Technical deep dives, malware analysis |
| **Codestral** | 22B | GPU 24GB | ⭐⭐⭐⭐ Very Good | Fast | Code analysis, malware TTPs |
| **Llama 3 13B** | 13B | GPU 16GB | ⭐⭐⭐⭐ Very Good | Fast | Balanced performance |
| **Mistral 7B** | 7B | GPU 8GB | ⭐⭐⭐ Good | Very Fast | Resource-constrained |
| **Llama 3 7B** | 7B | CPU/8GB GPU | ⭐⭐⭐ Good | Very Fast | Budget deployments |
| **Phi-3** | 3.8B | CPU | ⭐⭐ Acceptable | Fastest | Minimal hardware |

**Recommendation:** Start with **Llama 3 13B** - best balance of quality and hardware requirements.

---

### Performance Comparison

| Aspect | Claude Pro | Claude Enterprise | Local (70B) | Local (13B) | Local (7B) |
|--------|------------|-------------------|-------------|-------------|------------|
| **Analysis Quality** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Speed** | 1-3 sec | 1-3 sec | 5-15 sec | 2-5 sec | 1-3 sec |
| **Cost** | $20/mo | $30+/user/mo | Hardware only | Hardware only | Hardware only |
| **Data Privacy** | Anthropic policy | Enhanced controls | Complete control | Complete control | Complete control |
| **Internet** | Required | Required | Not required | Not required | Not required |
| **CUI/Classified** | ❌ No | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes |
| **CMMC Support** | ❌ No | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes |
| **Initial Investment** | $0 | $0 | $5k-15k | $2k-5k | $500-1k |

*Speed estimates based on typical queries. Actual performance varies by hardware, query complexity, and data volume.*

---

### Use Cases by Deployment Type

#### Cloud LLM (Claude Pro)

**✅ Best for:**
- Public OSINT threat intelligence (TLP:CLEAR)
- Academic research and education
- Startup/small business without sensitive data
- Proof of concept and testing
- Community threat intelligence sharing

**❌ Not suitable for:**
- Classified intelligence (SECRET, TOP SECRET)
- CUI (defense contractors)
- Proprietary threat intelligence
- Customer/client data
- Active investigations

---

#### Cloud LLM (Claude Enterprise)

**✅ Potentially suitable for (with organizational approval):**
- TLP:AMBER corporate intelligence
- Internal proprietary research
- Financial analysis (with compliance approval)
- Executive protection intelligence

**❌ Still NOT suitable for:**
- CUI (not FedRAMP authorized - violates CMMC)
- Classified information (any level)
- ITAR-controlled data
- Data sovereignty requirements
- Highly regulated PHI (unless BAA verified with Anthropic)

**⚠️ Requires written approval from:**
- Legal/compliance team
- Data protection officer
- Chief Information Security Officer
- Document decision in risk register

---

#### Local LLM (Air-Gapped)

**✅ Best for:**
- Defense contractors (CMMC technical requirements)
- Government classified networks
- Financial services (GLBA, SOX compliance)
- Healthcare (HIPAA protected data)
- Law enforcement investigations
- Corporate espionage defense
- M&A due diligence (confidential)
- Executive protection intelligence
- ITAR-controlled information

**❌ Not suitable for:**
- Organizations without adequate hardware
- Teams lacking AI/ML operations expertise
- Budget-constrained deployments (cloud cheaper upfront)

---

### TLP Filtering with Local LLM

**Question:** "If I'm using a local LLM, do I still need TLP filtering?"

**Answer:** YES - recommended for multiple reasons:

**Organizational Governance:**
- Enforce data handling policies technically
- Prevent accidental queries of restricted data
- Document access for audit compliance
- Train junior analysts on classification

**Multi-User Environments:**
- Different analysts with different clearances
- Enforce least privilege access
- Prevent mistakes under pressure (incident response)

**Defense in Depth:**
- Technical control backing human judgment
- Compliance evidence (logs show policy enforcement)
- Fail-safe for misconfigured systems

**Example Scenario:**
```
Analyst (SECRET clearance) queries OpenCTI
OpenCTI contains mix of UNCLASSIFIED and TOP SECRET intel
MCP server filters: Only returns UNCLASSIFIED and SECRET
Analyst never sees TOP SECRET (even with local LLM)
Audit log proves policy compliance
```

---

### Compliance Considerations

#### CMMC (CUI in Cloud)

**Cloud LLM:**
- ❌ Claude Pro: Cannot process CUI via cloud services
- ❌ Claude Enterprise: NOT FedRAMP authorized - still violates CMMC
- ✅ TLP:CLEAR public intelligence only

**Local LLM:**
- ✅ Supports CMMC Level 2 technical requirements
- ✅ Air-gapped deployment supported
- ⚠️ Organization must document in System Security Plan (SSP)

---

#### CMMC Level 2 (Enhanced CUI Protection)

**Technical requirements:**
- Air-gapped or highly controlled environment
- Multi-factor authentication
- Enhanced access controls

**Cloud LLM:**
- ❌ Not suitable at any level

**Local LLM:**
- ✅ Supports technical requirements
- ✅ TLP filtering provides documented technical controls
- ✅ Audit logs meet CMMC requirements
- ⚠️ Organization responsible for SSP, POA&M documentation

---

#### NIST 800-171

**Requirement 3.13.11:** "Employ cryptographic mechanisms to protect the confidentiality of CUI during transmission."

**Cloud LLM:**
- ⚠️ Sending CUI to external systems (even encrypted) may violate this requirement
- Consult your SSP (System Security Plan)

**Local LLM:**
- ✅ No transmission outside your infrastructure
- ✅ Full compliance with encryption requirements

---

#### HIPAA

**Cloud LLM:**
- ❌ Claude Pro: No BAA available
- ⚠️ Claude Enterprise: MAY have BAA (verify with Anthropic before use)
- ⚠️ Threat intelligence typically doesn't contain PHI, but verify

**Local LLM:**
- ✅ PHI never leaves covered entity infrastructure
- ✅ No BAA required
- ✅ Full compliance with Security Rule

---

### Troubleshooting Local LLM Setup

**"Model is too slow"**
- Try smaller model (13B instead of 70B)
- Check GPU utilization (should be >80%)
- Reduce context length in model config
- Consider quantized models (GGUF format)

**"Out of memory errors"**
- Model too large for your GPU
- Try smaller model or quantized version
- Use CPU inference (slower but works)

**"MCP client can't connect to local model"**
- Verify Ollama/LM Studio is running
- Check endpoint URL (usually localhost:11434 for Ollama)
- Test with curl: `curl http://localhost:11434/api/tags`
- Check firewall rules

**"Model quality seems poor"**
- Use larger model (70B significantly better than 7B)
- Check prompt formatting (some models are picky)
- Try different model (Llama vs Mistral vs Codestral)

---

### Questions About Air-Gapped Deployment?

**Technical support:**
- Ollama: https://ollama.com/docs
- LM Studio: https://lmstudio.ai/docs
- vLLM: https://docs.vllm.ai/

**This project:**
- Email: matt@coopercybercoffee.com
- GitHub Issues: https://github.com/CooperCyberCoffee/opencti_mcp_server/issues

**For Claude Enterprise inquiries:**
- Contact Anthropic directly for pricing and BAA availability
- Get written confirmation of data handling policies
- Document approval in your risk register

**For classified/CUI deployments:**
This project is MIT licensed - deploy however needed for your mission. No restrictions, no vendor lock-in, no licensing fees.

---

## Troubleshooting

### "Connection refused" or "Cannot connect to OpenCTI"

**Causes:**
- OpenCTI is not running
- Wrong URL in configuration
- Network/firewall issues

**Solutions:**
1. Check OpenCTI is running:
   ```bash
   # If using Docker:
   docker ps | grep opencti

   # Should see opencti containers running
   ```

2. Verify URL is correct:
   ```bash
   # Test with curl:
   curl http://localhost:8080/graphql

   # Should return GraphQL schema or "Unauthorized"
   ```

3. Check `.env` file has correct `OPENCTI_URL`

---

### "Authentication failed" or "Invalid token"

**Causes:**
- Wrong API token
- Token expired or revoked
- Token doesn't have required permissions

**Solutions:**
1. Verify token in OpenCTI web interface:
   - Log in → Profile → Settings → API Access
   - Check token is active

2. Copy token exactly (no extra spaces):
   ```bash
   # In .env file:
   OPENCTI_TOKEN=abc123-your-token-here
   # No quotes, no spaces
   ```

3. Regenerate token if necessary

---

### "Module not found" or "ImportError"

**Causes:**
- Dependencies not installed
- Wrong Python environment

**Solutions:**
1. Activate virtual environment:
   ```bash
   source venv/bin/activate  # macOS/Linux
   venv\Scripts\activate     # Windows
   ```

2. Reinstall dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Verify installation:
   ```bash
   pip list | grep pycti
   # Should show: pycti    6.x.x
   ```

---

### "MCP server not appearing in Claude Desktop"

**Causes:**
- Config file has syntax errors
- Wrong Python path
- Claude Desktop not restarted

**Solutions:**
1. Validate JSON syntax:
   ```bash
   # Use a JSON validator:
   cat ~/Library/Application\ Support/Claude/claude_desktop_config.json | python -m json.tool

   # Should show formatted JSON with no errors
   ```

2. Check Python path is absolute:
   ```bash
   # Get full path:
   which python  # macOS/Linux
   where python  # Windows

   # Use this EXACT path in config
   ```

3. Fully quit and restart Claude Desktop (don't just close window)

4. Check Claude Desktop logs:
   - Help → Show Logs
   - Look for MCP server startup errors

---

### "No data found" or "Entity not found"

**Causes:**
- OpenCTI database is empty
- Search term doesn't match any entities
- Case sensitivity issues

**Solutions:**
1. Check if OpenCTI has data:
   ```
   You: "Check my OpenCTI connection"
   # Should show "Database: Contains threat intelligence data"
   ```

2. Import threat intelligence:
   - Use OpenCTI connectors to import data
   - Common sources: MISP feeds, MITRE ATT&CK, AlienVault OTX

3. Try alternative search terms:
   ```
   # Instead of: "APT 28"
   # Try: "APT28" or "Fancy Bear" (alias)
   ```

4. Use search_entities to explore:
   ```
   You: "Search for entities related to russia"
   ```

---

### "SSL verification failed"

**Causes:**
- Self-signed certificates
- SSL misconfiguration

**Solutions:**
1. For development/testing, disable SSL verification:
   ```bash
   # In .env file:
   OPENCTI_SSL_VERIFY=false
   ```

2. For production, use valid SSL certificates

---

## Contributing

This is an educational open-source project and contributions are welcome!

### How to Contribute

1. **Fork the repository**
   - Click "Fork" on GitHub
   - Clone your fork locally

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow existing code style
   - Add docstrings to new functions
   - Include type hints
   - Update README if adding features

4. **Test your changes**
   ```bash
   # Test the MCP server
   python main.py

   # Test in Claude Desktop
   ```

5. **Commit with clear messages**
   ```bash
   git add .
   git commit -m "Add feature: brief description"
   ```

6. **Push and create pull request**
   ```bash
   git push origin feature/your-feature-name
   ```
   - Go to GitHub and create pull request
   - Describe your changes clearly

### Development Guidelines

- **Code Quality:** Production-ready code from day one
- **Documentation:** Google-style docstrings on all functions
- **Type Hints:** Use Python type hints throughout
- **Error Handling:** Comprehensive error handling with helpful messages
- **Copyright:** All Python files include Cooper Cyber Coffee copyright header
- **Testing:** Test with OpenCTI 6.x before submitting

### Ideas for Contributions

- Add new MCP tools for additional OpenCTI entities
- Improve error messages and user feedback
- Add caching optimizations
- Create example queries and use cases
- Improve documentation
- Add unit tests
- Create video tutorials

---

## About Cooper Cyber Coffee

**Mission:** Making enterprise-grade cybersecurity capabilities accessible to organizations that can't afford traditional solutions.

**The Cooper Cyber Coffee methodology demonstrates how to build professional security capabilities using:**
- Free and open-source tools (OpenCTI, MISP, TheHive)
- AI augmentation (Claude, local LLMs)
- Cloud platforms (AWS, Azure)
- Modern development practices

**Target:** Crossing the "cyber poverty line" - providing supply chain partners with threat intelligence capabilities they couldn't otherwise afford.

**Philosophy:**
- Simple > Clever (maintainability wins)
- Explicit > Implicit (clarity over magic)
- Tested > Assumed (if untested, it's broken)
- Documented > Self-evident (help future-you)

**This project is part of that mission - demonstrating that effective threat intelligence analysis doesn't require expensive enterprise platforms.**

---

## License

MIT License - Free for all use, including commercial projects.

Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

See [LICENSE.md](LICENSE.md) for full license text.

**What this means:**
- ✅ Use for any purpose (personal, educational, commercial)
- ✅ Modify and distribute
- ✅ Private use
- ✅ No attribution required (but appreciated!)

---

## Acknowledgments

- **OpenCTI Team** - For building an amazing open-source threat intelligence platform
- **Anthropic** - For Claude and the MCP protocol
- **MITRE** - For the ATT&CK framework
- **The Security Community** - For sharing knowledge and building in public

---

## Built By

**Matthew Hopkins** - Senior Staff Cyber Intelligence Analyst with 8+ years in Fortune 500 threat intelligence, and creator of the Cooper Cyber Coffee methodology.

- **LinkedIn:** [matthew-hopkins](https://linkedin.com/in/matthew-hopkins)
- **Cooper Cyber Coffee:** [coopercybercoffee.com](https://coopercybercoffee.com)
- **Email:** matt@coopercybercoffee.com

---

## Contact

**Questions or feedback?**

**Email:** matt@coopercybercoffee.com

**Project updates:** Follow on [LinkedIn](https://linkedin.com/in/matthew-hopkins)

**Found a bug?** [Open a GitHub issue](https://github.com/CooperCyberCoffee/opencti_mcp_server/issues)

**Want to contribute?** See Contributing section above

---

**Built with ☕ by the Cooper Cyber Coffee community**

*Crossing the cyber poverty line, one open-source project at a time.*
