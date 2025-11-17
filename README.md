# Cooper Cyber Coffee OpenCTI MCP Server

**Connect Claude Desktop to OpenCTI for AI-augmented threat intelligence analysis**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenCTI](https://img.shields.io/badge/OpenCTI-6.x-green.svg)](https://www.opencti.io/)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![Claude Desktop](https://img.shields.io/badge/Claude-Desktop-purple.svg)](https://claude.ai/)

An open-source educational project demonstrating how to bridge Claude Desktop with OpenCTI's threat intelligence platform using the Model Context Protocol (MCP). Ask questions about threats in natural language and get instant, contextualized answers from your threat intelligence database.

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
- Expensive enterprise features for basic analysis

**The Solution:** With this MCP server, you can:

```
You: "What TTPs does APT28 use?"
Claude: *Instantly shows 47 MITRE ATT&CK techniques with descriptions*

You: "Which ones target email?"
Claude: *Filters to spearphishing techniques with kill chain phases*

You: "Show me recent indicators for those campaigns"
Claude: *Retrieves IOCs with context and analysis templates*
```

**Cost Comparison:**
- Traditional Enterprise TIP: $50k-500k/year + training
- OpenCTI + Claude + This MCP: Free (OpenCTI) + $20/month (Claude Pro)

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

The MCP server provides 12 tools organized by function:

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

#### 3. search_by_hash_with_context
**What it does:** Searches for indicators by file hash (MD5, SHA1, SHA256) with full context.

**Example query:** "Search for hash 44d88612fea8a8f36de82e1278abb02f"

**What you get:**
- Indicator details
- Related malware families
- Associated threat actors
- Detection patterns

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

**Supported platforms:** macOS, Windows, Linux

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
python -m opencti_mcp
```

**Expected output:**
```
[INFO] OpenCTI MCP Server starting...
[INFO] Connected to OpenCTI version 6.x.x
[INFO] MCP server ready
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

**Hash Investigation:**
```
You: "Search for hash 44d88612fea8a8f36de82e1278abb02f"

Claude: *Shows indicator details, associated malware,
        threat context, and detection guidance*
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
   - 12 specialized tools
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
   python -m opencti_mcp

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

## Contact

**Questions or feedback?**

**Email:** matt@coopercybercoffee.com

**Project updates:** Follow on [LinkedIn](https://linkedin.com/in/matthew-hopkins)

**Found a bug?** [Open a GitHub issue](https://github.com/CooperCyberCoffee/opencti_mcp_server/issues)

**Want to contribute?** See Contributing section above

---

## About Cooper Cyber Coffee

**Mission:** Making enterprise-grade cybersecurity capabilities accessible to organizations that can't afford traditional solutions.

**The Cooper Cyber Coffee methodology demonstrates how to build professional security capabilities using:**
- Free and open-source tools (OpenCTI, MISP, TheHive)
- AI augmentation (Claude, GPT)
- Cloud platforms (AWS, Azure)
- Modern development practices

**Target:** Crossing the "cyber poverty line" - providing supply chain partners with threat intelligence capabilities at $20/month instead of $500k/year.

**Philosophy:**
- Simple > Clever (maintainability wins)
- Explicit > Implicit (clarity over magic)
- Tested > Assumed (if untested, it's broken)
- Documented > Self-evident (help future-you)

**This project is part of that mission - demonstrating that effective threat intelligence analysis doesn't require expensive enterprise platforms.**

---

## Acknowledgments

- **OpenCTI Team** - For building an amazing open-source threat intelligence platform
- **Anthropic** - For Claude and the MCP protocol
- **MITRE** - For the ATT&CK framework
- **The Security Community** - For sharing knowledge and building in public

---

**Built with ☕ by the Cooper Cyber Coffee community**

*Crossing the cyber poverty line, one open-source project at a time.*
