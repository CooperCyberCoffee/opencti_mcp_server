# Migration Guide: v0.1.0 → v0.2.0

## Overview

Version 0.2.0 moves configuration from hard-coded Python to simple Markdown files.

**Why?** Makes customization accessible to everyone, not just Python developers. Security analysts, threat intelligence professionals, and anyone who can edit text files can now customize analysis templates, define organizational priorities, and document their security stack - without touching code.

**Time required:** 30 seconds to 10 minutes (depending on customization level)

---

## What Changed

### Templates Location

**Before (v0.1.0):**
```python
# Hard-coded in src/opencti_mcp/templates.py
class AnalysisTemplates:
    @staticmethod
    def executive_briefing_template():
        return """
        Please analyze the provided threat intelligence...
        """
```

**After (v0.2.0):**
```markdown
# Simple Markdown file: config/templates/executive_briefing.md

# Executive Briefing Template

Please analyze the provided threat intelligence data and format as an executive briefing:

## Executive Summary
...
```

### New Configuration Files

Three new configuration capabilities:

1. **`config/pirs.md`** - Your organization's intelligence priorities
   - What threats you care about
   - Your technology stack
   - Strategic business priorities

2. **`config/security_stack.md`** - Your deployed security controls
   - Tools you have (EDR, SIEM, firewall, etc.)
   - What you monitor and block
   - Known gaps in coverage

3. **`config/templates/*.md`** - All analysis templates
   - Executive briefing
   - Technical analysis
   - Incident response
   - Trend analysis

### Code Changes

**Before:**
```python
from .templates import AnalysisTemplates

template = AnalysisTemplates.get_template('executive')
```

**After:**
```python
from .config_manager import ConfigManager

config = ConfigManager()
full_context = config.get_full_context('executive_briefing')
# Now includes template + PIRs + security stack automatically!
```

---

## Migration Scenarios

### Scenario 1: You Haven't Modified Code (Most Users)

**Steps:**
```bash
# Update to latest
git pull origin main

# Done! New config files have example content
```

**What you get:**
- All 4 templates automatically converted to Markdown
- Example PIRs file ready to customize
- Example security stack file ready to customize

**Time required:** 30 seconds

**Next step:** Optionally customize `config/pirs.md` and `config/security_stack.md` for your organization (15-45 minutes)

---

### Scenario 2: You Customized Templates in Python

If you edited `src/opencti_mcp/templates.py` with custom analysis formats:

**Step 1: Save your customizations**
```bash
# Check what you changed
git diff v0.1.0 src/opencti_mcp/templates.py > my_template_changes.diff

# Or just view the file
cat src/opencti_mcp/templates.py
```

**Step 2: Copy customizations to Markdown**

1. Open the template you customized (e.g., `config/templates/executive_briefing.md`)
2. Paste your custom content
3. Save file

**Example:**
```bash
# If you customized the executive briefing template
vim config/templates/executive_briefing.md

# Paste your custom template content
# Save and close
```

**Step 3: Reset Python code to upstream**
```bash
# Get fresh version from main branch
git checkout origin/main src/opencti_mcp/templates.py
```

**Time required:** 5-10 minutes per customized template

---

### Scenario 3: You Want Organization-Specific Configuration

**Step 1: Create local configuration copies** (recommended for private configs)
```bash
# Create private versions that won't be tracked in git
cp config/pirs.md config/pirs.local.md
cp config/security_stack.md config/security_stack.local.md

# Add to .gitignore
echo "config/*.local.md" >> .gitignore
```

**Step 2: Edit your local copies**
```bash
# Edit with your favorite editor
vim config/pirs.local.md
vim config/security_stack.local.md
```

**Step 3: Update ConfigManager to load .local files first** (optional)

Edit `src/opencti_mcp/config_manager.py` to prefer `.local.md` versions:

```python
def _load_file(self, filename: str) -> str:
    # Try .local version first
    local_filename = filename.replace('.md', '.local.md')
    local_filepath = self.config_dir / local_filename

    if local_filepath.exists():
        filepath = local_filepath
    else:
        filepath = self.config_dir / filename

    # ... rest of method
```

**Alternative (simpler):** Just edit the default `config/pirs.md` and `config/security_stack.md` directly if you're not contributing back to the repo.

**Time required:** 45 minutes (including thoughtful customization)

---

### Scenario 4: You Want Industry-Specific Templates

**Step 1: Check examples directory**
```bash
ls examples/

# Look for your industry:
# - examples/healthcare/
# - examples/finance/
# - examples/manufacturing/
# - examples/retail/
```

**Step 2: Copy industry template**
```bash
# Example: Healthcare organization
cp examples/healthcare/pirs.md config/pirs.md
cp examples/healthcare/security_stack.md config/security_stack.md
```

**Step 3: Customize for your specific organization**
- Update company size, geography
- Add your specific technology stack
- Modify threat priorities for your risk profile

**Time required:** 15-20 minutes

**Note:** If your industry isn't in `/examples`, consider contributing one! See Contributing section below.

---

## Breaking Changes

### 1. AnalysisTemplates Class Removed

**What broke:**
```python
from .templates import AnalysisTemplates  # ❌ This import fails

template = AnalysisTemplates.get_template('executive')  # ❌ Class doesn't exist
```

**How to fix:**
```python
from .config_manager import ConfigManager  # ✅ Use new class

config = ConfigManager()
template = config.get_full_context('executive_briefing')  # ✅ New method
```

**Who this affects:** Developers who imported `AnalysisTemplates` in custom code

### 2. Template Names Changed

**What broke:**
- `'executive'` → `'executive_briefing'`
- `'technical'` → `'technical_analysis'`
- `'incident_response'` → No change
- `'trend_analysis'` → No change

**How to fix:**
Update any code referencing templates to use full names.

**Who this affects:** Custom scripts calling MCP tools with `analysis_type` parameter

### 3. Configuration File Required

**What broke:**
Server won't start if `config/` directory doesn't exist.

**How to fix:**
```bash
# Create config directory if missing
mkdir -p config/templates

# Pull latest templates from repo
git pull origin main
```

**Who this affects:** Users running from source without git (rare)

---

## Benefits of New Approach

✅ **Easier to customize** - Edit text files, no Python required
✅ **Version control friendly** - Track template changes separately from code
✅ **Community shareable** - Contribute industry-specific templates
✅ **LLM-native** - Claude parses any format naturally, optimize for humans
✅ **Context-aware** - PIRs and security stack automatically included in analysis
✅ **Maintainable** - Update templates without touching code
✅ **Testable** - Templates are data, not code - easier to validate
✅ **Portable** - Copy configs between environments easily

---

## Testing Your Migration

### 1. Verify Configuration Loads

```bash
# Run the MCP server
python -m opencti_mcp

# Look for these log messages:
# [INFO] Loaded config file: pirs.md
# [INFO] Loaded config file: security_stack.md
# [INFO] Loaded template: executive_briefing
# [INFO] Loaded template: technical_analysis
# [INFO] Loaded template: incident_response
# [INFO] Loaded template: trend_analysis
# [INFO] ConfigManager initialized: 4 templates loaded
```

### 2. Test Template Access

```python
from opencti_mcp.config_manager import ConfigManager

config = ConfigManager()

# List available templates
print(config.list_templates())
# Expected: ['executive_briefing', 'incident_response', 'technical_analysis', 'trend_analysis']

# Get full context (template + PIRs + security stack)
context = config.get_full_context('executive_briefing')
print(len(context))  # Should be > 1000 characters

# Check configuration status
status = config.get_config_status()
print(status)
# Expected: has_pirs=True, has_security_stack=True, templates_count=4
```

### 3. Test End-to-End Analysis

In Claude Desktop:

```
You: "Check my OpenCTI connection"
# Should work normally

You: "Get recent indicators with executive briefing analysis"
# Should include your PIRs and security stack context in analysis
```

**Expected behavior:** Claude's analysis should reference:
- Your organization profile (if you customized PIRs)
- Your security tools (if you customized security stack)
- Your specific priorities and threat actors

---

## Rollback (If Needed)

If you encounter issues with v0.2.0:

```bash
# Rollback to v0.1.0
git checkout v0.1.0

# Or rollback just the specific files
git checkout v0.1.0 -- src/opencti_mcp/templates.py
git checkout v0.1.0 -- src/opencti_mcp/server.py
```

**Note:** Rollback is **not recommended** - v0.2.0 has better architecture for long-term maintainability. If you encounter issues, please open a GitHub issue so we can help and improve the migration guide.

---

## Need Help?

### Common Issues

**Issue:** `ConfigManager` not found
```bash
# Solution: Make sure you pulled latest code
git pull origin main
```

**Issue:** Templates directory not found
```bash
# Solution: Create config structure
mkdir -p config/templates
git pull origin main  # Get template files
```

**Issue:** Server starts but analysis quality decreased
```bash
# Solution: Customize PIRs and security stack
vim config/pirs.md
vim config/security_stack.md
```

**Issue:** Custom templates not loading
```bash
# Solution: Check file naming (must be .md extension)
ls config/templates/
# Should see: executive_briefing.md, technical_analysis.md, etc.
```

### Get Support

**Email:** matt@coopercybercoffee.com

**GitHub Issues:** [opencti_mcp_server/issues](https://github.com/CooperCyberCoffee/opencti_mcp_server/issues)

**LinkedIn:** [Matthew Hopkins](https://linkedin.com/in/matthew-hopkins)

---

## Contributing Your Configurations

Help others in your industry!

### Share Industry-Specific PIRs

```bash
# Create anonymized version
cp config/pirs.md examples/your-industry/pirs.md

# Remove sensitive details:
# - Company names
# - Specific IP addresses
# - Internal system names
# - Confidential priorities

# Submit PR
git checkout -b add-industry-template
git add examples/your-industry/
git commit -m "Add example PIRs for [industry] sector"
git push origin add-industry-template
```

### Share Role-Specific Templates

Create templates for different audiences:
- CISO update template
- Board reporting template
- SOC analyst template
- Compliance reporting template

### Share Security Stack Examples

Help others benchmark:
- Startup security stack (limited budget)
- Mid-market security stack (growing team)
- Enterprise security stack (mature program)
- Cloud-first security stack
- Hybrid/on-prem security stack

---

## Frequently Asked Questions

**Q: Can I keep using the old hard-coded templates?**
A: No, `AnalysisTemplates` was removed in v0.2.0. Migration is required.

**Q: Do I have to customize PIRs and security stack?**
A: No, they're optional. Templates work without them, but analysis is more generic.

**Q: Can I create custom templates?**
A: Yes! Add any `.md` file to `config/templates/` and reference it by name (without .md extension).

**Q: Will my customizations be overwritten on git pull?**
A: No, if you edit files in `config/`, they're tracked separately. Use `.local.md` files for private configs.

**Q: Can I use different configs for different environments (dev/prod)?**
A: Yes, set `CONFIG_DIR` environment variable to point to different config directories.

**Q: How do I version control my organization's configs?**
A: Fork the repo, commit your customizations to your fork, pull upstream updates as needed.

**Q: Can I share configs within my organization?**
A: Yes! Commit to internal git repo, share via network drive, or use config management tools.

---

**Total Migration Time:**
- No customizations: 30 seconds
- With template customizations: 5-10 minutes
- With full org customization: 45 minutes

**Recommendation:** Start with basic migration (30 seconds), then customize PIRs and security stack over time as you use the tool.

---

*Configuration is documentation that makes AI smarter. Invest time in customization, get better analysis forever.*

**Cooper Cyber Coffee** - Making enterprise-grade threat intelligence accessible to everyone.
