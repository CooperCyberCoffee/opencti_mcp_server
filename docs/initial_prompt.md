I need you to build an MCP server for OpenCTI threat intelligence queries following Anthropic's official MCP best practices and incorporating enterprise-grade features inspired by successful MCP implementations. This is for the Cooper Cyber Coffee project - build incrementally with focus on getting core functionality working first.

**TARGET PLATFORM: OpenCTI 6.x (Latest Major Version)**
This project targets OpenCTI 6.x only. We'll add version validation and clear error messages for unsupported versions.

**SETUP: Project Foundation**

Create essential project structure and licensing:

**1. Create LICENSE.md file:**
```markdown
# MIT License

**Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee**

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## About Cooper Cyber Coffee

This project is part of the **Cooper Cyber Coffee** research initiative - demonstrating how to build enterprise-grade cybersecurity capabilities using free and open-source tools, enhanced with AI through Claude.

**Built by:** [Matthew Hopkins](https://linkedin.com/in/matthew-hopkins)  
**Project:** [Cooper Cyber Coffee](https://coopercybercoffee.com)

### Commercial Inquiries

For consulting, custom development, enterprise support, or acquisition inquiries:

**📧 Email:** business@coopercybercoffee.com  
**💼 LinkedIn:** [linkedin.com/in/matthew-hopkins](https://linkedin.com/in/matthew-hopkins)  
**🔗 Website:** [coopercybercoffee.com](https://coopercybercoffee.com)

---

*"Democratizing AI-enhanced cybersecurity tools, one integration at a time."*
```

**2. Create .gitignore file:**
```
# Environment and secrets
.env
*.env
.env.local
.env.production

# API tokens and credentials
opencti_token.txt
api_keys/
secrets/

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
env/
ENV/
.venv/

# IDE and editor files
.vscode/
.idea/
*.swp
*.swo
*~

# OS files
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Test coverage
.coverage
htmlcov/
.pytest_cache/

# MCP specific
mcp_sessions/
*.session

# Docker
.dockerignore
```

**3. Create Dockerfile for Enterprise Deployment:**
```dockerfile
FROM python:3.9-slim

LABEL maintainer="Matthew Hopkins <business@coopercybercoffee.com>"
LABEL description="Cooper Cyber Coffee OpenCTI MCP Server"
LABEL version="1.0.0"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ ./src/
COPY main.py .

# Create non-root user
RUN useradd -r -s /bin/false mcp && \
    chown -R mcp:mcp /app

USER mcp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["python", "main.py"]
```

**4. Create README.md:**
```markdown
# Cooper Cyber Coffee OpenCTI MCP Server

**The industry-standard MCP server for OpenCTI 6.x threat intelligence**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenCTI](https://img.shields.io/badge/OpenCTI-6.x-green.svg)](https://www.opencti.io/)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![Claude Desktop](https://img.shields.io/badge/Claude-Desktop-purple.svg)](https://claude.ai/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)

Transform OpenCTI's raw threat intelligence into Claude-compatible insights with professional analysis templates, replacing expensive enterprise automation features with free, AI-enhanced alternatives.

## 🎯 Project Status

**⚠️ In Development:** Core functionality implementation in progress. Documentation and features coming soon.

## 💡 What This Enables

Replace expensive threat intelligence platform features with AI-enhanced workflows:

- **Manual Analysis** → **AI-Assisted Pattern Recognition with Templates**
- **Static Dashboards** → **Natural Language Queries with Context**  
- **Complex Workflows** → **Automated Intelligence Processing**
- **Enterprise Licensing** → **Open Source + Claude + Professional Templates**

## 🚀 Key Features

### Professional Analysis Templates
- **Executive Briefing Templates** - Board-ready threat summaries
- **Technical Analysis Templates** - Detailed attribution and TTP analysis
- **Incident Response Templates** - Structured response guidance
- **Trend Analysis Templates** - Strategic threat landscape insights

### Enterprise-Ready Deployment
- **Docker containerization** for easy deployment
- **Professional error handling** with helpful diagnostics
- **Comprehensive logging** for audit and compliance
- **Health checks** and monitoring endpoints

## 📋 Requirements

- **OpenCTI 6.x** (required - earlier versions not supported)
- **Python 3.9+**
- **Claude Desktop** (for MCP integration)
- **Docker** (optional, for containerized deployment)

## 🚀 Cooper Cyber Coffee Initiative

This is part of the **Cooper Cyber Coffee** research project - demonstrating how to build enterprise-grade cybersecurity capabilities using free and open-source tools, with AI enhancement through Claude.

**Cost Comparison:**
- **Traditional Enterprise TI Platform:** $50k-500k/year
- **Cooper Cyber Coffee Stack:** $0/month (OpenCTI + Claude + This MCP)
- **Time Savings:** Manual analysis (30min) → AI-assisted (30sec)

## 🏆 Built By

**Matthew Hopkins** - Senior Staff Cyber Intelligence Analyst, cybersecurity professional with 8+ years in Fortune 500 threat intelligence, and creator of the Cooper Cyber Coffee methodology.

- **LinkedIn:** [matthew-hopkins](https://linkedin.com/in/matthew-hopkins)
- **Cooper Cyber Coffee:** [coopercybercoffee.com](https://coopercybercoffee.com)

## 💼 Enterprise Inquiries

For consulting, custom development, enterprise support, training, or acquisition discussions:

**📧 Business:** business@coopercybercoffee.com  
**🎤 Speaking:** speaking@coopercybercoffee.com  
**🔧 Consulting:** consulting@coopercybercoffee.com

### Services Available
- Enterprise MCP server implementation
- AI-enhanced threat intelligence consulting  
- Custom security tool integrations
- Claude Desktop workflow training
- Conference speaking and workshops

## 📄 License

MIT License - Free for all use. See [LICENSE.md](LICENSE.md) for details.

## 🤝 Contributing

This project welcomes contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with clear documentation

## 📞 Connect

- **Project Updates:** Follow on [LinkedIn](https://linkedin.com/in/matthew-hopkins)
- **Technical Support:** Open a GitHub issue
- **Business Inquiries:** business@coopercybercoffee.com

---

*Building the future of accessible, AI-enhanced cybersecurity tools.*
```

**FOCUS: Core MCP Server Implementation with Professional Templates**

**Required Dependencies:**
```
mcp>=1.0.0
pycti>=6.0.0
aiohttp>=3.8.0
python-dotenv>=1.0.0
pydantic>=2.0.0
```

**Project Structure:**
```
opencti-mcp-server/
├── schemas/
│   └── opencti-6x-schema.graphql
├── src/
│   └── opencti_mcp/
│       ├── __init__.py
│       ├── server.py              # MCP server implementation
│       ├── opencti_client.py      # OpenCTI pycti client wrapper
│       ├── templates.py           # Professional analysis templates
│       ├── tools.py               # MCP tool implementations
│       └── utils.py               # Helper functions
├── .env.example
├── .gitignore
├── Dockerfile                     # Enterprise deployment
├── LICENSE.md                     # MIT License
├── requirements.txt
├── README.md                      # Professional documentation
└── main.py
```

**IMPORTANT: Copyright Headers**

Add this copyright header to ALL Python source files:

```python
"""
Cooper Cyber Coffee OpenCTI MCP Server
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

For consulting and enterprise inquiries: business@coopercybercoffee.com
"""
```

**PHASE 1: OpenCTI Client with Professional pycti Integration**

**OpenCTI Client Using Official Python Library:**
```python
"""
Cooper Cyber Coffee OpenCTI MCP Server
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)
"""

import logging
from typing import Dict, List, Optional, Any
from pycti import OpenCTIApiClient
import asyncio
from concurrent.futures import ThreadPoolExecutor

class OpenCTIClient:
    """Professional OpenCTI client wrapper with async support and error handling"""
    
    def __init__(self, url: str, token: str, ssl_verify: bool = False):
        self.url = url
        self.token = token
        self.ssl_verify = ssl_verify
        self._client = None
        self._executor = ThreadPoolExecutor(max_workers=4)
        self.logger = logging.getLogger(__name__)
        
    async def _get_client(self) -> OpenCTIApiClient:
        """Lazy initialization of OpenCTI client"""
        if self._client is None:
            self._client = OpenCTIApiClient(
                url=self.url,
                token=self.token,
                ssl_verify=self.ssl_verify,
                log_level="INFO"
            )
        return self._client
    
    async def validate_opencti_setup(self) -> Dict[str, Any]:
        """Validate OpenCTI 6.x setup and data availability"""
        try:
            client = await self._get_client()
            
            # Check version and basic connectivity
            def _check_version():
                # Get platform info
                about_info = client.admin.about()
                version = about_info.get('version', 'unknown')
                
                # Check for indicators (basic data availability)
                indicators = client.indicator.list(first=1)
                has_indicators = len(indicators) > 0
                
                # Check connectors
                connectors = client.connector.list(first=5)
                active_connectors = [c for c in connectors if c.get('active', False)]
                
                return {
                    "version": version,
                    "has_data": has_indicators,
                    "active_connectors": len(active_connectors),
                    "status": "ready" if has_indicators else "empty_database",
                    "connector_names": [c.get('name', 'unknown') for c in active_connectors[:3]]
                }
            
            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _check_version
            )
            
            # Validate version
            version = result["version"]
            if not version.startswith("6."):
                raise ValueError(f"OpenCTI 6.x required, found version {version}")
                
            self.logger.info(f"OpenCTI validation successful: {result}")
            return result
            
        except Exception as e:
            self.logger.error(f"OpenCTI validation failed: {e}")
            raise
    
    async def get_recent_indicators(
        self, 
        limit: int = 10, 
        indicator_types: Optional[List[str]] = None,
        days_back: int = 7,
        min_confidence: int = 50
    ) -> List[Dict[str, Any]]:
        """Get recent indicators with filtering"""
        try:
            client = await self._get_client()
            
            def _get_indicators():
                # Build filters
                filters = []
                
                if indicator_types:
                    # Convert to OpenCTI filter format
                    type_filter = {
                        "key": "indicator_types",
                        "values": indicator_types,
                        "operator": "eq",
                        "mode": "or"
                    }
                    filters.append(type_filter)
                
                if min_confidence > 0:
                    confidence_filter = {
                        "key": "confidence",
                        "values": [str(min_confidence)],
                        "operator": "gte"
                    }
                    filters.append(confidence_filter)
                
                # Get indicators
                indicators = client.indicator.list(
                    first=limit,
                    filters=filters if filters else None,
                    orderBy="created_at",
                    orderMode="desc"
                )
                
                # Format for MCP consumption
                formatted = []
                for indicator in indicators:
                    formatted_indicator = {
                        "id": indicator.get("id"),
                        "pattern": indicator.get("pattern"),
                        "indicator_types": indicator.get("indicator_types", []),
                        "confidence": indicator.get("confidence"),
                        "created_at": indicator.get("created_at"),
                        "valid_from": indicator.get("valid_from"),
                        "valid_until": indicator.get("valid_until"),
                        "labels": [label.get("value") for label in indicator.get("objectLabel", [])],
                        "markings": [marking.get("definition") for marking in indicator.get("objectMarking", [])]
                    }
                    formatted.append(formatted_indicator)
                
                return formatted
            
            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _get_indicators
            )
            
            self.logger.info(f"Retrieved {len(result)} indicators")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to get indicators: {e}")
            raise
    
    async def search_by_hash(self, hash_value: str) -> List[Dict[str, Any]]:
        """Search for indicators by hash value"""
        try:
            client = await self._get_client()
            
            def _search_hash():
                indicators = client.indicator.list(
                    search=hash_value,
                    filters=[{
                        "key": "pattern",
                        "values": [hash_value],
                        "operator": "eq"
                    }]
                )
                
                formatted = []
                for indicator in indicators:
                    formatted_indicator = {
                        "id": indicator.get("id"),
                        "pattern": indicator.get("pattern"),
                        "indicator_types": indicator.get("indicator_types", []),
                        "confidence": indicator.get("confidence"),
                        "created_at": indicator.get("created_at"),
                        "labels": [label.get("value") for label in indicator.get("objectLabel", [])]
                    }
                    formatted.append(formatted_indicator)
                
                return formatted
            
            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _search_hash
            )
            
            self.logger.info(f"Hash search for {hash_value} returned {len(result)} results")
            return result
            
        except Exception as e:
            self.logger.error(f"Hash search failed: {e}")
            raise
```

**PHASE 2: Professional Analysis Templates (Censys-Inspired)**

**Analysis Templates Module:**
```python
"""
Cooper Cyber Coffee OpenCTI MCP Server - Professional Analysis Templates
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
"""

from typing import Dict, Any

class AnalysisTemplates:
    """Professional analysis templates for structured threat intelligence output"""
    
    @staticmethod
    def executive_briefing_template() -> str:
        return """
Please analyze the provided threat intelligence data and format as an executive briefing:

## Executive Summary
- **Threat Level**: [Critical/High/Medium/Low] based on indicators
- **Key Finding**: One-sentence summary of most important threat
- **Business Impact**: Potential impact to organization operations
- **Immediate Actions Required**: Top 3 specific actions needed

## Threat Landscape Overview
- **Active Campaigns**: Currently observed threat campaigns
- **Attribution Confidence**: Assessment of threat actor attribution
- **Geographic Focus**: Primary regions/sectors being targeted
- **Timeline**: When these threats were first observed

## Strategic Recommendations
1. **Short-term (24-48 hours)**: Immediate protective measures
2. **Medium-term (1-2 weeks)**: Enhanced monitoring and detection
3. **Long-term (1-3 months)**: Strategic security improvements

## Technical Appendix
- **Indicator Summary**: Count and types of IOCs
- **Confidence Levels**: Overall data quality assessment
- **Data Sources**: Primary intelligence sources used

*This analysis was generated using Cooper Cyber Coffee methodology*
"""

    @staticmethod
    def technical_analysis_template() -> str:
        return """
Please provide a detailed technical analysis of the threat intelligence:

## Threat Actor Analysis
- **Primary Attribution**: Most likely threat actor or group
- **Attribution Confidence**: [High/Medium/Low] with reasoning
- **Known TTPs**: Tactics, techniques, and procedures observed
- **Historical Activity**: Previous campaigns and patterns

## Indicator Analysis
- **IOC Breakdown**: Categorize indicators by type and confidence
- **Pattern Recognition**: Common elements across indicators
- **Infrastructure Analysis**: Hosting patterns, registrations, etc.
- **Timeline Correlation**: Temporal relationships between indicators

## Campaign Assessment
- **Campaign Scope**: Scale and targeting of observed activity
- **Victimology**: Industries, regions, or entities targeted
- **Operational Security**: Adversary OPSEC and detection evasion
- **Success Indicators**: Evidence of successful compromises

## Detection and Response
- **Detection Opportunities**: Where these threats can be identified
- **Hunting Queries**: Specific search patterns for threat hunting
- **Mitigation Strategies**: Technical controls to reduce risk
- **Monitoring Recommendations**: Long-term surveillance strategies

*Technical analysis by Cooper Cyber Coffee threat intelligence methodology*
"""

    @staticmethod
    def incident_response_template() -> str:
        return """
Please analyze the threat data for incident response planning:

## Immediate Response Actions
- **Containment**: Steps to prevent spread of identified threats
- **Evidence Preservation**: Critical data to collect and preserve
- **Stakeholder Notification**: Who needs to be informed immediately
- **Resource Requirements**: Personnel and tools needed

## Investigation Priorities
1. **Primary IOCs**: Most critical indicators to investigate first
2. **System Targeting**: Likely systems and assets at risk
3. **Lateral Movement**: Potential paths for threat expansion
4. **Data at Risk**: Information likely targeted by threat actors

## Response Procedures
- **Isolation Criteria**: When to isolate affected systems
- **Forensic Collection**: Evidence collection priorities
- **Communication Plan**: Internal and external communication needs
- **Recovery Planning**: Steps to restore normal operations

## Lessons Learned Integration
- **Detection Gaps**: Where current security controls failed
- **Process Improvements**: Recommended changes to response procedures
- **Training Needs**: Skills development for response team
- **Technology Enhancements**: Security tool improvements needed

*Incident response guidance by Cooper Cyber Coffee methodology*
"""

    @staticmethod
    def trend_analysis_template() -> str:
        return """
Please analyze the threat intelligence data for strategic trends:

## Threat Landscape Trends
- **Emerging Patterns**: New or evolving threat behaviors
- **Threat Actor Evolution**: Changes in adversary capabilities
- **Campaign Trends**: Shifts in targeting or methodology
- **Infrastructure Patterns**: Changes in adversary infrastructure use

## Strategic Implications
- **Industry Impact**: How trends affect specific sectors
- **Geographic Shifts**: Changes in regional threat activity
- **Technology Adaptation**: How threats adapt to new technologies
- **Defensive Effectiveness**: Success/failure of current defenses

## Predictive Insights
- **Future Threat Vectors**: Likely evolution of current threats
- **Preparation Strategies**: Proactive measures for emerging threats
- **Investment Priorities**: Security spending recommendations
- **Capability Development**: Skills and tools needed for future threats

## Strategic Recommendations
- **Policy Updates**: Recommended changes to security policies
- **Architecture Modifications**: Infrastructure security improvements
- **Partnership Opportunities**: External collaboration benefits
- **Research Priorities**: Areas needing additional investigation

*Strategic trend analysis by Cooper Cyber Coffee threat intelligence methodology*
"""
```

**PHASE 3: Enhanced MCP Tools with Templates**

**MCP Tools with Professional Templates:**
```python
"""
Cooper Cyber Coffee OpenCTI MCP Server - MCP Tools Implementation
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
"""

from mcp.types import Tool
from .templates import AnalysisTemplates

def get_mcp_tools():
    """Professional MCP tools with analysis templates"""
    return [
        Tool(
            name="get_recent_indicators_with_analysis",
            description="Get recent indicators from OpenCTI 6.x with professional analysis template guidance",
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 10,
                        "description": "Number of indicators to retrieve"
                    },
                    "indicator_types": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["file-md5", "file-sha1", "file-sha256", "ipv4-addr", "domain-name", "url"]
                        },
                        "description": "Filter by specific indicator types"
                    },
                    "days_back": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 365,
                        "default": 7,
                        "description": "How many days back to search"
                    },
                    "min_confidence": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 100,
                        "default": 50,
                        "description": "Minimum confidence level (0-100)"
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": ["executive", "technical", "incident_response", "trend_analysis"],
                        "default": "executive",
                        "description": "Type of professional analysis template to apply"
                    }
                }
            }
        ),
        Tool(
            name="search_by_hash_with_context",
            description="Search for indicators by hash value with contextual analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "hash": {
                        "type": "string",
                        "pattern": "^[a-fA-F0-9]+$",
                        "description": "Hash value to search for (MD5, SHA1, SHA256)"
                    },
                    "include_context": {
                        "type": "boolean",
                        "default": True,
                        "description": "Include threat context and analysis guidance"
                    }
                },
                "required": ["hash"]
            }
        ),
        Tool(
            name="validate_opencti_connection",
            description="Check OpenCTI connection, version, and data availability with diagnostic information",
            inputSchema={
                "type": "object",
                "properties": {
                    "detailed": {
                        "type": "boolean",
                        "default": False,
                        "description": "Include detailed diagnostic information"
                    }
                }
            }
        ),
        Tool(
            name="get_threat_landscape_summary",
            description="Generate comprehensive threat landscape summary with professional analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "days_back": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 90,
                        "default": 30,
                        "description": "Time period for threat landscape analysis"
                    },
                    "focus_area": {
                        "type": "string",
                        "enum": ["malware", "apt", "infrastructure", "all"],
                        "default": "all",
                        "description": "Focus area for threat analysis"
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["executive", "technical", "both"],
                        "default": "executive",
                        "description": "Analysis output format"
                    }
                }
            }
        )
    ]
```

**Environment Configuration (.env.example):**
```
# Cooper Cyber Coffee OpenCTI MCP Server Configuration
# Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

# OpenCTI 6.x Configuration
OPENCTI_URL=http://localhost:8080
OPENCTI_TOKEN=your_api_token_here
OPENCTI_SSL_VERIFY=false

# MCP Server Configuration
MCP_SERVER_PORT=8000
MCP_SERVER_HOST=0.0.0.0
LOG_LEVEL=INFO

# Performance Configuration
TIMEOUT_SECONDS=30
MAX_INDICATORS_PER_QUERY=1000
ENABLE_QUERY_CACHING=true
CACHE_TTL_SECONDS=300
THREAD_POOL_SIZE=4

# Enterprise Features
ENABLE_HEALTH_CHECKS=true
ENABLE_METRICS=true
ENABLE_AUDIT_LOGGING=true
```

**Key Implementation Requirements:**

**1. MCP Security Best Practices:**
- Validate all incoming messages with Pydantic models
- Use proper MCP error codes (-32700 to -32603)
- Implement secure session handling
- Comprehensive audit logging

**2. Enterprise Professional Features:**
- Professional analysis templates for consistent output
- Docker containerization for easy deployment
- Health check endpoints for monitoring
- Comprehensive error handling and diagnostics

**3. OpenCTI 6.x Specific:**
- Use official pycti client library
- Version validation on startup
- Handle empty databases gracefully
- Proper async patterns with thread pool

**4. Censys-Inspired Enhancements:**
- Analysis templates for consistent professional output
- Natural language optimization for domain-specific queries
- Container-ready deployment for enterprise adoption
- Professional packaging and documentation

**Success Criteria:**
- MCP server starts without errors in both development and Docker
- Connects to OpenCTI 6.x using official pycti client
- All tools work with professional analysis templates
- Handles empty OpenCTI databases gracefully
- Provides structured, professional analysis output
- Enterprise-ready deployment with Docker
- Comprehensive logging and health monitoring
- Professional documentation ready for acquisition discussions

**Next Phase Planning:**
After core functionality with templates works:
- Phase 3: Documentation Agent (comprehensive guides, enterprise deployment docs)
- Phase 4: Testing Agent (MCP Inspector setup, automated testing)
- Phase 5: Performance Agent (advanced caching, optimization, Grafana integration)

Build the core with professional templates and enterprise packaging from day one - this positions us as a serious industry-standard solution ready for acquisition or enterprise adoption.
