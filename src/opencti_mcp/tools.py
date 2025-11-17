"""
Cooper Cyber Coffee OpenCTI MCP Server - MCP Tools Implementation
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

For consulting and enterprise inquiries: business@coopercybercoffee.com
"""

from mcp.types import Tool
from typing import List


def get_mcp_tools() -> List[Tool]:
    """Get all MCP tools with professional analysis template support.

    Returns:
        List of MCP Tool objects with comprehensive schemas

    These tools provide:
    - Recent indicator retrieval with analysis templates
    - Hash-based indicator search
    - OpenCTI connection validation
    - Comprehensive threat landscape summaries
    """
    return [
        Tool(
            name="get_recent_indicators_with_analysis",
            description=(
                "Get recent indicators from OpenCTI 6.x with professional analysis "
                "template guidance. Retrieves indicators and applies executive, technical, "
                "incident response, or trend analysis templates for structured output."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 10,
                        "description": "Number of indicators to retrieve (1-100)"
                    },
                    "indicator_types": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": [
                                "file-md5",
                                "file-sha1",
                                "file-sha256",
                                "ipv4-addr",
                                "ipv6-addr",
                                "domain-name",
                                "url",
                                "email-addr"
                            ]
                        },
                        "description": "Filter by specific indicator types (optional)"
                    },
                    "days_back": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 365,
                        "default": 7,
                        "description": "How many days back to search (1-365)"
                    },
                    "min_confidence": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 100,
                        "default": 50,
                        "description": "Minimum confidence level 0-100 (default: 50)"
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": [
                            "executive",
                            "technical",
                            "incident_response",
                            "trend_analysis"
                        ],
                        "default": "executive",
                        "description": (
                            "Type of professional analysis template to apply:\n"
                            "- executive: Board-ready threat summaries\n"
                            "- technical: Detailed attribution and TTP analysis\n"
                            "- incident_response: Structured response guidance\n"
                            "- trend_analysis: Strategic threat landscape insights"
                        )
                    }
                }
            }
        ),

        Tool(
            name="search_by_hash_with_context",
            description=(
                "Search for indicators by hash value (MD5, SHA1, SHA256) with "
                "contextual analysis. Returns matching indicators and optional "
                "threat context including labels, confidence, and related campaigns."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "hash": {
                        "type": "string",
                        "pattern": "^[a-fA-F0-9]+$",
                        "description": (
                            "Hash value to search for (MD5: 32 chars, "
                            "SHA1: 40 chars, SHA256: 64 chars)"
                        )
                    },
                    "include_context": {
                        "type": "boolean",
                        "default": True,
                        "description": (
                            "Include threat context and analysis guidance "
                            "(labels, confidence, campaigns)"
                        )
                    }
                },
                "required": ["hash"]
            }
        ),

        Tool(
            name="validate_opencti_connection",
            description=(
                "Check OpenCTI connection, version compatibility, and data "
                "availability with diagnostic information. Validates OpenCTI 6.x "
                "setup and reports on database status, active connectors, and "
                "overall system readiness."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "detailed": {
                        "type": "boolean",
                        "default": False,
                        "description": (
                            "Include detailed diagnostic information "
                            "(connector status, database metrics)"
                        )
                    }
                }
            }
        ),

        Tool(
            name="get_threat_landscape_summary",
            description=(
                "Generate comprehensive threat landscape summary with professional "
                "analysis. Aggregates indicators, identifies trends, and produces "
                "executive or technical summaries of the current threat environment "
                "based on OpenCTI data."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "days_back": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 90,
                        "default": 30,
                        "description": "Time period for threat landscape analysis (1-90 days)"
                    },
                    "focus_area": {
                        "type": "string",
                        "enum": ["malware", "apt", "infrastructure", "all"],
                        "default": "all",
                        "description": (
                            "Focus area for threat analysis:\n"
                            "- malware: Malware-specific indicators and campaigns\n"
                            "- apt: Advanced Persistent Threat activity\n"
                            "- infrastructure: Infrastructure patterns and hosting\n"
                            "- all: Comprehensive cross-domain analysis"
                        )
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["executive", "technical", "both"],
                        "default": "executive",
                        "description": (
                            "Analysis output format:\n"
                            "- executive: High-level business-focused summary\n"
                            "- technical: Detailed technical analysis\n"
                            "- both: Combined executive and technical views"
                        )
                    }
                }
            }
        ),

        Tool(
            name="get_attack_patterns",
            description=(
                "Query MITRE ATT&CK techniques and tactics from OpenCTI. Retrieves "
                "attack patterns with descriptions, kill chain phases, and associated "
                "threat intelligence. Access the 452K+ MITRE ATT&CK techniques in your "
                "OpenCTI instance."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 20,
                        "description": "Number of attack patterns to retrieve (1-100)"
                    },
                    "search_term": {
                        "type": "string",
                        "description": (
                            "Optional search term to filter attack patterns "
                            "(e.g., 'phishing', 'lateral movement', 'T1059')"
                        )
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": [
                            "executive",
                            "technical",
                            "incident_response"
                        ],
                        "default": "technical",
                        "description": (
                            "Type of professional analysis template to apply:\n"
                            "- executive: High-level threat summaries\n"
                            "- technical: Detailed TTP analysis\n"
                            "- incident_response: Detection and response guidance"
                        )
                    }
                }
            }
        ),

        Tool(
            name="get_vulnerabilities",
            description=(
                "Query CVEs and vulnerabilities from OpenCTI with severity filtering. "
                "Retrieves vulnerability details including CVE IDs, CVSS scores, "
                "descriptions, and associated threat intelligence. Access CISA KEV "
                "and other vulnerability databases."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 20,
                        "description": "Number of vulnerabilities to retrieve (1-100)"
                    },
                    "search_term": {
                        "type": "string",
                        "description": (
                            "Optional search term to filter vulnerabilities "
                            "(e.g., 'CVE-2024-1234', 'Microsoft', 'remote code execution')"
                        )
                    },
                    "min_severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "none"],
                        "default": "none",
                        "description": (
                            "Minimum severity level to include:\n"
                            "- critical: CVSS 9.0-10.0\n"
                            "- high: CVSS 7.0-8.9\n"
                            "- medium: CVSS 4.0-6.9\n"
                            "- low: CVSS 0.1-3.9\n"
                            "- none: All vulnerabilities"
                        )
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": [
                            "executive",
                            "technical",
                            "incident_response"
                        ],
                        "default": "technical",
                        "description": "Type of professional analysis template to apply"
                    }
                }
            }
        ),

        Tool(
            name="get_malware",
            description=(
                "Query malware families and samples from OpenCTI. Retrieves malware "
                "names, descriptions, capabilities, and associated threat intelligence. "
                "Includes ransomware, trojans, backdoors, and other malware types."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 20,
                        "description": "Number of malware entries to retrieve (1-100)"
                    },
                    "search_term": {
                        "type": "string",
                        "description": (
                            "Optional search term to filter malware "
                            "(e.g., 'ransomware', 'cobalt strike', 'emotet')"
                        )
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": [
                            "executive",
                            "technical",
                            "incident_response"
                        ],
                        "default": "technical",
                        "description": "Type of professional analysis template to apply"
                    }
                }
            }
        ),

        Tool(
            name="search_entities",
            description=(
                "General entity search across all OpenCTI entity types. Search for "
                "threat actors, campaigns, intrusion sets, tools, and more. Flexible "
                "search across the entire OpenCTI knowledge base."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "search_term": {
                        "type": "string",
                        "description": "Search term to find entities (required)"
                    },
                    "entity_types": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": [
                                "Threat-Actor",
                                "Intrusion-Set",
                                "Campaign",
                                "Malware",
                                "Tool",
                                "Attack-Pattern",
                                "Vulnerability",
                                "Indicator",
                                "all"
                            ]
                        },
                        "default": ["all"],
                        "description": (
                            "Entity types to search:\n"
                            "- Threat-Actor: APT groups, cybercrime actors\n"
                            "- Intrusion-Set: Coordinated threat campaigns\n"
                            "- Campaign: Specific attack campaigns\n"
                            "- Malware: Malware families\n"
                            "- Tool: Hacking tools and frameworks\n"
                            "- Attack-Pattern: MITRE ATT&CK techniques\n"
                            "- Vulnerability: CVEs and vulnerabilities\n"
                            "- Indicator: IOCs (hashes, IPs, domains)\n"
                            "- all: Search across all types"
                        )
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 50,
                        "default": 10,
                        "description": "Maximum number of results to return (1-50)"
                    }
                },
                "required": ["search_term"]
            }
        ),

        Tool(
            name="get_threat_actor_ttps",
            description=(
                "Get attack patterns (TTPs) used by a threat actor or intrusion set. "
                "Traverses 'uses' relationships to retrieve MITRE ATT&CK techniques "
                "associated with APT groups and threat actors. Essential for threat "
                "actor profiling and attribution analysis."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "actor_name": {
                        "type": "string",
                        "description": (
                            "Threat actor or intrusion set name (e.g., 'APT29', 'Lazarus Group'). "
                            "Also accepts entity IDs (intrusion-set-- or threat-actor--)"
                        )
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 50,
                        "description": "Maximum number of attack patterns to retrieve (1-100)"
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": [
                            "executive",
                            "technical",
                            "incident_response"
                        ],
                        "default": "technical",
                        "description": "Type of professional analysis template to apply"
                    }
                },
                "required": ["actor_name"]
            }
        ),

        Tool(
            name="get_malware_techniques",
            description=(
                "Get attack patterns used by malware families. Traverses relationships "
                "between malware and MITRE ATT&CK techniques to show TTPs used by "
                "ransomware, trojans, and other malware. Critical for malware analysis "
                "and defensive planning."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "malware_name": {
                        "type": "string",
                        "description": (
                            "Malware name (e.g., 'Emotet', 'Cobalt Strike', 'Ryuk'). "
                            "Also accepts malware IDs (malware--)"
                        )
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 50,
                        "description": "Maximum number of attack patterns to retrieve (1-100)"
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": [
                            "executive",
                            "technical",
                            "incident_response"
                        ],
                        "default": "technical",
                        "description": "Type of professional analysis template to apply"
                    }
                },
                "required": ["malware_name"]
            }
        ),

        Tool(
            name="get_campaign_details",
            description=(
                "Get comprehensive campaign details with full relationship graph. "
                "Retrieves associated threat actors, attack patterns, malware, targets, "
                "and timeline information. Essential for understanding coordinated "
                "threat campaigns and attribution."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "campaign_name": {
                        "type": "string",
                        "description": (
                            "Campaign name (e.g., 'SolarWinds Compromise', 'Operation Aurora'). "
                            "Also accepts campaign IDs (campaign--)"
                        )
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": [
                            "executive",
                            "technical",
                            "incident_response"
                        ],
                        "default": "executive",
                        "description": "Type of professional analysis template to apply"
                    }
                },
                "required": ["campaign_name"]
            }
        ),

        Tool(
            name="get_entity_relationships",
            description=(
                "Get relationships for any entity type. Generic relationship traversal "
                "supporting 'uses', 'targets', 'indicates', 'related-to' and other "
                "relationship types. Flexible tool for exploring the OpenCTI knowledge "
                "graph and understanding entity connections."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "entity_id": {
                        "type": "string",
                        "description": (
                            "Entity ID to query relationships for (e.g., 'threat-actor--abc123', "
                            "'malware--xyz789'). Must be a valid OpenCTI entity ID."
                        )
                    },
                    "relationship_type": {
                        "type": "string",
                        "enum": [
                            "uses",
                            "targets",
                            "indicates",
                            "related-to",
                            "attributed-to",
                            "mitigates",
                            "all"
                        ],
                        "default": "all",
                        "description": (
                            "Filter by relationship type:\n"
                            "- uses: Entity uses another (e.g., actor uses malware)\n"
                            "- targets: Entity targets another (e.g., campaign targets sector)\n"
                            "- indicates: Indicator indicates entity (e.g., IP indicates malware)\n"
                            "- related-to: General relationship\n"
                            "- attributed-to: Attribution relationship\n"
                            "- mitigates: Mitigation relationship\n"
                            "- all: Return all relationship types"
                        )
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "default": 50,
                        "description": "Maximum number of relationships to return (1-100)"
                    }
                },
                "required": ["entity_id"]
            }
        )
    ]


def get_tool_descriptions() -> dict:
    """Get human-readable descriptions of all tools for documentation.

    Returns:
        Dictionary mapping tool names to detailed descriptions

    Example:
        >>> descriptions = get_tool_descriptions()
        >>> print(descriptions['get_recent_indicators_with_analysis'])
    """
    return {
        "get_recent_indicators_with_analysis": (
            "Retrieve recent threat indicators from OpenCTI with professional "
            "analysis templates. Supports filtering by type, confidence, and "
            "timeframe, with output formatted for executive, technical, incident "
            "response, or trend analysis use cases."
        ),
        "search_by_hash_with_context": (
            "Search OpenCTI for specific hash values (MD5, SHA1, SHA256) and "
            "retrieve contextual threat intelligence including confidence scores, "
            "labels, and campaign associations."
        ),
        "validate_opencti_connection": (
            "Validate OpenCTI 6.x connection, check version compatibility, and "
            "assess data availability. Provides diagnostic information for "
            "troubleshooting connection issues."
        ),
        "get_threat_landscape_summary": (
            "Generate comprehensive threat landscape summaries with professional "
            "analysis templates. Aggregates indicators across timeframes and "
            "produces executive or technical views of the threat environment."
        ),
        "get_attack_patterns": (
            "Query MITRE ATT&CK techniques and tactics with optional search "
            "filtering. Retrieves attack patterns with descriptions, kill chain "
            "phases, and professional analysis templates for TTP understanding."
        ),
        "get_vulnerabilities": (
            "Query CVEs and vulnerabilities with severity filtering. Retrieves "
            "vulnerability details including CVSS scores, descriptions, and "
            "associated threat intelligence from CISA KEV and other sources."
        ),
        "get_malware": (
            "Query malware families and samples with optional search filtering. "
            "Retrieves malware names, descriptions, capabilities, and associated "
            "threat intelligence for ransomware, trojans, and other malware types."
        ),
        "search_entities": (
            "General entity search across all OpenCTI entity types. Flexible "
            "search for threat actors, campaigns, intrusion sets, tools, and "
            "more across the entire OpenCTI knowledge base."
        ),
        "get_threat_actor_ttps": (
            "Query attack patterns (TTPs) used by specific threat actors or "
            "intrusion sets. Retrieves MITRE ATT&CK techniques, kill chain phases, "
            "and associated tactics with professional analysis templates. This is "
            "the core relationship query for threat actor attribution."
        ),
        "get_malware_techniques": (
            "Query attack patterns and techniques used by specific malware families. "
            "Retrieves MITRE ATT&CK techniques associated with malware, showing how "
            "the malware operates and what TTPs it implements. Essential for "
            "understanding malware behavior and defensive countermeasures."
        ),
        "get_campaign_details": (
            "Retrieve comprehensive campaign relationship graphs including all "
            "associated entities: threat actors, malware, attack patterns, targets, "
            "and indicators. Provides complete campaign intelligence with timeline "
            "and attribution data for incident response and threat hunting."
        ),
        "get_entity_relationships": (
            "Generic relationship traversal tool for querying relationships between "
            "any OpenCTI entities. Supports filtering by relationship type (uses, "
            "targets, indicates, related-to, etc.) and provides flexible relationship "
            "graph queries for custom threat intelligence research."
        )
    }
