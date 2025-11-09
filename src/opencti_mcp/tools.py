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
        )
    }
