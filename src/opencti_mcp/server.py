"""
Cooper Cyber Coffee OpenCTI MCP Server - Core Server Implementation
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

For consulting and enterprise inquiries: business@coopercybercoffee.com
"""

import asyncio
from typing import Any, Dict
from mcp.server import Server
from mcp.types import (
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)
import structlog

from .opencti_client import OpenCTIClient
from .templates import AnalysisTemplates
from .tools import get_mcp_tools
from .utils import (
    format_error_message,
    validate_hash,
    format_indicator_summary,
    get_version_info
)


class OpenCTIMCPServer:
    """Cooper Cyber Coffee OpenCTI MCP Server.

    Production-ready MCP server for OpenCTI 6.x threat intelligence integration
    with Claude Desktop. Provides professional analysis templates and enterprise
    features for AI-enhanced threat intelligence workflows.

    Features:
    - Professional analysis templates (executive, technical, IR, trend)
    - OpenCTI 6.x integration via official pycti library
    - Comprehensive error handling and logging
    - Health checks and diagnostics
    - Async/await throughout for performance

    Args:
        config: Configuration dictionary from utils.load_config()

    Example:
        >>> config = load_config()
        >>> server = OpenCTIMCPServer(config)
        >>> await server.run()
    """

    def __init__(self, config: Dict[str, Any]):
        """Initialize the MCP server with configuration."""
        self.config = config
        self.logger = structlog.get_logger()
        self.server = Server("opencti-mcp-server")

        # Initialize OpenCTI client
        self.opencti_client = OpenCTIClient(
            url=config["opencti_url"],
            token=config["opencti_token"],
            ssl_verify=config["opencti_ssl_verify"]
        )

        # Register handlers
        self._register_handlers()

        self.logger.info(
            "server_initialized",
            version=get_version_info()["version"],
            opencti_url=config["opencti_url"]
        )

    def _register_handlers(self):
        """Register MCP protocol handlers."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List all available MCP tools."""
            tools = get_mcp_tools()
            self.logger.debug("tools_listed", count=len(tools))
            return tools

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> list[TextContent]:
            """Handle tool execution requests."""
            self.logger.info("tool_called", tool=name, args=arguments)

            try:
                if name == "get_recent_indicators_with_analysis":
                    return await self._handle_get_recent_indicators(arguments)

                elif name == "search_by_hash_with_context":
                    return await self._handle_search_by_hash(arguments)

                elif name == "validate_opencti_connection":
                    return await self._handle_validate_connection(arguments)

                elif name == "get_threat_landscape_summary":
                    return await self._handle_threat_landscape_summary(arguments)

                elif name == "get_attack_patterns":
                    return await self._handle_get_attack_patterns(arguments)

                elif name == "get_vulnerabilities":
                    return await self._handle_get_vulnerabilities(arguments)

                elif name == "get_malware":
                    return await self._handle_get_malware(arguments)

                elif name == "search_entities":
                    return await self._handle_search_entities(arguments)

                elif name == "get_threat_actor_ttps":
                    return await self._handle_get_threat_actor_ttps(arguments)

                elif name == "get_malware_techniques":
                    return await self._handle_get_malware_techniques(arguments)

                elif name == "get_campaign_details":
                    return await self._handle_get_campaign_details(arguments)

                elif name == "get_entity_relationships":
                    return await self._handle_get_entity_relationships(arguments)

                else:
                    error_msg = f"Unknown tool: {name}"
                    self.logger.error("unknown_tool", tool=name)
                    return [TextContent(type="text", text=error_msg)]

            except Exception as e:
                error_msg = format_error_message(e, f"tool execution ({name})")
                self.logger.error(
                    "tool_execution_failed",
                    tool=name,
                    error=str(e),
                    error_type=type(e).__name__
                )
                return [TextContent(
                    type="text",
                    text=f"❌ Error: {error_msg}\n\n"
                         f"Please check your OpenCTI connection and try again."
                )]

    async def _handle_get_recent_indicators(self, args: dict) -> list[TextContent]:
        """Handle get_recent_indicators_with_analysis tool.

        Args:
            args: Tool arguments including limit, types, confidence, analysis_type

        Returns:
            List containing TextContent with formatted indicator analysis
        """
        limit = args.get("limit", 10)
        indicator_types = args.get("indicator_types")
        days_back = args.get("days_back", 7)
        min_confidence = args.get("min_confidence", 50)
        analysis_type = args.get("analysis_type", "executive")

        self.logger.info(
            "fetching_indicators",
            limit=limit,
            types=indicator_types,
            days_back=days_back,
            min_confidence=min_confidence,
            analysis_type=analysis_type
        )

        # Fetch indicators from OpenCTI
        indicators = await self.opencti_client.get_recent_indicators(
            limit=limit,
            indicator_types=indicator_types,
            days_back=days_back,
            min_confidence=min_confidence
        )

        if not indicators:
            return [TextContent(
                type="text",
                text=(
                    "ℹ️ No indicators found matching your criteria.\n\n"
                    "**Suggestions:**\n"
                    "- Reduce the minimum confidence threshold\n"
                    "- Increase the days_back timeframe\n"
                    "- Remove indicator type filters\n"
                    "- Check if your OpenCTI instance has data ingested\n\n"
                    "*If this is a new OpenCTI instance, configure connectors "
                    "to import threat intelligence data.*"
                )
            )]

        # Generate summary statistics
        summary = format_indicator_summary(indicators)

        # Format with analysis template
        formatted_output = AnalysisTemplates.format_indicator_data(
            indicators,
            analysis_type
        )

        # Add summary header
        header = (
            f"# OpenCTI Threat Intelligence Analysis\n\n"
            f"**Analysis Type:** {analysis_type.replace('_', ' ').title()}\n"
            f"**Indicators Retrieved:** {summary['total_count']}\n"
            f"**Average Confidence:** {summary['avg_confidence']}%\n"
            f"**High Confidence (≥75%):** {summary['high_confidence_count']} "
            f"({summary['high_confidence_percentage']}%)\n\n"
            f"**Indicator Types:**\n"
        )

        for ioc_type, count in summary['types'].items():
            header += f"- {ioc_type}: {count}\n"

        header += "\n---\n\n"

        final_output = header + formatted_output

        self.logger.info(
            "indicators_retrieved",
            count=len(indicators),
            avg_confidence=summary['avg_confidence']
        )

        return [TextContent(type="text", text=final_output)]

    async def _handle_search_by_hash(self, args: dict) -> list[TextContent]:
        """Handle search_by_hash_with_context tool.

        Args:
            args: Tool arguments including hash value and context flag

        Returns:
            List containing TextContent with search results
        """
        hash_value = args.get("hash", "").strip()
        include_context = args.get("include_context", True)

        # Validate hash
        hash_type = validate_hash(hash_value)
        if not hash_type:
            return [TextContent(
                type="text",
                text=(
                    f"❌ Invalid hash format: `{hash_value}`\n\n"
                    "**Expected formats:**\n"
                    "- MD5: 32 hexadecimal characters\n"
                    "- SHA1: 40 hexadecimal characters\n"
                    "- SHA256: 64 hexadecimal characters\n\n"
                    "**Example:** `44d88612fea8a8f36de82e1278abb02f` (MD5)"
                )
            )]

        self.logger.info("searching_hash", hash=hash_value, hash_type=hash_type)

        # Search OpenCTI
        results = await self.opencti_client.search_by_hash(hash_value)

        if not results:
            return [TextContent(
                type="text",
                text=(
                    f"# Hash Search Results\n\n"
                    f"**Hash:** `{hash_value}`\n"
                    f"**Type:** {hash_type.upper()}\n"
                    f"**Status:** ✅ Not found in threat intelligence database\n\n"
                    "This hash is not currently identified as malicious in your "
                    "OpenCTI instance. However, this does not guarantee the file "
                    "is safe. Consider:\n\n"
                    "1. Checking other threat intelligence sources\n"
                    "2. Performing dynamic analysis in a sandbox\n"
                    "3. Scanning with multiple AV engines\n"
                    "4. Reviewing file metadata and behavior\n\n"
                    "*Results reflect data available in your OpenCTI instance only.*"
                )
            )]

        # Format results
        output = (
            f"# Hash Search Results\n\n"
            f"**Hash:** `{hash_value}`\n"
            f"**Type:** {hash_type.upper()}\n"
            f"**Status:** ⚠️ Found in threat intelligence database\n"
            f"**Matches:** {len(results)}\n\n"
            "---\n\n"
        )

        for idx, result in enumerate(results, 1):
            output += f"## Match {idx}\n\n"
            output += f"- **Pattern:** `{result.get('pattern', 'N/A')}`\n"
            output += f"- **Types:** {', '.join(result.get('indicator_types', ['unknown']))}\n"
            output += f"- **Confidence:** {result.get('confidence', 0)}%\n"
            output += f"- **Created:** {result.get('created_at', 'N/A')}\n"

            if include_context:
                labels = result.get('labels', [])
                if labels:
                    output += f"- **Labels:** {', '.join(labels)}\n"

            output += "\n"

        output += (
            "\n**Recommended Actions:**\n"
            "1. Block this hash at network perimeter and endpoints\n"
            "2. Search for this hash in your environment\n"
            "3. Review associated indicators and campaigns\n"
            "4. Update detection signatures\n"
        )

        self.logger.info("hash_search_complete", matches=len(results))

        return [TextContent(type="text", text=output)]

    async def _handle_validate_connection(self, args: dict) -> list[TextContent]:
        """Handle validate_opencti_connection tool.

        Args:
            args: Tool arguments including detailed flag

        Returns:
            List containing TextContent with validation results
        """
        detailed = args.get("detailed", False)

        self.logger.info("validating_connection", detailed=detailed)

        try:
            validation = await self.opencti_client.validate_opencti_setup()

            output = (
                f"# OpenCTI Connection Validation\n\n"
                f"**Status:** ✅ Connected\n"
                f"**URL:** {self.config['opencti_url']}\n"
                f"**Version:** {validation['version']}\n"
                f"**Database Status:** {validation['status']}\n"
                f"**Active Connectors:** {validation['active_connectors']}\n\n"
            )

            if validation['status'] == 'empty_database':
                output += (
                    "⚠️ **Warning:** Your OpenCTI database appears to be empty.\n\n"
                    "**Next Steps:**\n"
                    "1. Configure threat intelligence connectors in OpenCTI\n"
                    "2. Import initial threat intelligence feeds\n"
                    "3. Wait for data synchronization to complete\n"
                    "4. Re-run this validation\n\n"
                )

            if detailed and validation['connector_names']:
                output += "**Active Connectors:**\n"
                for connector in validation['connector_names']:
                    output += f"- {connector}\n"
                output += "\n"

            output += (
                "**Cooper Cyber Coffee MCP Server:**\n"
                f"- Version: {get_version_info()['version']}\n"
                f"- Ready for Claude Desktop integration ✅\n"
            )

            self.logger.info("validation_successful", version=validation['version'])

            return [TextContent(type="text", text=output)]

        except Exception as e:
            error_msg = format_error_message(e, "connection validation")
            self.logger.error("validation_failed", error=str(e))

            output = (
                f"# OpenCTI Connection Validation\n\n"
                f"**Status:** ❌ Failed\n"
                f"**Error:** {error_msg}\n\n"
                "**Troubleshooting Steps:**\n"
                "1. Verify OPENCTI_URL is correct in .env\n"
                "2. Verify OPENCTI_TOKEN is valid (Settings > API Access)\n"
                "3. Check OpenCTI is running and accessible\n"
                "4. Review firewall and network settings\n"
                "5. Check OpenCTI logs for errors\n\n"
                "**Configuration:**\n"
                f"- URL: {self.config['opencti_url']}\n"
                f"- SSL Verify: {self.config['opencti_ssl_verify']}\n"
            )

            return [TextContent(type="text", text=output)]

    async def _handle_threat_landscape_summary(self, args: dict) -> list[TextContent]:
        """Handle get_threat_landscape_summary tool.

        Args:
            args: Tool arguments including days_back, focus_area, output_format

        Returns:
            List containing TextContent with threat landscape analysis
        """
        days_back = args.get("days_back", 30)
        focus_area = args.get("focus_area", "all")
        output_format = args.get("output_format", "executive")

        self.logger.info(
            "generating_threat_landscape",
            days_back=days_back,
            focus_area=focus_area,
            output_format=output_format
        )

        # Fetch comprehensive indicator set
        indicator_types = None
        if focus_area == "malware":
            indicator_types = ["file-md5", "file-sha1", "file-sha256"]
        elif focus_area == "infrastructure":
            indicator_types = ["ipv4-addr", "ipv6-addr", "domain-name", "url"]

        indicators = await self.opencti_client.get_recent_indicators(
            limit=100,
            indicator_types=indicator_types,
            days_back=days_back,
            min_confidence=0  # Get all to analyze trends
        )

        if not indicators:
            return [TextContent(
                type="text",
                text=(
                    f"# Threat Landscape Summary\n\n"
                    f"**Period:** Last {days_back} days\n"
                    f"**Focus:** {focus_area}\n\n"
                    "ℹ️ No indicators found in this timeframe.\n\n"
                    "**Possible reasons:**\n"
                    "- OpenCTI database is empty or newly deployed\n"
                    "- Connectors are not configured\n"
                    "- No activity in selected timeframe\n"
                )
            )]

        # Generate summary
        summary = format_indicator_summary(indicators)

        # Determine analysis template
        analysis_type = "executive" if output_format in ["executive", "both"] else "technical"

        formatted_output = AnalysisTemplates.format_indicator_data(
            indicators[:20],  # Limit to top 20 for summary
            analysis_type
        )

        header = (
            f"# Threat Landscape Summary\n\n"
            f"**Period:** Last {days_back} days\n"
            f"**Focus Area:** {focus_area.upper()}\n"
            f"**Total Indicators:** {summary['total_count']}\n"
            f"**Average Confidence:** {summary['avg_confidence']}%\n"
            f"**High Confidence Indicators:** {summary['high_confidence_count']} "
            f"({summary['high_confidence_percentage']}%)\n\n"
            "**Indicator Distribution:**\n"
        )

        for ioc_type, count in sorted(summary['types'].items(), key=lambda x: x[1], reverse=True):
            percentage = round((count / summary['total_count'] * 100), 1)
            header += f"- {ioc_type}: {count} ({percentage}%)\n"

        header += "\n---\n\n"

        final_output = header + formatted_output

        # Add technical view if requested
        if output_format == "both":
            tech_output = AnalysisTemplates.format_indicator_data(
                indicators[:20],
                "technical"
            )
            final_output += "\n\n---\n\n# Technical Analysis\n\n" + tech_output

        self.logger.info(
            "threat_landscape_generated",
            indicators=summary['total_count'],
            avg_confidence=summary['avg_confidence']
        )

        return [TextContent(type="text", text=final_output)]

    async def _handle_get_attack_patterns(self, args: dict) -> list[TextContent]:
        """Handle get_attack_patterns tool.

        Args:
            args: Tool arguments including limit, search_term, analysis_type

        Returns:
            List containing TextContent with formatted attack pattern analysis
        """
        limit = args.get("limit", 20)
        search_term = args.get("search_term")
        analysis_type = args.get("analysis_type", "technical")

        self.logger.info(
            "fetching_attack_patterns",
            limit=limit,
            search_term=search_term,
            analysis_type=analysis_type
        )

        # Fetch attack patterns from OpenCTI
        patterns = await self.opencti_client.get_attack_patterns(
            limit=limit,
            search_term=search_term
        )

        if not patterns:
            search_info = f" matching '{search_term}'" if search_term else ""
            return [TextContent(
                type="text",
                text=(
                    f"ℹ️ No attack patterns found{search_info}.\n\n"
                    "**Suggestions:**\n"
                    "- Try a different search term\n"
                    "- Remove search filters\n"
                    "- Check if MITRE ATT&CK data is imported in OpenCTI\n"
                )
            )]

        # Format output
        output = (
            f"# MITRE ATT&CK Techniques & Tactics\n\n"
            f"**Total Patterns:** {len(patterns)}\n"
        )

        if search_term:
            output += f"**Search Term:** {search_term}\n"

        output += "\n---\n\n"

        for idx, pattern in enumerate(patterns, 1):
            output += f"## {idx}. {pattern.get('name', 'Unknown')}\n\n"

            if pattern.get('x_mitre_id'):
                output += f"- **MITRE ID:** {pattern['x_mitre_id']}\n"

            output += f"- **Description:** {pattern.get('description', 'No description')[:500]}...\n"

            kill_chain = pattern.get('kill_chain_phases', [])
            if kill_chain:
                output += f"- **Kill Chain Phases:** {', '.join(kill_chain)}\n"

            labels = pattern.get('labels', [])
            if labels:
                output += f"- **Labels:** {', '.join(labels[:5])}\n"

            output += "\n"

        # Add analysis template guidance
        template = AnalysisTemplates.get_template(analysis_type)
        output += "\n---\n\n" + template

        self.logger.info("attack_patterns_retrieved", count=len(patterns))

        return [TextContent(type="text", text=output)]

    async def _handle_get_vulnerabilities(self, args: dict) -> list[TextContent]:
        """Handle get_vulnerabilities tool.

        Args:
            args: Tool arguments including limit, search_term, min_severity, analysis_type

        Returns:
            List containing TextContent with formatted vulnerability analysis
        """
        limit = args.get("limit", 20)
        search_term = args.get("search_term")
        min_severity = args.get("min_severity", "none")
        analysis_type = args.get("analysis_type", "technical")

        self.logger.info(
            "fetching_vulnerabilities",
            limit=limit,
            search_term=search_term,
            min_severity=min_severity,
            analysis_type=analysis_type
        )

        # Fetch vulnerabilities from OpenCTI
        vulns = await self.opencti_client.get_vulnerabilities(
            limit=limit,
            search_term=search_term,
            min_severity=min_severity if min_severity != "none" else None
        )

        if not vulns:
            search_info = f" matching '{search_term}'" if search_term else ""
            severity_info = f" with severity >= {min_severity}" if min_severity != "none" else ""
            return [TextContent(
                type="text",
                text=(
                    f"ℹ️ No vulnerabilities found{search_info}{severity_info}.\n\n"
                    "**Suggestions:**\n"
                    "- Try a different search term\n"
                    "- Adjust severity filter\n"
                    "- Check if CVE data is imported in OpenCTI\n"
                )
            )]

        # Calculate severity distribution
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        for vuln in vulns:
            severity_counts[vuln.get("severity", "Unknown")] += 1

        # Format output
        output = (
            f"# CVEs & Vulnerabilities\n\n"
            f"**Total Vulnerabilities:** {len(vulns)}\n"
        )

        if search_term:
            output += f"**Search Term:** {search_term}\n"

        if min_severity != "none":
            output += f"**Minimum Severity:** {min_severity.title()}\n"

        output += "\n**Severity Distribution:**\n"
        for severity, count in severity_counts.items():
            if count > 0:
                output += f"- {severity}: {count}\n"

        output += "\n---\n\n"

        for idx, vuln in enumerate(vulns, 1):
            output += f"## {idx}. {vuln.get('name', 'Unknown')}\n\n"

            cvss_score = vuln.get('cvss_score', 0)
            severity = vuln.get('severity', 'Unknown')

            if cvss_score > 0:
                output += f"- **CVSS Score:** {cvss_score} ({severity})\n"

            output += f"- **Description:** {vuln.get('description', 'No description')}\n"

            labels = vuln.get('labels', [])
            if labels:
                output += f"- **Labels:** {', '.join(labels[:5])}\n"

            output += "\n"

        # Add analysis template guidance
        template = AnalysisTemplates.get_template(analysis_type)
        output += "\n---\n\n" + template

        self.logger.info("vulnerabilities_retrieved", count=len(vulns))

        return [TextContent(type="text", text=output)]

    async def _handle_get_malware(self, args: dict) -> list[TextContent]:
        """Handle get_malware tool.

        Args:
            args: Tool arguments including limit, search_term, analysis_type

        Returns:
            List containing TextContent with formatted malware analysis
        """
        limit = args.get("limit", 20)
        search_term = args.get("search_term")
        analysis_type = args.get("analysis_type", "technical")

        self.logger.info(
            "fetching_malware",
            limit=limit,
            search_term=search_term,
            analysis_type=analysis_type
        )

        # Fetch malware from OpenCTI
        malware_list = await self.opencti_client.get_malware(
            limit=limit,
            search_term=search_term
        )

        if not malware_list:
            search_info = f" matching '{search_term}'" if search_term else ""
            return [TextContent(
                type="text",
                text=(
                    f"ℹ️ No malware found{search_info}.\n\n"
                    "**Suggestions:**\n"
                    "- Try a different search term\n"
                    "- Remove search filters\n"
                    "- Check if malware data is imported in OpenCTI\n"
                )
            )]

        # Count malware types
        type_counts = {}
        for malware in malware_list:
            for mtype in malware.get('malware_types', ['unknown']):
                type_counts[mtype] = type_counts.get(mtype, 0) + 1

        # Format output
        output = (
            f"# Malware Families & Samples\n\n"
            f"**Total Entries:** {len(malware_list)}\n"
        )

        if search_term:
            output += f"**Search Term:** {search_term}\n"

        output += "\n**Malware Types:**\n"
        for mtype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            output += f"- {mtype}: {count}\n"

        output += "\n---\n\n"

        for idx, malware in enumerate(malware_list, 1):
            output += f"## {idx}. {malware.get('name', 'Unknown')}\n\n"

            if malware.get('is_family'):
                output += "- **Type:** Malware Family\n"

            mtypes = malware.get('malware_types', [])
            if mtypes:
                output += f"- **Malware Types:** {', '.join(mtypes)}\n"

            output += f"- **Description:** {malware.get('description', 'No description')}\n"

            labels = malware.get('labels', [])
            if labels:
                output += f"- **Labels:** {', '.join(labels[:5])}\n"

            output += "\n"

        # Add analysis template guidance
        template = AnalysisTemplates.get_template(analysis_type)
        output += "\n---\n\n" + template

        self.logger.info("malware_retrieved", count=len(malware_list))

        return [TextContent(type="text", text=output)]

    async def _handle_search_entities(self, args: dict) -> list[TextContent]:
        """Handle search_entities tool.

        Args:
            args: Tool arguments including search_term, entity_types, limit

        Returns:
            List containing TextContent with formatted entity search results
        """
        search_term = args.get("search_term", "")
        entity_types = args.get("entity_types", ["all"])
        limit = args.get("limit", 10)

        if not search_term:
            return [TextContent(
                type="text",
                text="❌ Error: search_term is required for entity search"
            )]

        self.logger.info(
            "searching_entities",
            search_term=search_term,
            entity_types=entity_types,
            limit=limit
        )

        # Search entities
        results = await self.opencti_client.search_entities(
            search_term=search_term,
            entity_types=entity_types,
            limit=limit
        )

        if not results:
            return [TextContent(
                type="text",
                text=(
                    f"ℹ️ No entities found matching '{search_term}'.\n\n"
                    "**Suggestions:**\n"
                    "- Try different search terms\n"
                    "- Use more general keywords\n"
                    "- Check if data is imported for the entity types you're searching\n"
                )
            )]

        # Count by entity type
        type_counts = {}
        for entity in results:
            etype = entity.get('entity_type', 'Unknown')
            type_counts[etype] = type_counts.get(etype, 0) + 1

        # Format output
        output = (
            f"# Entity Search Results\n\n"
            f"**Search Term:** {search_term}\n"
            f"**Total Results:** {len(results)}\n\n"
            "**Entity Types:**\n"
        )

        for etype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            output += f"- {etype}: {count}\n"

        output += "\n---\n\n"

        for idx, entity in enumerate(results, 1):
            output += f"## {idx}. {entity.get('name', 'Unknown')}\n\n"
            output += f"- **Entity Type:** {entity.get('entity_type', 'Unknown')}\n"
            output += f"- **Description:** {entity.get('description', 'No description')}\n"

            labels = entity.get('labels', [])
            if labels:
                output += f"- **Labels:** {', '.join(labels[:5])}\n"

            output += "\n"

        self.logger.info("entity_search_complete", results=len(results))

        return [TextContent(type="text", text=output)]

    async def _handle_get_threat_actor_ttps(self, args: dict) -> list[TextContent]:
        """Handle get_threat_actor_ttps tool.

        Args:
            args: Tool arguments including actor_name, limit, analysis_type

        Returns:
            List containing TextContent with formatted TTP analysis
        """
        actor_name = args.get("actor_name", "")
        limit = args.get("limit", 50)
        analysis_type = args.get("analysis_type", "technical")

        if not actor_name:
            return [TextContent(
                type="text",
                text="❌ Error: actor_name is required"
            )]

        self.logger.info(
            "fetching_actor_ttps",
            actor_name=actor_name,
            limit=limit,
            analysis_type=analysis_type
        )

        # Fetch TTPs from OpenCTI
        result = await self.opencti_client.get_threat_actor_ttps(
            actor_name=actor_name,
            limit=limit
        )

        if not result or not result.get("attack_patterns"):
            return [TextContent(
                type="text",
                text=(
                    f"ℹ️ No threat actor found matching '{actor_name}' or no TTPs associated.\n\n"
                    "**Suggestions:**\n"
                    "- Try a different actor name or alias\n"
                    "- Search for the actor first using search_entities\n"
                    "- Check if threat actor data is imported in OpenCTI\n"
                )
            )]

        attack_patterns = result["attack_patterns"]

        # Group by kill chain phase
        by_phase = {}
        for pattern in attack_patterns:
            phases = pattern.get("kill_chain_phases", ["unknown"])
            for phase in phases:
                if phase not in by_phase:
                    by_phase[phase] = []
                by_phase[phase].append(pattern)

        # Format output
        output = (
            f"# Threat Actor TTPs\n\n"
            f"**Threat Actor:** {result.get('actor_name', actor_name)}\n"
            f"**Total TTPs:** {len(attack_patterns)}\n\n"
            "**Kill Chain Distribution:**\n"
        )

        for phase, patterns in sorted(by_phase.items()):
            output += f"- {phase}: {len(patterns)} techniques\n"

        output += "\n---\n\n"

        # Group output by kill chain phase
        for phase in sorted(by_phase.keys()):
            output += f"## {phase.upper()}\n\n"

            for pattern in by_phase[phase]:
                output += f"### {pattern.get('name', 'Unknown')}\n\n"

                if pattern.get('x_mitre_id'):
                    output += f"- **MITRE ID:** {pattern['x_mitre_id']}\n"

                desc = pattern.get('description', 'No description')
                output += f"- **Description:** {desc[:300]}...\n"

                labels = pattern.get('labels', [])
                if labels:
                    output += f"- **Labels:** {', '.join(labels[:3])}\n"

                output += "\n"

        # Add analysis template guidance
        template = AnalysisTemplates.get_template(analysis_type)
        output += "\n---\n\n" + template

        self.logger.info("actor_ttps_retrieved", count=len(attack_patterns))

        return [TextContent(type="text", text=output)]

    async def _handle_get_malware_techniques(self, args: dict) -> list[TextContent]:
        """Handle get_malware_techniques tool.

        Args:
            args: Tool arguments including malware_name, limit, analysis_type

        Returns:
            List containing TextContent with formatted malware technique analysis
        """
        malware_name = args.get("malware_name", "")
        limit = args.get("limit", 50)
        analysis_type = args.get("analysis_type", "technical")

        if not malware_name:
            return [TextContent(
                type="text",
                text="❌ Error: malware_name is required"
            )]

        self.logger.info(
            "fetching_malware_techniques",
            malware_name=malware_name,
            limit=limit,
            analysis_type=analysis_type
        )

        # Fetch techniques from OpenCTI
        result = await self.opencti_client.get_malware_techniques(
            malware_name=malware_name,
            limit=limit
        )

        if not result or not result.get("attack_patterns"):
            return [TextContent(
                type="text",
                text=(
                    f"ℹ️ No malware found matching '{malware_name}' or no techniques associated.\n\n"
                    "**Suggestions:**\n"
                    "- Try a different malware name or variant\n"
                    "- Search for the malware first using get_malware\n"
                    "- Check if malware technique mappings are imported in OpenCTI\n"
                )
            )]

        attack_patterns = result["attack_patterns"]

        # Group by kill chain phase
        by_phase = {}
        for pattern in attack_patterns:
            phases = pattern.get("kill_chain_phases", ["unknown"])
            for phase in phases:
                if phase not in by_phase:
                    by_phase[phase] = []
                by_phase[phase].append(pattern)

        # Format output
        output = (
            f"# Malware Techniques\n\n"
            f"**Malware:** {result.get('malware_name', malware_name)}\n"
            f"**Total Techniques:** {len(attack_patterns)}\n\n"
        )

        if result.get("malware_types"):
            output += f"**Malware Types:** {', '.join(result['malware_types'])}\n\n"

        output += "**Kill Chain Distribution:**\n"
        for phase, patterns in sorted(by_phase.items()):
            output += f"- {phase}: {len(patterns)} techniques\n"

        output += "\n---\n\n"

        # Group output by kill chain phase
        for phase in sorted(by_phase.keys()):
            output += f"## {phase.upper()}\n\n"

            for pattern in by_phase[phase]:
                output += f"### {pattern.get('name', 'Unknown')}\n\n"

                if pattern.get('x_mitre_id'):
                    output += f"- **MITRE ID:** {pattern['x_mitre_id']}\n"

                desc = pattern.get('description', 'No description')
                output += f"- **Description:** {desc[:300]}...\n"

                output += "\n"

        # Add analysis template guidance
        template = AnalysisTemplates.get_template(analysis_type)
        output += "\n---\n\n" + template

        self.logger.info("malware_techniques_retrieved", count=len(attack_patterns))

        return [TextContent(type="text", text=output)]

    async def _handle_get_campaign_details(self, args: dict) -> list[TextContent]:
        """Handle get_campaign_details tool.

        Args:
            args: Tool arguments including campaign_name, analysis_type

        Returns:
            List containing TextContent with formatted campaign analysis
        """
        campaign_name = args.get("campaign_name", "")
        analysis_type = args.get("analysis_type", "executive")

        if not campaign_name:
            return [TextContent(
                type="text",
                text="❌ Error: campaign_name is required"
            )]

        self.logger.info(
            "fetching_campaign_details",
            campaign_name=campaign_name,
            analysis_type=analysis_type
        )

        # Fetch campaign details from OpenCTI
        result = await self.opencti_client.get_campaign_details(
            campaign_name=campaign_name
        )

        if not result:
            return [TextContent(
                type="text",
                text=(
                    f"ℹ️ No campaign found matching '{campaign_name}'.\n\n"
                    "**Suggestions:**\n"
                    "- Try a different campaign name\n"
                    "- Search for campaigns first using search_entities with entity_types=['Campaign']\n"
                    "- Check if campaign data is imported in OpenCTI\n"
                )
            )]

        # Format output
        output = (
            f"# Campaign Intelligence Report\n\n"
            f"**Campaign:** {result.get('name', campaign_name)}\n"
        )

        if result.get('description'):
            output += f"\n**Description:**\n{result['description']}\n"

        if result.get('first_seen') or result.get('last_seen'):
            output += "\n**Timeline:**\n"
            if result.get('first_seen'):
                output += f"- First Seen: {result['first_seen']}\n"
            if result.get('last_seen'):
                output += f"- Last Seen: {result['last_seen']}\n"

        output += "\n---\n\n"

        # Threat Actors
        threat_actors = result.get("threat_actors", [])
        if threat_actors:
            output += f"## Attribution ({len(threat_actors)} threat actors)\n\n"
            for actor in threat_actors:
                output += f"- **{actor.get('name', 'Unknown')}**"
                if actor.get('description'):
                    output += f": {actor['description'][:200]}..."
                output += "\n"
            output += "\n"

        # Attack Patterns
        attack_patterns = result.get("attack_patterns", [])
        if attack_patterns:
            output += f"## TTPs ({len(attack_patterns)} techniques)\n\n"
            by_phase = {}
            for pattern in attack_patterns:
                phases = pattern.get("kill_chain_phases", ["unknown"])
                for phase in phases:
                    if phase not in by_phase:
                        by_phase[phase] = []
                    if pattern not in by_phase[phase]:
                        by_phase[phase].append(pattern)

            for phase, patterns in sorted(by_phase.items()):
                output += f"### {phase.upper()}\n"
                for pattern in patterns:
                    mitre_id = pattern.get('x_mitre_id', '')
                    output += f"- {pattern.get('name', 'Unknown')}"
                    if mitre_id:
                        output += f" ({mitre_id})"
                    output += "\n"
                output += "\n"

        # Malware
        malware = result.get("malware", [])
        if malware:
            output += f"## Malware ({len(malware)} families/samples)\n\n"
            for m in malware:
                output += f"- **{m.get('name', 'Unknown')}**"
                mtypes = m.get('malware_types', [])
                if mtypes:
                    output += f" ({', '.join(mtypes)})"
                output += "\n"
            output += "\n"

        # Indicators
        indicators = result.get("indicators", [])
        if indicators:
            output += f"## Indicators ({len(indicators)} IOCs)\n\n"
            type_counts = {}
            for indicator in indicators:
                for ioc_type in indicator.get('indicator_types', ['unknown']):
                    type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1

            for ioc_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                output += f"- {ioc_type}: {count}\n"
            output += "\n"

        # Add analysis template guidance
        template = AnalysisTemplates.get_template(analysis_type)
        output += "\n---\n\n" + template

        self.logger.info("campaign_details_retrieved", campaign=result.get('name'))

        return [TextContent(type="text", text=output)]

    async def _handle_get_entity_relationships(self, args: dict) -> list[TextContent]:
        """Handle get_entity_relationships tool.

        Args:
            args: Tool arguments including entity_id, relationship_types, limit

        Returns:
            List containing TextContent with formatted relationship graph
        """
        entity_id = args.get("entity_id", "")
        relationship_types = args.get("relationship_types", ["all"])
        limit = args.get("limit", 50)

        if not entity_id:
            return [TextContent(
                type="text",
                text="❌ Error: entity_id is required"
            )]

        self.logger.info(
            "fetching_entity_relationships",
            entity_id=entity_id,
            relationship_types=relationship_types,
            limit=limit
        )

        # Fetch relationships from OpenCTI
        result = await self.opencti_client.get_entity_relationships(
            entity_id=entity_id,
            relationship_types=relationship_types,
            limit=limit
        )

        if not result:
            return [TextContent(
                type="text",
                text=(
                    f"ℹ️ No entity found with ID '{entity_id}' or no relationships found.\n\n"
                    "**Suggestions:**\n"
                    "- Verify the entity ID is correct\n"
                    "- Try searching for the entity first to get its ID\n"
                    "- Adjust relationship type filters\n"
                )
            )]

        relationships = result.get("relationships", [])

        if not relationships:
            return [TextContent(
                type="text",
                text=(
                    f"# Entity Relationships\n\n"
                    f"**Entity:** {result.get('entity_name', 'Unknown')} ({result.get('entity_type', 'Unknown')})\n\n"
                    "ℹ️ No relationships found for this entity.\n"
                )
            )]

        # Group by relationship type
        by_type = {}
        for rel in relationships:
            rel_type = rel.get("relationship_type", "unknown")
            if rel_type not in by_type:
                by_type[rel_type] = []
            by_type[rel_type].append(rel)

        # Format output
        output = (
            f"# Entity Relationships\n\n"
            f"**Entity:** {result.get('entity_name', 'Unknown')}\n"
            f"**Entity Type:** {result.get('entity_type', 'Unknown')}\n"
            f"**Total Relationships:** {len(relationships)}\n\n"
            "**Relationship Types:**\n"
        )

        for rel_type, rels in sorted(by_type.items()):
            output += f"- {rel_type}: {len(rels)}\n"

        output += "\n---\n\n"

        # Group output by relationship type
        for rel_type in sorted(by_type.keys()):
            output += f"## {rel_type.upper()}\n\n"

            for rel in by_type[rel_type]:
                target = rel.get("target", {})
                output += f"- **{target.get('name', 'Unknown')}** ({target.get('entity_type', 'Unknown')})"

                if target.get('description'):
                    output += f"\n  {target['description'][:150]}..."

                output += "\n\n"

        self.logger.info("entity_relationships_retrieved", count=len(relationships))

        return [TextContent(type="text", text=output)]

    async def run(self):
        """Run the MCP server.

        Starts the server and handles graceful shutdown.
        """
        self.logger.info("server_starting", config=self.config)

        try:
            # Validate OpenCTI connection on startup
            validation = await self.opencti_client.validate_opencti_setup()
            self.logger.info(
                "opencti_validated",
                version=validation['version'],
                status=validation['status']
            )

            if validation['status'] == 'empty_database':
                self.logger.warning(
                    "empty_database_detected",
                    message="OpenCTI database is empty. Configure connectors to import data."
                )

            # Start MCP server
            from mcp.server.stdio import stdio_server

            async with stdio_server() as (read_stream, write_stream):
                self.logger.info("server_running", status="ready")
                await self.server.run(
                    read_stream,
                    write_stream,
                    self.server.create_initialization_options()
                )

        except Exception as e:
            self.logger.error(
                "server_error",
                error=str(e),
                error_type=type(e).__name__
            )
            raise
        finally:
            await self.opencti_client.close()
            self.logger.info("server_shutdown", status="complete")
