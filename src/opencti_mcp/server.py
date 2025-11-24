"""
Cooper Cyber Coffee OpenCTI MCP Server - Core Server Implementation
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

Contact: matt@coopercybercoffee.com
"""

import asyncio
import time
from typing import Any, Dict
from mcp.server import Server
from mcp import types
from mcp.types import (
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
)
import structlog

from .opencti_client import OpenCTIClient
from .config_manager import ConfigManager
from .audit import AuditLogger
from .tlp_filter import TLPFilter
from .rate_limiter import RateLimiter
from .exceptions import OperationCancelled
from .mcp_context import MCPToolContext, CancellationToken
from .tools import get_mcp_tools
from .utils import (
    format_error_message,
    validate_hash,
    detect_observable_type,
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

        # Initialize configuration manager for templates and context
        self.config_manager = ConfigManager(
            config_dir=config.get("config_dir", "config")
        )

        # Initialize audit logger for compliance
        self.audit_logger = AuditLogger()
        self.audit_logger.log_session_start(
            metadata={
                "version": get_version_info()["version"],
                "opencti_url": config["opencti_url"],
                "config_dir": config.get("config_dir", "config")
            }
        )

        # Initialize TLP filter for data governance
        try:
            self.tlp_filter = TLPFilter("config/tlp_policy.yaml")
            self.logger.info("tlp_filtering_enabled", policy="TLP:CLEAR only (default)")
        except Exception as e:
            self.logger.error(f"Failed to load TLP policy: {e}")
            raise

        # Initialize rate limiter for DoS protection (v0.4.0+)
        calls_per_minute = config.get("rate_limit_calls_per_minute", 60)
        self.rate_limiter = RateLimiter(calls_per_minute=calls_per_minute)
        self.logger.info(
            "rate_limiting_enabled",
            calls_per_minute=calls_per_minute,
            message="DoS protection active"
        )

        # Track current data classification for audit logging
        self._current_classification = "UNMARKED"

        # Track filtering metadata for audit logging (v0.4.0+)
        self._filtering_metadata = None

        # Register handlers
        self._register_handlers()

        self.logger.info(
            "server_initialized",
            version=get_version_info()["version"],
            opencti_url=config["opencti_url"],
            audit_session=self.audit_logger.get_session_id()
        )

    def _format_indicator_data_with_template(
        self,
        indicators: list,
        analysis_type: str = "executive_briefing"
    ) -> str:
        """Format indicator data with appropriate template for analysis.

        Args:
            indicators: List of indicator dictionaries from OpenCTI
            analysis_type: Type of analysis template to use

        Returns:
            Formatted string combining template with indicator data
        """
        # Get full context (template + PIRs + security stack)
        template_context = self.config_manager.get_full_context(analysis_type)

        # Build indicator summary
        indicator_summary = f"\n\n## THREAT INTELLIGENCE DATA ({len(indicators)} indicators)\n\n"

        for idx, indicator in enumerate(indicators, 1):
            indicator_summary += f"### Indicator {idx}\n"
            indicator_summary += f"- **Pattern**: {indicator.get('pattern', 'N/A')}\n"
            indicator_summary += f"- **Type**: {', '.join(indicator.get('indicator_types', ['unknown']))}\n"
            indicator_summary += f"- **Confidence**: {indicator.get('confidence', 0)}%\n"
            indicator_summary += f"- **Created**: {indicator.get('created_at', 'N/A')}\n"

            labels = indicator.get('labels', [])
            if labels:
                indicator_summary += f"- **Labels**: {', '.join(labels)}\n"

            indicator_summary += "\n"

        return template_context + indicator_summary

    def _count_results(self, result: Any) -> Optional[int]:
        """Count results from tool response for audit logging.

        Args:
            result: Tool response (list of TextContent)

        Returns:
            Number of results if determinable, else None
        """
        if not result:
            return 0

        # Result is a list of TextContent objects
        if isinstance(result, list) and len(result) > 0:
            # Try to extract count from text content
            text = result[0].text if hasattr(result[0], 'text') else str(result[0])

            # Look for common patterns in output
            import re

            # Pattern: "Retrieved X indicators/patterns/entities/etc"
            match = re.search(r'Retrieved (\d+)', text)
            if match:
                return int(match.group(1))

            # Pattern: "Found X results"
            match = re.search(r'Found (\d+)', text)
            if match:
                return int(match.group(1))

            # Pattern: "Total: X"
            match = re.search(r'Total:\s*(\d+)', text)
            if match:
                return int(match.group(1))

            # Pattern: count in brackets like "[47 results]"
            match = re.search(r'\[(\d+)\s+(?:results?|indicators?|entities?)\]', text)
            if match:
                return int(match.group(1))

        return None

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
            """Handle tool execution requests with audit logging, progress reporting, and cancellation."""
            self.logger.info("tool_called", tool=name, args=arguments)

            # Apply rate limiting (v0.4.0+)
            allowed, message, reset_in = self.rate_limiter.check_rate_limit()
            if not allowed:
                error_response = self.rate_limiter.get_rate_limit_error(reset_in)
                self.logger.warning(
                    "rate_limit_exceeded",
                    tool=name,
                    reset_in=reset_in
                )
                return [TextContent(
                    type="text",
                    text=error_response["error"]["message"]
                )]

            # Generate correlation ID for tracking related events (v0.4.0+)
            import uuid
            correlation_id = str(uuid.uuid4())
            self.logger.info("correlation_id", id=correlation_id)

            # Create MCP context for progress reporting and cancellation (v0.4.1+)
            cancellation_token = CancellationToken()
            ctx = MCPToolContext(
                logger=self.logger,
                cancellation_token=cancellation_token
            )

            # Start timing for performance metrics
            start_time = time.time()

            try:
                # Execute tool handler and capture result for audit logging
                if name == "get_recent_indicators_with_analysis":
                    result = await self._handle_get_recent_indicators(arguments, ctx)

                elif name == "search_observable":
                    result = await self._handle_search_observable(arguments, ctx)

                elif name == "validate_opencti_connection":
                    result = await self._handle_validate_connection(arguments, ctx)

                elif name == "get_threat_landscape_summary":
                    result = await self._handle_threat_landscape_summary(arguments, ctx)

                elif name == "get_attack_patterns":
                    result = await self._handle_get_attack_patterns(arguments, ctx)

                elif name == "get_vulnerabilities":
                    result = await self._handle_get_vulnerabilities(arguments, ctx)

                elif name == "get_malware":
                    result = await self._handle_get_malware(arguments, ctx)

                elif name == "search_entities":
                    result = await self._handle_search_entities(arguments, ctx)

                elif name == "get_threat_actor_ttps":
                    result = await self._handle_get_threat_actor_ttps(arguments, ctx)

                elif name == "get_malware_techniques":
                    result = await self._handle_get_malware_techniques(arguments, ctx)

                elif name == "get_campaign_details":
                    result = await self._handle_get_campaign_details(arguments, ctx)

                elif name == "get_entity_relationships":
                    result = await self._handle_get_entity_relationships(arguments, ctx)

                elif name == "get_reports":
                    result = await self._handle_get_reports(arguments, ctx)

                else:
                    error_msg = f"Unknown tool: {name}"
                    self.logger.error("unknown_tool", tool=name)

                    # Audit log unknown tool attempt
                    execution_time_ms = int((time.time() - start_time) * 1000)
                    self.audit_logger.log_tool_call(
                        tool_name=name,
                        parameters=arguments,
                        execution_time_ms=execution_time_ms,
                        success=False,
                        error=f"Unknown tool: {name}",
                        correlation_id=correlation_id
                    )

                    return [TextContent(type="text", text=error_msg)]

                # Calculate execution time
                execution_time_ms = int((time.time() - start_time) * 1000)

                # Count results
                results_count = self._count_results(result) if 'result' in locals() else None

                # Audit log successful tool call (v0.4.0+: includes correlation ID and filtering metadata)
                self.audit_logger.log_tool_call(
                    tool_name=name,
                    parameters=arguments,
                    data_classification=self._current_classification,
                    results_count=results_count,
                    execution_time_ms=execution_time_ms,
                    success=True,
                    correlation_id=correlation_id,
                    filtering_metadata=self._filtering_metadata
                )

                # Reset classification and filtering metadata for next call
                self._current_classification = "UNMARKED"
                self._filtering_metadata = None

                return result

            except OperationCancelled as e:
                # User-initiated cancellation (v0.4.1+) - NOT an error condition
                execution_time_ms = int((time.time() - start_time) * 1000)

                self.logger.info(
                    "tool_cancelled",
                    tool=name,
                    correlation_id=correlation_id,
                    execution_time_ms=execution_time_ms,
                    message=str(e)
                )

                # Audit log cancellation
                self.audit_logger.log_tool_call(
                    tool_name=name,
                    parameters=arguments,
                    data_classification="N/A",
                    results_count=0,
                    execution_time_ms=execution_time_ms,
                    success=False,
                    error="User cancelled operation",
                    correlation_id=correlation_id
                )

                # Return user-friendly cancellation message
                return [TextContent(
                    type="text",
                    text=(
                        "⛔ **Operation Cancelled**\n\n"
                        "The operation was cancelled by user request.\n\n"
                        "Partial results have been discarded for data consistency."
                    )
                )]

            except Exception as e:
                # Calculate execution time even on failure
                execution_time_ms = int((time.time() - start_time) * 1000)

                error_msg = format_error_message(e, f"tool execution ({name})")
                self.logger.error(
                    "tool_execution_failed",
                    tool=name,
                    error=str(e),
                    error_type=type(e).__name__
                )

                # Audit log failed tool call (v0.4.0+: includes correlation ID)
                self.audit_logger.log_tool_call(
                    tool_name=name,
                    parameters=arguments,
                    execution_time_ms=execution_time_ms,
                    success=False,
                    error=str(e),
                    correlation_id=correlation_id
                )

                # Also log as error event
                self.audit_logger.log_error(
                    error_type=type(e).__name__,
                    error_message=str(e),
                    context={"tool_name": name, "parameters": arguments}
                )

                return [TextContent(
                    type="text",
                    text=f"❌ Error: {error_msg}\n\n"
                         f"Please check your OpenCTI connection and try again."
                )]

    async def _handle_get_recent_indicators(
        self,
        args: dict,
        ctx: MCPToolContext
    ) -> list[TextContent]:
        """Handle get_recent_indicators_with_analysis tool with progress reporting.

        Args:
            args: Tool arguments including limit, types, confidence, analysis_type
            ctx: MCP context for progress reporting and cancellation (v0.4.1+)

        Returns:
            List containing TextContent with formatted indicator analysis

        Raises:
            OperationCancelled: If user cancels operation via ctx.cancellation_token
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

        # Define progress callback wrapper
        async def report_progress(current: int, total: int, message: str):
            """Report progress to Claude Desktop via MCP context."""
            await ctx.send_progress(current, total, message)

        # Fetch indicators from OpenCTI with server-side TLP filtering (v0.4.0+)
        # and progress reporting + cancellation support (v0.4.1+)
        try:
            indicators, filtering_metadata = await self.opencti_client.get_recent_indicators_scoped(
                limit=limit,
                indicator_types=indicator_types,
                days_back=days_back,
                min_confidence=min_confidence,
                use_server_side_filtering=True,
                progress_callback=report_progress,
                cancellation_token=ctx.cancellation_token
            )

            # Store filtering metadata for audit logging
            self._filtering_metadata = filtering_metadata

            # Log filtering performance
            if filtering_metadata.get("filtering_method") == "server_side":
                self.logger.info(
                    "server_side_filtering_applied",
                    performance_ms=filtering_metadata.get("performance_ms"),
                    marking_count=filtering_metadata.get("scoping_metadata", {}).get("marking_uuids_count", 0)
                )
            else:
                self.logger.info(
                    "client_side_filtering_fallback",
                    reason=filtering_metadata.get("scoping_metadata", {}).get("reason", "unknown")
                )
        except OperationCancelled:
            # Re-raise cancellation (will be caught by call_tool() handler)
            raise
        except AttributeError:
            # Fallback to old method if scoped method doesn't exist (backward compatibility)
            self.logger.warning("get_recent_indicators_scoped_not_available", message="Using legacy method")
            indicators = await self.opencti_client.get_recent_indicators(
                limit=limit,
                indicator_types=indicator_types,
                days_back=days_back,
                min_confidence=min_confidence
            )
            self._filtering_metadata = {"filtering_method": "client_side_legacy"}

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

        # Apply client-side TLP filtering (security: defense in depth, even with server-side filtering)
        indicators, stats = self.tlp_filter.filter_objects(indicators)

        # Set classification for audit logging
        if indicators:
            self._current_classification = self.tlp_filter.get_classification_label(indicators[0])
        else:
            self._current_classification = "UNMARKED"

        # Log filtering stats
        if stats['filtered_objects'] > 0:
            self.logger.warning(
                "tlp_filter_applied",
                filtered=stats['filtered_objects'],
                total=stats['total_objects'],
                reasons=stats['filter_reasons']
            )

        # If strict mode filtered everything, return error
        if not indicators and stats['total_objects'] > 0:
            return [TextContent(
                type="text",
                text=(
                    f"⚠️ **TLP Policy Violation**\n\n"
                    f"All {stats['total_objects']} indicators were filtered due to TLP restrictions.\n\n"
                    f"**Filtered Reasons:**\n"
                    + "\n".join([f"- {reason}: {count}" for reason, count in stats['filter_reasons'].items()])
                    + "\n\n"
                    f"**Current Policy:** Only TLP:CLEAR data is sent to Claude by default.\n\n"
                    f"**To resolve:**\n"
                    f"1. Review `config/tlp_policy.yaml` to understand your current policy\n"
                    f"2. Ensure OpenCTI objects are marked with TLP:CLEAR if they're public data\n"
                    f"3. Adjust policy if appropriate for your organization\n"
                    f"4. See README Data Governance section for guidance\n"
                )
            )]

        # Generate summary statistics
        summary = format_indicator_summary(indicators)

        # Format with analysis template (includes PIRs and security stack context)
        formatted_output = self._format_indicator_data_with_template(
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

    async def _handle_search_observable(self, args: dict, ctx: MCPToolContext) -> list[TextContent]:
        """Handle search_observable tool with multi-type support.

        Supports IPv4, IPv6, domains, URLs, emails, and file hashes with
        automatic type detection and contextual analysis.

        Args:
            args: Tool arguments including observable value and context flag
            ctx: MCP context for progress reporting and cancellation (v0.4.1+)

        Returns:
            List containing TextContent with search results
        """
        observable_value = args.get("value", "").strip()
        include_context = args.get("include_context", True)

        # Detect and validate observable type
        observable_info = detect_observable_type(observable_value)
        if not observable_info:
            return [TextContent(
                type="text",
                text=(
                    f"❌ Invalid or unsupported observable format: `{observable_value}`\n\n"
                    "**Supported formats:**\n"
                    "- **IPv4:** 192.168.1.1\n"
                    "- **IPv6:** 2001:0db8:85a3::8a2e:0370:7334\n"
                    "- **Domain:** evil.com, malware.example.org\n"
                    "- **URL:** http://malicious.com/payload.exe\n"
                    "- **Email:** attacker@evil.com\n"
                    "- **Hash (MD5):** 44d88612fea8a8f36de82e1278abb02f (32 hex chars)\n"
                    "- **Hash (SHA1):** 356a192b7913b04c54574d18c28d46e6395428ab (40 hex chars)\n"
                    "- **Hash (SHA256):** e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (64 hex chars)\n\n"
                    "**Example:** `search_observable(value=\"192.168.1.1\")`"
                )
            )]

        observable_type = observable_info['type']
        indicator_type = observable_info['indicator_type']

        self.logger.info(
            "searching_observable",
            value=observable_value,
            type=observable_type,
            indicator_type=indicator_type
        )

        # Search OpenCTI
        results = await self.opencti_client.search_observable(observable_value)

        if not results:
            return [TextContent(
                type="text",
                text=(
                    f"# Observable Search Results\n\n"
                    f"**Observable:** `{observable_value}`\n"
                    f"**Type:** {observable_type.upper()}\n"
                    f"**Indicator Type:** {indicator_type}\n"
                    f"**Status:** ✅ Not found in threat intelligence database\n\n"
                    "This observable is not currently identified as malicious in your "
                    "OpenCTI instance. However, this does not guarantee it is safe. "
                    "Consider:\n\n"
                    "1. Checking other threat intelligence sources\n"
                    "2. Reviewing historical context and associations\n"
                    "3. Monitoring for future appearances\n"
                    "4. Correlating with other indicators\n\n"
                    "*Results reflect data available in your OpenCTI instance only.*"
                )
            )]

        # Apply TLP filtering
        results, stats = self.tlp_filter.filter_objects(results)

        # Set classification for audit logging
        if results:
            self._current_classification = self.tlp_filter.get_classification_label(results[0])
        else:
            self._current_classification = "UNMARKED"

        # Log filtering stats
        if stats['filtered_objects'] > 0:
            self.logger.warning(
                "tlp_filter_applied",
                filtered=stats['filtered_objects'],
                total=stats['total_objects'],
                reasons=stats['filter_reasons']
            )

        # If strict mode filtered everything, return error
        if not results and stats['total_objects'] > 0:
            return [TextContent(
                type="text",
                text=(
                    f"⚠️ **TLP Policy Violation**\n\n"
                    f"Hash search found {stats['total_objects']} matches, but all were filtered due to TLP restrictions.\n\n"
                    f"**Filtered Reasons:**\n"
                    + "\n".join([f"- {reason}: {count}" for reason, count in stats['filter_reasons'].items()])
                    + "\n\n"
                    f"**Current Policy:** Only TLP:CLEAR data is sent to Claude by default.\n\n"
                    f"Review `config/tlp_policy.yaml` and README Data Governance section for guidance.\n"
                )
            )]

        # Format results
        output = (
            f"# Observable Search Results\n\n"
            f"**Observable:** `{observable_value}`\n"
            f"**Type:** {observable_type.upper()}\n"
            f"**Indicator Type:** {indicator_type}\n"
            f"**Status:** ⚠️ Found in threat intelligence database\n"
            f"**Matches:** {len(results)}\n\n"
            "---\n\n"
        )

        for idx, result in enumerate(results, 1):
            output += f"## Match {idx}\n\n"
            output += f"- **Pattern:** `{result.get('pattern', 'N/A')}`\n"
            output += f"- **Indicator Types:** {', '.join(result.get('indicator_types', ['unknown']))}\n"
            output += f"- **Confidence:** {result.get('confidence', 0)}%\n"
            output += f"- **Created:** {result.get('created_at', 'N/A')}\n"

            if include_context:
                labels = result.get('labels', [])
                if labels:
                    output += f"- **Labels:** {', '.join(labels)}\n"

            output += "\n"

        # Provide type-specific recommendations
        if observable_type.startswith('hash-'):
            recommendations = (
                "\n**Recommended Actions:**\n"
                "1. Block this hash at network perimeter and endpoints\n"
                "2. Search for this hash in your environment\n"
                "3. Review associated malware families and campaigns\n"
                "4. Update detection signatures and YARA rules\n"
            )
        elif observable_type in ['ipv4', 'ipv6']:
            recommendations = (
                "\n**Recommended Actions:**\n"
                "1. Block this IP at network perimeter (firewall, IPS)\n"
                "2. Search logs for connections to/from this IP\n"
                "3. Review associated domains and infrastructure\n"
                "4. Check for ongoing connections\n"
            )
        elif observable_type == 'domain':
            recommendations = (
                "\n**Recommended Actions:**\n"
                "1. Block this domain in DNS and web proxies\n"
                "2. Search logs for DNS queries and HTTP requests\n"
                "3. Review WHOIS and domain registration data\n"
                "4. Check for subdomains and related infrastructure\n"
            )
        elif observable_type == 'url':
            recommendations = (
                "\n**Recommended Actions:**\n"
                "1. Block this URL in web proxies and security gateways\n"
                "2. Search logs for access attempts\n"
                "3. Review the hosting infrastructure\n"
                "4. Check for similar URLs in campaigns\n"
            )
        elif observable_type == 'email':
            recommendations = (
                "\n**Recommended Actions:**\n"
                "1. Block sender in email security gateway\n"
                "2. Search mailboxes for messages from this address\n"
                "3. Review associated phishing campaigns\n"
                "4. Educate users about this threat actor\n"
            )
        else:
            recommendations = (
                "\n**Recommended Actions:**\n"
                "1. Block this observable in relevant security controls\n"
                "2. Search your environment for this indicator\n"
                "3. Review associated threats and campaigns\n"
                "4. Update detection rules\n"
            )

        output += recommendations

        self.logger.info("observable_search_complete", matches=len(results), type=observable_type)

        return [TextContent(type="text", text=output)]

    async def _handle_validate_connection(self, args: dict, ctx: MCPToolContext) -> list[TextContent]:
        """Handle validate_opencti_connection tool.

        Args:
            args: Tool arguments including detailed flag
            ctx: MCP context for progress reporting and cancellation (v0.4.1+)

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

    async def _handle_threat_landscape_summary(self, args: dict, ctx: MCPToolContext) -> list[TextContent]:
        """Handle get_threat_landscape_summary tool.

        Args:
            args: Tool arguments including days_back, focus_area, output_format
            ctx: MCP context for progress reporting and cancellation (v0.4.1+)

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

        formatted_output = self._format_indicator_data_with_template(
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
            tech_output = self._format_indicator_data_with_template(
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

    async def _handle_get_attack_patterns(self, args: dict, ctx: MCPToolContext) -> list[TextContent]:
        """Handle get_attack_patterns tool.

        Args:
            args: Tool arguments including limit, search_term, analysis_type
            ctx: MCP context for progress reporting and cancellation (v0.4.1+)

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

        # Apply TLP filtering
        patterns, stats = self.tlp_filter.filter_objects(patterns)

        # Set classification for audit logging
        if patterns:
            self._current_classification = self.tlp_filter.get_classification_label(patterns[0])
        else:
            self._current_classification = "UNMARKED"

        # Log filtering stats
        if stats['filtered_objects'] > 0:
            self.logger.warning(
                "tlp_filter_applied",
                filtered=stats['filtered_objects'],
                total=stats['total_objects'],
                reasons=stats['filter_reasons']
            )

        # If strict mode filtered everything, return error
        if not patterns and stats['total_objects'] > 0:
            return [TextContent(
                type="text",
                text=(
                    f"⚠️ **TLP Policy Violation**\n\n"
                    f"All {stats['total_objects']} attack patterns were filtered due to TLP restrictions.\n\n"
                    f"**Filtered Reasons:**\n"
                    + "\n".join([f"- {reason}: {count}" for reason, count in stats['filter_reasons'].items()])
                    + "\n\n"
                    f"**Current Policy:** Only TLP:CLEAR data is sent to Claude by default.\n\n"
                    f"Review `config/tlp_policy.yaml` for guidance.\n"
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
        template = self.config_manager.get_full_context(analysis_type)
        output += "\n---\n\n" + template

        self.logger.info("attack_patterns_retrieved", count=len(patterns))

        return [TextContent(type="text", text=output)]

    async def _handle_get_vulnerabilities(self, args: dict, ctx: MCPToolContext) -> list[TextContent]:
        """Handle get_vulnerabilities tool.

        Args:
            args: Tool arguments including limit, search_term, min_severity, analysis_type
            ctx: MCP context for progress reporting and cancellation (v0.4.1+)

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

        # Apply TLP filtering

        # Set classification for audit logging
        if vulns:
            self._current_classification = self.tlp_filter.get_classification_label(vulns[0])
        else:
            self._current_classification = "UNMARKED"
        vulns, stats = self.tlp_filter.filter_objects(vulns)

        # Log filtering stats
        if stats['filtered_objects'] > 0:
            self.logger.warning(
                "tlp_filter_applied",
                filtered=stats['filtered_objects'],
                total=stats['total_objects'],
                reasons=stats['filter_reasons']
            )

        # If strict mode filtered everything, return error
        if not vulns and stats['total_objects'] > 0:
            return [TextContent(
                type="text",
                text=(
                    f"⚠️ **TLP Policy Violation**\n\n"
                    f"All {stats['total_objects']} vulnerabilities were filtered due to TLP restrictions.\n\n"
                    f"**Filtered Reasons:**\n"
                    + "\n".join([f"- {reason}: {count}" for reason, count in stats['filter_reasons'].items()])
                    + "\n\n"
                    f"**Current Policy:** Only TLP:CLEAR data is sent to Claude by default.\n\n"
                    f"Review `config/tlp_policy.yaml` for guidance.\n"
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
        template = self.config_manager.get_full_context(analysis_type)
        output += "\n---\n\n" + template

        self.logger.info("vulnerabilities_retrieved", count=len(vulns))

        return [TextContent(type="text", text=output)]

    async def _handle_get_malware(self, args: dict, ctx: MCPToolContext) -> list[TextContent]:
        """Handle get_malware tool.

        Args:
            args: Tool arguments including limit, search_term, analysis_type
            ctx: MCP context for progress reporting and cancellation (v0.4.1+)

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

        # Set classification for audit logging
        if malware_list:
            self._current_classification = self.tlp_filter.get_classification_label(malware_list[0])
        else:
            self._current_classification = "UNMARKED"

        # Apply TLP filtering
        malware_list, stats = self.tlp_filter.filter_objects(malware_list)

        # Log filtering stats
        if stats['filtered_objects'] > 0:
            self.logger.warning(
                "tlp_filter_applied",
                filtered=stats['filtered_objects'],
                total=stats['total_objects'],
                reasons=stats['filter_reasons']
            )

        # If strict mode filtered everything, return error
        if not malware_list and stats['total_objects'] > 0:
            return [TextContent(
                type="text",
                text=(
                    f"⚠️ **TLP Policy Violation**\n\n"
                    f"All {stats['total_objects']} malware entries were filtered due to TLP restrictions.\n\n"
                    f"**Filtered Reasons:**\n"
                    + "\n".join([f"- {reason}: {count}" for reason, count in stats['filter_reasons'].items()])
                    + "\n\n"
                    f"**Current Policy:** Only TLP:CLEAR data is sent to Claude by default.\n\n"
                    f"Review `config/tlp_policy.yaml` for guidance.\n"
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
        template = self.config_manager.get_full_context(analysis_type)
        output += "\n---\n\n" + template

        self.logger.info("malware_retrieved", count=len(malware_list))

        return [TextContent(type="text", text=output)]

    async def _handle_search_entities(self, args: dict, ctx: MCPToolContext) -> list[TextContent]:
        """Handle search_entities tool.

        Args:
            args: Tool arguments including search_term, entity_types, limit
            ctx: MCP context for progress reporting and cancellation (v0.4.1+)

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

        # Set classification for audit logging
        if results:
            self._current_classification = self.tlp_filter.get_classification_label(results[0])
        else:
            self._current_classification = "UNMARKED"

        # Apply TLP filtering
        results, stats = self.tlp_filter.filter_objects(results)

        # Log filtering stats
        if stats['filtered_objects'] > 0:
            self.logger.warning(
                "tlp_filter_applied",
                filtered=stats['filtered_objects'],
                total=stats['total_objects'],
                reasons=stats['filter_reasons']
            )

        # If strict mode filtered everything, return error
        if not results and stats['total_objects'] > 0:
            return [TextContent(
                type="text",
                text=(
                    f"⚠️ **TLP Policy Violation**\n\n"
                    f"All {stats['total_objects']} entities were filtered due to TLP restrictions.\n\n"
                    f"**Filtered Reasons:**\n"
                    + "\n".join([f"- {reason}: {count}" for reason, count in stats['filter_reasons'].items()])
                    + "\n\n"
                    f"**Current Policy:** Only TLP:CLEAR data is sent to Claude by default.\n\n"
                    f"Review `config/tlp_policy.yaml` for guidance.\n"
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
            output += f"- **Entity ID:** `{entity.get('id', 'N/A')}`\n"
            output += f"- **Entity Type:** {entity.get('entity_type', 'Unknown')}\n"

            # Add MITRE ID if available
            mitre_id = entity.get('mitre_id')
            if mitre_id:
                output += f"- **MITRE ID:** {mitre_id}\n"

            # Add aliases if available
            aliases = entity.get('aliases', [])
            if aliases:
                output += f"- **Aliases:** {', '.join(aliases[:5])}\n"

            output += f"- **Description:** {entity.get('description', 'No description')}\n"

            labels = entity.get('labels', [])
            if labels:
                output += f"- **Labels:** {', '.join(labels[:5])}\n"

            output += "\n"

        # Add usage hint for query chaining
        output += (
            "---\n\n"
            "**💡 Query Chaining:**\n"
            "Use the Entity IDs above with relationship query functions:\n"
            "- `get_threat_actor_ttps(actor_name=<entity_id>)` - Get threat actor TTPs\n"
            "- `get_malware_techniques(malware_name=<entity_id>)` - Get malware techniques\n"
            "- `get_campaign_details(campaign_name=<entity_id>)` - Get campaign details\n"
            "- `get_entity_relationships(entity_id=<entity_id>)` - Get all relationships\n\n"
            "You can also use names, aliases, or MITRE IDs - the MCP server will resolve them automatically!\n"
        )

        self.logger.info("entity_search_complete", results=len(results))

        return [TextContent(type="text", text=output)]

    async def _handle_get_threat_actor_ttps(self, args: dict, ctx: MCPToolContext) -> list[TextContent]:
        """Handle get_threat_actor_ttps tool.

        Args:
            args: Tool arguments including actor_name, limit, analysis_type
            ctx: MCP context for progress reporting and cancellation (v0.4.1+)

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

        # Set classification for audit logging
        if attack_patterns:
            self._current_classification = self.tlp_filter.get_classification_label(attack_patterns[0])
        else:
            self._current_classification = "UNMARKED"

        # Apply TLP filtering
        attack_patterns, stats = self.tlp_filter.filter_objects(attack_patterns)

        # Log filtering stats
        if stats['filtered_objects'] > 0:
            self.logger.warning(
                "tlp_filter_applied",
                filtered=stats['filtered_objects'],
                total=stats['total_objects'],
                reasons=stats['filter_reasons']
            )

        # If strict mode filtered everything, return error
        if not attack_patterns and stats['total_objects'] > 0:
            return [TextContent(
                type="text",
                text=(
                    f"⚠️ **TLP Policy Violation**\n\n"
                    f"All {stats['total_objects']} attack patterns were filtered due to TLP restrictions.\n\n"
                    f"**Filtered Reasons:**\n"
                    + "\n".join([f"- {reason}: {count}" for reason, count in stats['filter_reasons'].items()])
                    + "\n\n"
                    f"**Current Policy:** Only TLP:CLEAR data is sent to Claude by default.\n\n"
                    f"Review `config/tlp_policy.yaml` for guidance.\n"
                )
            )]

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
        template = self.config_manager.get_full_context(analysis_type)
        output += "\n---\n\n" + template

        self.logger.info("actor_ttps_retrieved", count=len(attack_patterns))

        return [TextContent(type="text", text=output)]

    async def _handle_get_malware_techniques(self, args: dict, ctx: MCPToolContext) -> list[TextContent]:
        """Handle get_malware_techniques tool.

        Args:
            args: Tool arguments including malware_name, limit, analysis_type
            ctx: MCP context for progress reporting and cancellation (v0.4.1+)

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

        # Set classification for audit logging
        if attack_patterns:
            self._current_classification = self.tlp_filter.get_classification_label(attack_patterns[0])
        else:
            self._current_classification = "UNMARKED"

        # Apply TLP filtering
        attack_patterns, stats = self.tlp_filter.filter_objects(attack_patterns)

        # Log filtering stats
        if stats['filtered_objects'] > 0:
            self.logger.warning(
                "tlp_filter_applied",
                filtered=stats['filtered_objects'],
                total=stats['total_objects'],
                reasons=stats['filter_reasons']
            )

        # If strict mode filtered everything, return error
        if not attack_patterns and stats['total_objects'] > 0:
            return [TextContent(
                type="text",
                text=(
                    f"⚠️ **TLP Policy Violation**\n\n"
                    f"All {stats['total_objects']} techniques were filtered due to TLP restrictions.\n\n"
                    f"**Filtered Reasons:**\n"
                    + "\n".join([f"- {reason}: {count}" for reason, count in stats['filter_reasons'].items()])
                    + "\n\n"
                    f"**Current Policy:** Only TLP:CLEAR data is sent to Claude by default.\n\n"
                    f"Review `config/tlp_policy.yaml` for guidance.\n"
                )
            )]

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
        template = self.config_manager.get_full_context(analysis_type)
        output += "\n---\n\n" + template

        self.logger.info("malware_techniques_retrieved", count=len(attack_patterns))

        return [TextContent(type="text", text=output)]

    async def _handle_get_campaign_details(self, args: dict, ctx: MCPToolContext) -> list[TextContent]:
        """Handle get_campaign_details tool.

        Args:
            args: Tool arguments including campaign_name, analysis_type
            ctx: MCP context for progress reporting and cancellation (v0.4.1+)

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

        # Apply TLP filtering to campaign object
        campaign_list = [result]
        campaign_list, stats = self.tlp_filter.filter_objects(campaign_list)

        # Set classification for audit logging
        if campaign_list:
            self._current_classification = self.tlp_filter.get_classification_label(campaign_list[0])
        else:
            self._current_classification = "UNMARKED"

        # Log filtering stats
        if stats['filtered_objects'] > 0:
            self.logger.warning(
                "tlp_filter_applied",
                filtered=stats['filtered_objects'],
                total=stats['total_objects'],
                reasons=stats['filter_reasons']
            )

        # If strict mode filtered the campaign, return error
        if not campaign_list and stats['total_objects'] > 0:
            return [TextContent(
                type="text",
                text=(
                    f"⚠️ **TLP Policy Violation**\n\n"
                    f"Campaign was filtered due to TLP restrictions.\n\n"
                    f"**Filtered Reasons:**\n"
                    + "\n".join([f"- {reason}: {count}" for reason, count in stats['filter_reasons'].items()])
                    + "\n\n"
                    f"**Current Policy:** Only TLP:CLEAR data is sent to Claude by default.\n\n"
                    f"Review `config/tlp_policy.yaml` for guidance.\n"
                )
            )]

        result = campaign_list[0]

        # Apply TLP filtering to embedded threat actors
        if result.get("threat_actors"):
            threat_actors, ta_stats = self.tlp_filter.filter_objects(result["threat_actors"])
            result["threat_actors"] = threat_actors
            if ta_stats['filtered_objects'] > 0:
                self.logger.warning(f"Filtered {ta_stats['filtered_objects']} threat actors from campaign")

        # Apply TLP filtering to embedded attack patterns
        if result.get("attack_patterns"):
            attack_patterns, ap_stats = self.tlp_filter.filter_objects(result["attack_patterns"])
            result["attack_patterns"] = attack_patterns
            if ap_stats['filtered_objects'] > 0:
                self.logger.warning(f"Filtered {ap_stats['filtered_objects']} attack patterns from campaign")

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
        template = self.config_manager.get_full_context(analysis_type)
        output += "\n---\n\n" + template

        self.logger.info("campaign_details_retrieved", campaign=result.get('name'))

        return [TextContent(type="text", text=output)]

    async def _handle_get_entity_relationships(self, args: dict, ctx: MCPToolContext) -> list[TextContent]:
        """Handle get_entity_relationships tool.

        Args:
            args: Tool arguments including entity_id, relationship_type, limit
            ctx: MCP context for progress reporting and cancellation (v0.4.1+)

        Returns:
            List containing TextContent with formatted relationship graph
        """
        entity_id = args.get("entity_id", "")
        relationship_type = args.get("relationship_type", "all")
        limit = args.get("limit", 50)

        if not entity_id:
            return [TextContent(
                type="text",
                text="❌ Error: entity_id is required"
            )]

        self.logger.info(
            "fetching_entity_relationships",
            entity_id=entity_id,
            relationship_type=relationship_type,
            limit=limit
        )

        # Fetch relationships from OpenCTI
        result = await self.opencti_client.get_entity_relationships(
            entity_id=entity_id,
            relationship_type=relationship_type if relationship_type != "all" else None,
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

        # Set classification for audit logging
        if relationships:
            self._current_classification = self.tlp_filter.get_classification_label(relationships[0])
        else:
            self._current_classification = "UNMARKED"

        # Apply TLP filtering
        relationships, stats = self.tlp_filter.filter_objects(relationships)

        # Log filtering stats
        if stats['filtered_objects'] > 0:
            self.logger.warning(
                "tlp_filter_applied",
                filtered=stats['filtered_objects'],
                total=stats['total_objects'],
                reasons=stats['filter_reasons']
            )

        # If strict mode filtered everything, return error
        if not relationships and stats['total_objects'] > 0:
            return [TextContent(
                type="text",
                text=(
                    f"⚠️ **TLP Policy Violation**\n\n"
                    f"All {stats['total_objects']} relationships were filtered due to TLP restrictions.\n\n"
                    f"**Filtered Reasons:**\n"
                    + "\n".join([f"- {reason}: {count}" for reason, count in stats['filter_reasons'].items()])
                    + "\n\n"
                    f"**Current Policy:** Only TLP:CLEAR data is sent to Claude by default.\n\n"
                    f"Review `config/tlp_policy.yaml` for guidance.\n"
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

    async def _handle_get_reports(self, args: dict, ctx: MCPToolContext) -> list[TextContent]:
        """Handle get_reports tool.

        Args:
            args: Tool arguments including limit, search_term, published_after, min_confidence
            ctx: MCP context for progress reporting and cancellation (v0.4.1+)

        Returns:
            List containing TextContent with formatted report summaries
        """
        limit = args.get("limit", 10)
        search_term = args.get("search_term")
        published_after = args.get("published_after")
        min_confidence = args.get("min_confidence", 0)

        self.logger.info(
            "fetching_reports",
            limit=limit,
            search_term=search_term,
            published_after=published_after,
            min_confidence=min_confidence
        )

        # Fetch reports from OpenCTI
        reports = await self.opencti_client.get_reports(
            limit=limit,
            search_term=search_term,
            published_after=published_after,
            min_confidence=min_confidence
        )

        if not reports:
            search_info = f" matching '{search_term}'" if search_term else ""
            date_info = f" published after {published_after}" if published_after else ""
            confidence_info = f" with confidence >= {min_confidence}%" if min_confidence > 0 else ""

            return [TextContent(
                type="text",
                text=(
                    f"ℹ️ No reports found{search_info}{date_info}{confidence_info}.\n\n"
                    "**Suggestions:**\n"
                    "- Try a different search term\n"
                    "- Remove date or confidence filters\n"
                    "- Check if reports are imported in OpenCTI\n"
                )
            )]

        # Set classification for audit logging
        if reports:
            self._current_classification = self.tlp_filter.get_classification_label(reports[0])
        else:
            self._current_classification = "UNMARKED"

        # Apply TLP filtering
        reports, stats = self.tlp_filter.filter_objects(reports)

        # Log filtering stats
        if stats['filtered_objects'] > 0:
            self.logger.warning(
                "tlp_filter_applied",
                filtered=stats['filtered_objects'],
                total=stats['total_objects'],
                reasons=stats['filter_reasons']
            )

        # If strict mode filtered everything, return error
        if not reports and stats['total_objects'] > 0:
            return [TextContent(
                type="text",
                text=(
                    f"⚠️ **TLP Policy Violation**\n\n"
                    f"All {stats['total_objects']} reports were filtered due to TLP restrictions.\n\n"
                    f"**Filtered Reasons:**\n"
                    + "\n".join([f"- {reason}: {count}" for reason, count in stats['filter_reasons'].items()])
                    + "\n\n"
                    f"**Current Policy:** Only TLP:CLEAR data is sent to Claude by default.\n\n"
                    f"Review `config/tlp_policy.yaml` for guidance.\n"
                )
            )]

        # Count report types
        type_counts = {}
        for report in reports:
            for rtype in report.get('report_types', ['unknown']):
                type_counts[rtype] = type_counts.get(rtype, 0) + 1

        # Format output
        output = (
            f"# Threat Intelligence Reports\n\n"
            f"**Total Reports:** {len(reports)}\n"
        )

        if search_term:
            output += f"**Search Term:** {search_term}\n"

        if published_after:
            output += f"**Published After:** {published_after}\n"

        if min_confidence > 0:
            output += f"**Minimum Confidence:** {min_confidence}%\n"

        if type_counts:
            output += "\n**Report Types:**\n"
            for rtype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                output += f"- {rtype}: {count}\n"

        output += "\n---\n\n"

        for idx, report in enumerate(reports, 1):
            output += f"## {idx}. {report.get('name', 'Unknown Report')}\n\n"

            published = report.get('published')
            if published:
                output += f"- **Published:** {published}\n"

            confidence = report.get('confidence', 0)
            output += f"- **Confidence:** {confidence}%\n"

            rtypes = report.get('report_types', [])
            if rtypes:
                output += f"- **Report Types:** {', '.join(rtypes)}\n"

            labels = report.get('labels', [])
            if labels:
                output += f"- **Labels:** {', '.join(labels[:5])}\n"

            obj_refs_count = report.get('object_refs_count', 0)
            if obj_refs_count > 0:
                output += f"- **Referenced Entities:** {obj_refs_count}\n"

            description = report.get('description', '')
            if description and description != 'No description available':
                # Truncate long descriptions
                desc_preview = description[:300]
                if len(description) > 300:
                    desc_preview += "..."
                output += f"- **Description:** {desc_preview}\n"

            output += "\n"

        output += (
            "---\n\n"
            "💡 **Tip:** Reports provide narrative analysis and context that ties together "
            "multiple threat intelligence entities. Use the entity IDs from reports to "
            "explore related threat actors, campaigns, malware, and indicators.\n"
        )

        self.logger.info("reports_retrieved", count=len(reports))

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

            # Initialize marking registry for server-side TLP filtering (v0.4.0+)
            try:
                self.logger.info("initializing_marking_registry", message="Querying OpenCTI for marking definitions...")
                await self.opencti_client.initialize_marking_registry(self.tlp_filter)
                self.logger.info(
                    "marking_registry_ready",
                    message="Server-side TLP filtering enabled (40-60% performance improvement)"
                )
            except Exception as e:
                self.logger.warning(
                    "marking_registry_failed",
                    error=str(e),
                    message="Falling back to client-side filtering (v0.3.0 behavior)"
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
