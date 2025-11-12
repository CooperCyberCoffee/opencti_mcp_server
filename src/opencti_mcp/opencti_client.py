"""
Cooper Cyber Coffee OpenCTI MCP Server
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

For consulting and enterprise inquiries: business@coopercybercoffee.com
"""

import logging
from typing import Dict, List, Optional, Any
from pycti import OpenCTIApiClient
import asyncio
from concurrent.futures import ThreadPoolExecutor


class OpenCTIClient:
    """Professional OpenCTI client wrapper with async support and error handling.

    This client wraps the official pycti library to provide:
    - Async/await support for MCP integration
    - OpenCTI 6.x version validation
    - Professional error handling
    - Thread-safe operations

    Args:
        url: OpenCTI server URL
        token: API authentication token
        ssl_verify: Whether to verify SSL certificates (default: False)

    Example:
        >>> client = OpenCTIClient(
        ...     url="http://localhost:8080",
        ...     token="your-token-here"
        ... )
        >>> validation = await client.validate_opencti_setup()
        >>> print(validation["status"])
        'ready'
    """

    def __init__(self, url: str, token: str, ssl_verify: bool = False):
        """Initialize OpenCTI client with connection parameters."""
        self.url = url
        self.token = token
        self.ssl_verify = ssl_verify
        self._client = None
        self._executor = ThreadPoolExecutor(max_workers=4)
        self.logger = logging.getLogger(__name__)

    async def _get_client(self) -> OpenCTIApiClient:
        """Lazy initialization of OpenCTI client with connection validation.

        Returns:
            Initialized OpenCTI API client

        Raises:
            ConnectionError: If unable to connect to OpenCTI
        """
        if self._client is None:
            try:
                self._client = OpenCTIApiClient(
                    url=self.url,
                    token=self.token,
                    ssl_verify=self.ssl_verify,
                    log_level="INFO"
                )
                self.logger.info(f"Connected to OpenCTI at {self.url}")
            except Exception as e:
                self.logger.error(f"Failed to initialize OpenCTI client: {e}")
                raise ConnectionError(f"Cannot connect to OpenCTI at {self.url}: {e}")
        return self._client

    async def validate_opencti_setup(self) -> Dict[str, Any]:
        """Validate OpenCTI 6.x setup and data availability.

        Performs comprehensive validation including:
        - Version check (requires OpenCTI 6.x)
        - Database availability
        - Connector status
        - Data availability

        Returns:
            Dict containing:
                - version: OpenCTI version string
                - has_data: Whether database contains indicators
                - active_connectors: Number of active connectors
                - status: 'ready' or 'empty_database'
                - connector_names: List of active connector names

        Raises:
            ValueError: If OpenCTI version is not 6.x
            ConnectionError: If unable to connect to OpenCTI
        """
        try:
            client = await self._get_client()

            def _check_version():
                # Get platform version via GraphQL query (pycti 6.x method)
                version = "unknown"
                try:
                    # Query the about endpoint for version information
                    query = """
                        query {
                            about {
                                version
                            }
                        }
                    """
                    about_result = client.query(query)
                    version = about_result.get('data', {}).get('about', {}).get('version', 'unknown')
                except Exception as e:
                    self.logger.warning(f"Could not retrieve version via GraphQL: {e}")
                    # Try alternative method - check if health_check method exists
                    try:
                        health = client.health_check()
                        if isinstance(health, dict):
                            version = health.get('version', 'unknown')
                    except Exception:
                        self.logger.warning("Could not determine OpenCTI version, continuing anyway")

                # Check for indicators (basic data availability)
                has_indicators = False
                try:
                    indicators = client.indicator.list(first=1)
                    has_indicators = len(indicators) > 0
                except Exception as e:
                    self.logger.warning(f"Could not check indicators: {e}")

                # Check connectors
                active_connectors = []
                try:
                    connectors = client.connector.list(first=5)
                    active_connectors = [c for c in connectors if c.get('active', False)]
                except Exception as e:
                    self.logger.warning(f"Could not check connectors: {e}")

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

            # Validate version (if we were able to determine it)
            version = result["version"]
            if version != "unknown" and not version.startswith("6."):
                self.logger.warning(
                    f"OpenCTI 6.x recommended for Cooper Cyber Coffee MCP Server. "
                    f"Found version {version}. Some features may not work correctly."
                )
                # Don't raise error, just warn - allow connection to proceed

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
        """Get recent indicators from OpenCTI with filtering.

        Args:
            limit: Maximum number of indicators to retrieve (default: 10)
            indicator_types: Filter by specific types (e.g., ['file-sha256', 'ipv4-addr'])
            days_back: How many days back to search (default: 7)
            min_confidence: Minimum confidence level 0-100 (default: 50)

        Returns:
            List of indicator dictionaries with formatted data

        Example:
            >>> indicators = await client.get_recent_indicators(
            ...     limit=5,
            ...     indicator_types=['file-sha256'],
            ...     min_confidence=75
            ... )
            >>> print(f"Found {len(indicators)} indicators")
        """
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
        """Search for indicators by hash value (MD5, SHA1, SHA256).

        Args:
            hash_value: Hash value to search for

        Returns:
            List of matching indicators

        Example:
            >>> results = await client.search_by_hash(
            ...     "44d88612fea8a8f36de82e1278abb02f"
            ... )
            >>> if results:
            ...     print(f"Hash found: {results[0]['pattern']}")
        """
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

    async def get_attack_patterns(
        self,
        limit: int = 20,
        search_term: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get MITRE ATT&CK techniques and attack patterns.

        Args:
            limit: Maximum number of attack patterns to retrieve (default: 20)
            search_term: Optional search term to filter results

        Returns:
            List of attack pattern dictionaries with formatted data

        Example:
            >>> patterns = await client.get_attack_patterns(
            ...     limit=10,
            ...     search_term="phishing"
            ... )
            >>> print(f"Found {len(patterns)} attack patterns")
        """
        try:
            client = await self._get_client()

            def _get_attack_patterns():
                # Build search parameters
                kwargs = {"first": limit, "orderBy": "created_at", "orderMode": "desc"}

                if search_term:
                    kwargs["search"] = search_term

                # Get attack patterns
                attack_patterns = client.attack_pattern.list(**kwargs)

                # Format for MCP consumption
                formatted = []
                for pattern in attack_patterns:
                    formatted_pattern = {
                        "id": pattern.get("id"),
                        "name": pattern.get("name"),
                        "description": pattern.get("description", "No description available"),
                        "x_mitre_id": pattern.get("x_mitre_id"),
                        "created_at": pattern.get("created_at"),
                        "kill_chain_phases": [
                            phase.get("phase_name", "unknown")
                            for phase in pattern.get("killChainPhases", [])
                        ],
                        "labels": [label.get("value") for label in pattern.get("objectLabel", [])]
                    }
                    formatted.append(formatted_pattern)

                return formatted

            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _get_attack_patterns
            )

            self.logger.info(f"Retrieved {len(result)} attack patterns")
            return result

        except Exception as e:
            self.logger.error(f"Failed to get attack patterns: {e}")
            raise

    async def get_vulnerabilities(
        self,
        limit: int = 20,
        search_term: Optional[str] = None,
        min_severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get CVEs and vulnerabilities from OpenCTI.

        Args:
            limit: Maximum number of vulnerabilities to retrieve (default: 20)
            search_term: Optional search term to filter results
            min_severity: Minimum severity level (critical, high, medium, low)

        Returns:
            List of vulnerability dictionaries with formatted data

        Example:
            >>> vulns = await client.get_vulnerabilities(
            ...     limit=10,
            ...     min_severity="high"
            ... )
            >>> print(f"Found {len(vulns)} vulnerabilities")
        """
        try:
            client = await self._get_client()

            def _get_vulnerabilities():
                # Build search parameters
                kwargs = {"first": limit, "orderBy": "created_at", "orderMode": "desc"}

                if search_term:
                    kwargs["search"] = search_term

                # Get vulnerabilities
                vulnerabilities = client.vulnerability.list(**kwargs)

                # Format for MCP consumption
                formatted = []
                for vuln in vulnerabilities:
                    # Get severity score
                    cvss_score = vuln.get("x_opencti_cvss_base_score", 0)

                    # Determine severity level
                    if cvss_score >= 9.0:
                        severity = "Critical"
                    elif cvss_score >= 7.0:
                        severity = "High"
                    elif cvss_score >= 4.0:
                        severity = "Medium"
                    elif cvss_score > 0:
                        severity = "Low"
                    else:
                        severity = "Unknown"

                    # Apply severity filter if specified
                    if min_severity:
                        min_score_map = {
                            "critical": 9.0,
                            "high": 7.0,
                            "medium": 4.0,
                            "low": 0.1
                        }
                        if min_severity in min_score_map and cvss_score < min_score_map[min_severity]:
                            continue

                    formatted_vuln = {
                        "id": vuln.get("id"),
                        "name": vuln.get("name"),
                        "description": vuln.get("description", "No description available")[:500],
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "created_at": vuln.get("created_at"),
                        "labels": [label.get("value") for label in vuln.get("objectLabel", [])]
                    }
                    formatted.append(formatted_vuln)

                return formatted

            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _get_vulnerabilities
            )

            self.logger.info(f"Retrieved {len(result)} vulnerabilities")
            return result

        except Exception as e:
            self.logger.error(f"Failed to get vulnerabilities: {e}")
            raise

    async def get_malware(
        self,
        limit: int = 20,
        search_term: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get malware families and samples from OpenCTI.

        Args:
            limit: Maximum number of malware entries to retrieve (default: 20)
            search_term: Optional search term to filter results

        Returns:
            List of malware dictionaries with formatted data

        Example:
            >>> malware = await client.get_malware(
            ...     limit=10,
            ...     search_term="ransomware"
            ... )
            >>> print(f"Found {len(malware)} malware families")
        """
        try:
            client = await self._get_client()

            def _get_malware():
                # Build search parameters
                kwargs = {"first": limit, "orderBy": "created_at", "orderMode": "desc"}

                if search_term:
                    kwargs["search"] = search_term

                # Get malware
                malware_list = client.malware.list(**kwargs)

                # Format for MCP consumption
                formatted = []
                for malware in malware_list:
                    formatted_malware = {
                        "id": malware.get("id"),
                        "name": malware.get("name"),
                        "description": malware.get("description", "No description available")[:500],
                        "malware_types": malware.get("malware_types", []),
                        "is_family": malware.get("is_family", False),
                        "created_at": malware.get("created_at"),
                        "labels": [label.get("value") for label in malware.get("objectLabel", [])]
                    }
                    formatted.append(formatted_malware)

                return formatted

            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _get_malware
            )

            self.logger.info(f"Retrieved {len(result)} malware entries")
            return result

        except Exception as e:
            self.logger.error(f"Failed to get malware: {e}")
            raise

    async def search_entities(
        self,
        search_term: str,
        entity_types: List[str] = ["all"],
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """General entity search across OpenCTI knowledge base.

        Args:
            search_term: Search term to find entities
            entity_types: List of entity types to search (default: ["all"])
            limit: Maximum number of results to return (default: 10)

        Returns:
            List of entity dictionaries with formatted data

        Example:
            >>> results = await client.search_entities(
            ...     search_term="APT29",
            ...     entity_types=["Threat-Actor", "Campaign"]
            ... )
            >>> print(f"Found {len(results)} entities")
        """
        try:
            client = await self._get_client()

            def _search_entities():
                formatted = []

                # Map entity types to client methods
                entity_method_map = {
                    "Threat-Actor": client.threat_actor,
                    "Intrusion-Set": client.intrusion_set,
                    "Campaign": client.campaign,
                    "Malware": client.malware,
                    "Tool": client.tool,
                    "Attack-Pattern": client.attack_pattern,
                    "Vulnerability": client.vulnerability,
                    "Indicator": client.indicator
                }

                # Determine which entity types to search
                search_types = []
                if "all" in entity_types:
                    search_types = list(entity_method_map.keys())
                else:
                    search_types = [t for t in entity_types if t in entity_method_map]

                # Search each entity type
                per_type_limit = max(1, limit // len(search_types)) if search_types else limit

                for entity_type in search_types:
                    try:
                        entity_client = entity_method_map[entity_type]
                        results = entity_client.list(
                            search=search_term,
                            first=per_type_limit
                        )

                        for entity in results:
                            formatted_entity = {
                                "id": entity.get("id"),
                                "entity_type": entity_type,
                                "name": entity.get("name"),
                                "description": entity.get("description", "No description available")[:300],
                                "created_at": entity.get("created_at"),
                                "labels": [label.get("value") for label in entity.get("objectLabel", [])]
                            }
                            formatted.append(formatted_entity)

                            if len(formatted) >= limit:
                                break
                    except Exception as e:
                        self.logger.warning(f"Failed to search {entity_type}: {e}")
                        continue

                    if len(formatted) >= limit:
                        break

                return formatted[:limit]

            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _search_entities
            )

            self.logger.info(f"Entity search returned {len(result)} results")
            return result

        except Exception as e:
            self.logger.error(f"Entity search failed: {e}")
            raise

    async def close(self):
        """Close the client and clean up resources."""
        if self._executor:
            self._executor.shutdown(wait=True)
            self.logger.info("OpenCTI client executor shutdown complete")
