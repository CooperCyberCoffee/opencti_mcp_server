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
                # Build FilterGroup for OpenCTI 6.x
                filter_list = []

                if indicator_types:
                    # Convert to OpenCTI filter format
                    type_filter = {
                        "key": "indicator_types",
                        "values": indicator_types,
                        "operator": "eq",
                        "mode": "or"
                    }
                    filter_list.append(type_filter)

                if min_confidence > 0:
                    confidence_filter = {
                        "key": "confidence",
                        "values": [str(min_confidence)],
                        "operator": "gte",
                        "mode": "or"
                    }
                    filter_list.append(confidence_filter)

                # Construct FilterGroup structure for OpenCTI 6.x
                filters = None
                if filter_list:
                    filters = {
                        "mode": "and",
                        "filters": filter_list,
                        "filterGroups": []
                    }

                self.logger.info(f"[DEBUG] get_recent_indicators filters: {filters}")

                # Get indicators
                indicators = client.indicator.list(
                    first=limit,
                    filters=filters,
                    orderBy="created_at",
                    orderMode="desc"
                )

                self.logger.info(f"[DEBUG] indicator.list returned {len(indicators) if indicators else 0} results")

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

    async def get_threat_actor_ttps(
        self,
        actor_name: str,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Get attack patterns (TTPs) used by a threat actor or intrusion set.

        Args:
            actor_name: Threat actor/intrusion set name or ID
            limit: Maximum number of attack patterns to return

        Returns:
            Dictionary containing actor info and associated attack patterns

        Example:
            >>> ttps = await client.get_threat_actor_ttps("APT29")
            >>> print(f"Found {len(ttps['attack_patterns'])} techniques")
        """
        try:
            self.logger.info(f"[DEBUG] get_threat_actor_ttps called with: '{actor_name}'")

            # Step 1: Get entity ID (either from input or by searching)
            actor_id = None
            resolved_actor_name = actor_name

            if not actor_name.startswith("intrusion-set--") and not actor_name.startswith("threat-actor--"):
                self.logger.info(f"[DEBUG] Not an ID, using search_entities to find actor: '{actor_name}'")

                # Use search_entities to find the threat actor (same method that works for user)
                search_results = await self.search_entities(
                    search_term=actor_name,
                    entity_types=["Intrusion-Set", "Threat-Actor"],
                    limit=1
                )

                self.logger.info(f"[DEBUG] search_entities returned {len(search_results)} results")

                if search_results:
                    actor_id = search_results[0]["id"]
                    resolved_actor_name = search_results[0]["name"]
                    self.logger.info(f"[DEBUG] Found actor via search_entities: id={actor_id}, name={resolved_actor_name}")
                else:
                    self.logger.error(f"[DEBUG] search_entities found no results for '{actor_name}'")
                    return {
                        "actor_name": actor_name,
                        "actor_id": None,
                        "found": False,
                        "attack_patterns": [],
                        "error": f"No threat actor found matching '{actor_name}'",
                        "searched_for": actor_name,
                        "suggestion": "Try search_entities tool first to verify the actor exists and get the correct name"
                    }
            else:
                actor_id = actor_name
                self.logger.info(f"[DEBUG] Input is already an ID: {actor_id}")

            self.logger.info(f"[DEBUG] Proceeding with GraphQL query for actor_id: {actor_id}")

            # Step 2: Query relationships using GraphQL
            client = await self._get_client()

            def _query_actor_ttps():

                # GraphQL query to get attack patterns
                query = """
                    query GetActorTTPs($id: String!) {
                        stixDomainObject(id: $id) {
                            ... on IntrusionSet {
                                id
                                name
                                description
                                attackPatterns {
                                    edges {
                                        node {
                                            id
                                            name
                                            description
                                            x_mitre_id
                                            killChainPhases {
                                                phase_name
                                            }
                                        }
                                    }
                                }
                            }
                            ... on ThreatActor {
                                id
                                name
                                description
                                attackPatterns {
                                    edges {
                                        node {
                                            id
                                            name
                                            description
                                            x_mitre_id
                                            killChainPhases {
                                                phase_name
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                """

                try:
                    self.logger.info(f"[DEBUG] Executing GraphQL query with id: {actor_id}")
                    result = client.query(query, {"id": actor_id})
                    self.logger.info(f"[DEBUG] GraphQL result keys: {result.keys() if result else 'None'}")

                    data = result.get("data", {}).get("stixDomainObject", {})
                    self.logger.info(f"[DEBUG] stixDomainObject data: {data}")

                    if not data:
                        self.logger.warning(f"[DEBUG] No stixDomainObject data returned for id: {actor_id}")
                        return {
                            "actor_name": resolved_actor_name,
                            "actor_id": actor_id,
                            "found": False,
                            "attack_patterns": []
                        }

                    # Extract attack patterns
                    patterns = []
                    attack_patterns_data = data.get("attackPatterns", {})
                    self.logger.info(f"[DEBUG] attackPatterns data type: {type(attack_patterns_data)}")
                    edges = attack_patterns_data.get("edges", []) if attack_patterns_data else []
                    self.logger.info(f"[DEBUG] Found {len(edges)} attack pattern edges")

                    for edge in edges[:limit]:
                        node = edge.get("node", {})
                        patterns.append({
                            "id": node.get("id"),
                            "name": node.get("name"),
                            "description": node.get("description", "")[:500],
                            "x_mitre_id": node.get("x_mitre_id"),
                            "kill_chain_phases": [
                                phase.get("phase_name")
                                for phase in node.get("killChainPhases", [])
                            ]
                        })

                    return {
                        "actor_name": data.get("name", resolved_actor_name),
                        "actor_id": actor_id,
                        "actor_description": data.get("description", ""),
                        "found": True,
                        "attack_patterns": patterns
                    }

                except Exception as e:
                    self.logger.warning(f"GraphQL query failed, falling back: {e}")
                    return {
                        "actor_name": resolved_actor_name,
                        "actor_id": actor_id,
                        "found": False,
                        "attack_patterns": [],
                        "error": str(e)
                    }

            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _query_actor_ttps
            )

            self.logger.info(f"Retrieved {len(result.get('attack_patterns', []))} TTPs for {actor_name}")
            return result

        except Exception as e:
            self.logger.error(f"Failed to get threat actor TTPs: {e}")
            raise

    async def get_malware_techniques(
        self,
        malware_name: str,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Get attack patterns used by malware and associated threat actors.

        Args:
            malware_name: Malware name or ID
            limit: Maximum number of results to return

        Returns:
            Dictionary containing malware info and associated techniques

        Example:
            >>> techniques = await client.get_malware_techniques("Emotet")
            >>> print(f"Found {len(techniques['attack_patterns'])} techniques")
        """
        try:
            self.logger.info(f"[DEBUG] get_malware_techniques called with: '{malware_name}'")

            # Step 1: Get entity ID (either from input or by searching)
            malware_id = None
            resolved_malware_name = malware_name

            if not malware_name.startswith("malware--"):
                self.logger.info(f"[DEBUG] Not an ID, using search_entities to find malware: '{malware_name}'")

                # Use search_entities to find the malware
                search_results = await self.search_entities(
                    search_term=malware_name,
                    entity_types=["Malware"],
                    limit=1
                )

                self.logger.info(f"[DEBUG] search_entities returned {len(search_results)} results")

                if search_results:
                    malware_id = search_results[0]["id"]
                    resolved_malware_name = search_results[0]["name"]
                    self.logger.info(f"[DEBUG] Found malware via search_entities: id={malware_id}, name={resolved_malware_name}")
                else:
                    self.logger.error(f"[DEBUG] search_entities found no results for '{malware_name}'")
                    return {
                        "malware_name": malware_name,
                        "malware_id": None,
                        "found": False,
                        "attack_patterns": [],
                        "threat_actors": [],
                        "error": f"No malware found matching '{malware_name}'",
                        "searched_for": malware_name,
                        "suggestion": "Try search_entities or get_malware tool first to verify the malware exists"
                    }
            else:
                malware_id = malware_name
                self.logger.info(f"[DEBUG] Input is already an ID: {malware_id}")

            self.logger.info(f"[DEBUG] Proceeding with GraphQL query for malware_id: {malware_id}")

            # Step 2: Query relationships using GraphQL
            client = await self._get_client()

            def _query_malware_techniques():

                # GraphQL query for malware techniques and threat actors
                query = """
                    query GetMalwareTechniques($id: String!) {
                        malware(id: $id) {
                            id
                            name
                            description
                            malware_types
                            attackPatterns {
                                edges {
                                    node {
                                        id
                                        name
                                        description
                                        x_mitre_id
                                        killChainPhases {
                                            phase_name
                                        }
                                    }
                                }
                            }
                        }
                    }
                """

                try:
                    self.logger.info(f"[DEBUG] Executing GraphQL query with id: {malware_id}")
                    result = client.query(query, {"id": malware_id})
                    self.logger.info(f"[DEBUG] GraphQL result keys: {result.keys() if result else 'None'}")

                    data = result.get("data", {}).get("malware", {})
                    self.logger.info(f"[DEBUG] malware data: {data}")

                    if not data:
                        self.logger.warning(f"[DEBUG] No malware data returned for id: {malware_id}")
                        return {
                            "malware_name": resolved_malware_name,
                            "malware_id": malware_id,
                            "found": False,
                            "attack_patterns": [],
                            "threat_actors": []
                        }

                    # Extract attack patterns
                    patterns = []
                    attack_patterns_data = data.get("attackPatterns", {})
                    self.logger.info(f"[DEBUG] attackPatterns data type: {type(attack_patterns_data)}")
                    edges = attack_patterns_data.get("edges", []) if attack_patterns_data else []
                    self.logger.info(f"[DEBUG] Found {len(edges)} attack pattern edges")

                    for edge in edges[:limit]:
                        node = edge.get("node", {})
                        patterns.append({
                            "id": node.get("id"),
                            "name": node.get("name"),
                            "description": node.get("description", "")[:500],
                            "x_mitre_id": node.get("x_mitre_id"),
                            "kill_chain_phases": [
                                phase.get("phase_name")
                                for phase in node.get("killChainPhases", [])
                            ]
                        })

                    return {
                        "malware_name": data.get("name", resolved_malware_name),
                        "malware_id": malware_id,
                        "malware_description": data.get("description", ""),
                        "malware_types": data.get("malware_types", []),
                        "found": True,
                        "attack_patterns": patterns,
                        "threat_actors": []  # Could be extended with additional query
                    }

                except Exception as e:
                    self.logger.warning(f"GraphQL query failed, falling back: {e}")
                    return {
                        "malware_name": resolved_malware_name,
                        "malware_id": malware_id,
                        "found": False,
                        "attack_patterns": [],
                        "threat_actors": [],
                        "error": str(e)
                    }

            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _query_malware_techniques
            )

            self.logger.info(f"Retrieved {len(result.get('attack_patterns', []))} techniques for malware {malware_name}")
            return result

        except Exception as e:
            self.logger.error(f"Failed to get malware techniques: {e}")
            raise

    async def get_campaign_details(
        self,
        campaign_name: str
    ) -> Dict[str, Any]:
        """Get comprehensive campaign details with full relationship graph.

        Args:
            campaign_name: Campaign name or ID

        Returns:
            Dictionary containing campaign details and all relationships

        Example:
            >>> campaign = await client.get_campaign_details("Operation X")
            >>> print(f"Campaign has {len(campaign['threat_actors'])} threat actors")
        """
        try:
            self.logger.info(f"[DEBUG] get_campaign_details called with: '{campaign_name}'")

            # Step 1: Get entity ID (either from input or by searching)
            campaign_id = None
            resolved_campaign_name = campaign_name

            if not campaign_name.startswith("campaign--"):
                self.logger.info(f"[DEBUG] Not an ID, using search_entities to find campaign: '{campaign_name}'")

                # Use search_entities to find the campaign
                search_results = await self.search_entities(
                    search_term=campaign_name,
                    entity_types=["Campaign"],
                    limit=1
                )

                self.logger.info(f"[DEBUG] search_entities returned {len(search_results)} results")

                if search_results:
                    campaign_id = search_results[0]["id"]
                    resolved_campaign_name = search_results[0]["name"]
                    self.logger.info(f"[DEBUG] Found campaign via search_entities: id={campaign_id}, name={resolved_campaign_name}")
                else:
                    self.logger.error(f"[DEBUG] search_entities found no results for '{campaign_name}'")
                    return {
                        "campaign_name": campaign_name,
                        "campaign_id": None,
                        "found": False,
                        "threat_actors": [],
                        "attack_patterns": [],
                        "malware": [],
                        "targets": [],
                        "error": f"No campaign found matching '{campaign_name}'",
                        "searched_for": campaign_name,
                        "suggestion": "Try search_entities tool first to verify the campaign exists"
                    }
            else:
                campaign_id = campaign_name
                self.logger.info(f"[DEBUG] Input is already an ID: {campaign_id}")

            self.logger.info(f"[DEBUG] Proceeding with GraphQL query for campaign_id: {campaign_id}")

            # Step 2: Query relationships using GraphQL
            client = await self._get_client()

            def _query_campaign_details():
                # GraphQL query for campaign relationships
                query = """
                    query GetCampaignDetails($id: String!) {
                        campaign(id: $id) {
                            id
                            name
                            description
                            first_seen
                            last_seen
                            attackPatterns {
                                edges {
                                    node {
                                        id
                                        name
                                        x_mitre_id
                                    }
                                }
                            }
                        }
                    }
                """

                try:
                    result = client.query(query, {"id": campaign_id})
                    data = result.get("data", {}).get("campaign", {})

                    if not data:
                        return {
                            "campaign_name": campaign_name,
                            "campaign_id": campaign_id,
                            "found": False,
                            "threat_actors": [],
                            "attack_patterns": [],
                            "malware": [],
                            "targets": []
                        }

                    # Extract attack patterns
                    patterns = []
                    attack_patterns_data = data.get("attackPatterns", {}).get("edges", [])

                    for edge in attack_patterns_data:
                        node = edge.get("node", {})
                        patterns.append({
                            "id": node.get("id"),
                            "name": node.get("name"),
                            "x_mitre_id": node.get("x_mitre_id")
                        })

                    return {
                        "campaign_name": data.get("name", resolved_campaign_name),
                        "campaign_id": campaign_id,
                        "campaign_description": data.get("description", ""),
                        "first_seen": data.get("first_seen"),
                        "last_seen": data.get("last_seen"),
                        "found": True,
                        "threat_actors": [],  # Could be extended
                        "attack_patterns": patterns,
                        "malware": [],  # Could be extended
                        "targets": []  # Could be extended
                    }

                except Exception as e:
                    self.logger.warning(f"GraphQL query failed: {e}")
                    return {
                        "campaign_name": resolved_campaign_name,
                        "campaign_id": campaign_id,
                        "found": False,
                        "threat_actors": [],
                        "attack_patterns": [],
                        "malware": [],
                        "targets": [],
                        "error": str(e)
                    }

            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _query_campaign_details
            )

            self.logger.info(f"Retrieved campaign details for {campaign_name}")
            return result

        except Exception as e:
            self.logger.error(f"Failed to get campaign details: {e}")
            raise

    async def get_entity_relationships(
        self,
        entity_id: str,
        relationship_type: Optional[str] = None,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Get relationships for any entity type.

        Args:
            entity_id: Entity ID to query relationships for
            relationship_type: Optional filter (uses, targets, indicates, related-to)
            limit: Maximum number of relationships to return

        Returns:
            Dictionary containing entity info and list of related entities

        Example:
            >>> rels = await client.get_entity_relationships(
            ...     "threat-actor--xyz",
            ...     relationship_type="uses"
            ... )
        """
        try:
            client = await self._get_client()

            def _get_relationships():
                try:
                    # Use GraphQL to query relationships with target entity details
                    query = """
                        query GetEntityRelationships($id: String!) {
                            stixDomainObject(id: $id) {
                                id
                                entity_type
                                ... on StixDomainObject {
                                    name
                                    stixCoreRelationships {
                                        edges {
                                            node {
                                                id
                                                relationship_type
                                                from {
                                                    ... on BasicObject {
                                                        id
                                                        entity_type
                                                    }
                                                    ... on StixDomainObject {
                                                        name
                                                        description
                                                    }
                                                }
                                                to {
                                                    ... on BasicObject {
                                                        id
                                                        entity_type
                                                    }
                                                    ... on StixDomainObject {
                                                        name
                                                        description
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    """

                    result = client.query(query, {"id": entity_id})
                    data = result.get("data", {}).get("stixDomainObject", {})

                    if not data:
                        return None

                    entity_name = data.get("name", "Unknown")
                    entity_type = data.get("entity_type", "Unknown")

                    relationships = []
                    edges = data.get("stixCoreRelationships", {}).get("edges", [])

                    for edge in edges[:limit]:
                        node = edge.get("node", {})
                        rel_type = node.get("relationship_type")

                        # Filter by relationship type if specified
                        if relationship_type and rel_type != relationship_type:
                            continue

                        from_entity = node.get("from", {})
                        to_entity = node.get("to", {})

                        # Determine target entity (the one that's not the source entity)
                        target = to_entity if from_entity.get("id") == entity_id else from_entity

                        relationships.append({
                            "relationship_id": node.get("id"),
                            "relationship_type": rel_type,
                            "target": {
                                "id": target.get("id"),
                                "entity_type": target.get("entity_type", "Unknown"),
                                "name": target.get("name", "Unknown"),
                                "description": target.get("description", "")
                            }
                        })

                    return {
                        "entity_id": entity_id,
                        "entity_name": entity_name,
                        "entity_type": entity_type,
                        "relationships": relationships
                    }

                except Exception as e:
                    self.logger.warning(f"GraphQL relationship query failed: {e}")
                    return None

            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _get_relationships
            )

            if result:
                self.logger.info(f"Retrieved {len(result.get('relationships', []))} relationships for {entity_id}")
            return result

        except Exception as e:
            self.logger.error(f"Failed to get entity relationships: {e}")
            raise

    async def close(self):
        """Close the client and clean up resources."""
        if self._executor:
            self._executor.shutdown(wait=True)
            self.logger.info("OpenCTI client executor shutdown complete")
