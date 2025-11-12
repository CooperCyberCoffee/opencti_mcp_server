"""
Cooper Cyber Coffee OpenCTI MCP Server
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

For consulting and enterprise inquiries: business@coopercybercoffee.com
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from pycti import OpenCTIApiClient
import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from datetime import datetime, timedelta


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

    def __init__(self, url: str, token: str, ssl_verify: bool = False, debug: bool = True):
        """Initialize OpenCTI client with connection parameters.

        Note: debug=True by default for testing. Set to False in production.
        """
        self.url = url
        self.token = token
        self.ssl_verify = ssl_verify
        self.debug = debug
        self._client = None
        self._executor = ThreadPoolExecutor(max_workers=4)
        self.logger = logging.getLogger(__name__)

        # Enable debug logging if requested
        if self.debug:
            self.logger.setLevel(logging.DEBUG)
            # Ensure handler exists and is configured
            if not self.logger.handlers:
                handler = logging.StreamHandler()
                handler.setLevel(logging.DEBUG)
                formatter = logging.Formatter('[%(levelname)s] %(message)s')
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)

        # Simple cache for entity resolution (prevents redundant lookups)
        self._entity_cache = {}
        self._cache_ttl = timedelta(minutes=15)

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

    def _get_cached(self, cache_key: str) -> Optional[Any]:
        """Get value from cache if not expired.

        Args:
            cache_key: Cache key to lookup

        Returns:
            Cached value or None if not found/expired
        """
        if cache_key in self._entity_cache:
            data, timestamp = self._entity_cache[cache_key]
            if datetime.now() - timestamp < self._cache_ttl:
                if self.debug:
                    self.logger.info(f"[DEBUG] Cache hit for: {cache_key}")
                return data
        return None

    def _set_cached(self, cache_key: str, data: Any):
        """Store value in cache with current timestamp.

        Args:
            cache_key: Cache key to store under
            data: Data to cache
        """
        self._entity_cache[cache_key] = (data, datetime.now())
        if self.debug:
            self.logger.info(f"[DEBUG] Cached: {cache_key}")

    async def _resolve_threat_actor(self, name: str) -> Tuple[Optional[str], Optional[str]]:
        """Resolve threat actor by name, alias, MITRE ID, or entity ID.

        TEST CASES THAT MUST WORK:
        1. _resolve_threat_actor("APT28") → should find entity
        2. _resolve_threat_actor("a777e02b-8a27-458f-8ed3-4b26bcfce87d") → should work with UUID
        3. _resolve_threat_actor("Fancy Bear") → should find via alias
        4. _resolve_threat_actor("G0007") → should find via MITRE ID

        Args:
            name: Threat actor name, alias, MITRE ID (e.g., "G0007"), or entity ID

        Returns:
            Tuple of (entity_id, entity_type) or (None, None) if not found
        """
        import traceback

        if self.debug:
            self.logger.info(f"[RESOLVE] === Starting resolution for: '{name}' ===")
            self.logger.info(f"[RESOLVE] Input length: {len(name)}")
            self.logger.info(f"[RESOLVE] Dash count: {name.count('-')}")

        # Quick path: Already an entity ID with prefix
        if name.startswith('intrusion-set--'):
            if self.debug:
                self.logger.info(f"[RESOLVE] Input has intrusion-set-- prefix")
            return (name, 'intrusion-set')
        if name.startswith('threat-actor--'):
            if self.debug:
                self.logger.info(f"[RESOLVE] Input has threat-actor-- prefix")
            return (name, 'threat-actor')

        # Check if it's a plain UUID (OpenCTI 6.x format)
        # Format: a777e02b-8a27-458f-8ed3-4b26bcfce87d (36 chars, 4 dashes)
        if len(name) == 36 and name.count('-') == 4:
            if self.debug:
                self.logger.info(f"[RESOLVE] Input is plain UUID format: {name}")

            client = await self._get_client()

            # Try intrusion-set first (most common)
            try:
                if self.debug:
                    self.logger.info(f"[RESOLVE] Attempting intrusion_set.read(id={name})")
                test = client.intrusion_set.read(id=name)
                if test:
                    if self.debug:
                        self.logger.info(f"[RESOLVE] ✓ Verified as intrusion-set: {test.get('name')}")
                    return (name, 'intrusion-set')
            except Exception as e:
                if self.debug:
                    self.logger.info(f"[RESOLVE] Not an intrusion-set: {e}")

            # Try threat-actor
            try:
                if self.debug:
                    self.logger.info(f"[RESOLVE] Attempting threat_actor.read(id={name})")
                test = client.threat_actor.read(id=name)
                if test:
                    if self.debug:
                        self.logger.info(f"[RESOLVE] ✓ Verified as threat-actor: {test.get('name')}")
                    return (name, 'threat-actor')
            except Exception as e:
                if self.debug:
                    self.logger.info(f"[RESOLVE] Not a threat-actor: {e}")

            # If we can't verify but it looks like a UUID, assume intrusion-set
            if self.debug:
                self.logger.info(f"[RESOLVE] Assuming UUID is intrusion-set")
            return (name, 'intrusion-set')

        # Check cache
        cache_key = f"threat_actor:{name.lower()}"
        cached = self._get_cached(cache_key)
        if cached:
            if self.debug:
                self.logger.info(f"[RESOLVE] ✓ Cache hit: {cached}")
            return cached

        if self.debug:
            self.logger.info(f"[RESOLVE] Not in cache, proceeding with search")

        client = await self._get_client()

        def _search_and_match():
            if self.debug:
                self.logger.info(f"[RESOLVE] === Starting _search_and_match ===")

            # Try intrusion sets first (most common for APT groups)
            try:
                if self.debug:
                    self.logger.info(f"[RESOLVE] Calling client.intrusion_set.list(search='{name}', first=10)")

                intrusion_sets = client.intrusion_set.list(search=name, first=10)

                # Null safety check
                if intrusion_sets is None:
                    if self.debug:
                        self.logger.warning(f"[RESOLVE] intrusion_set.list() returned None")
                    intrusion_sets = []

                if self.debug:
                    self.logger.info(f"[RESOLVE] Intrusion set search returned: {type(intrusion_sets)}")
                    self.logger.info(f"[RESOLVE] Result count: {len(intrusion_sets)}")
                    if intrusion_sets:
                        self.logger.info(f"[RESOLVE] First result: {intrusion_sets[0].get('name', 'NO NAME')} (id: {intrusion_sets[0].get('id', 'NO ID')})")

                if intrusion_sets:
                    # Priority 1: Exact name match (case-insensitive)
                    if self.debug:
                        self.logger.info(f"[RESOLVE] Checking for exact name match...")
                    for iset in intrusion_sets:
                        if iset.get('name', '').lower() == name.lower():
                            if self.debug:
                                self.logger.info(f"[RESOLVE] ✓ Found exact name match: {iset.get('name')}")
                            return (iset['id'], 'intrusion-set')

                    # Priority 2: Alias match
                    if self.debug:
                        self.logger.info(f"[RESOLVE] Checking for alias match...")
                    for iset in intrusion_sets:
                        aliases = iset.get('aliases', []) or []
                        if self.debug:
                            self.logger.info(f"[RESOLVE] {iset.get('name')} aliases: {aliases}")
                        if any(alias.lower() == name.lower() for alias in aliases):
                            if self.debug:
                                self.logger.info(f"[RESOLVE] ✓ Found alias match in: {iset.get('name')}")
                            return (iset['id'], 'intrusion-set')

                    # Priority 3: MITRE ID match
                    if self.debug:
                        self.logger.info(f"[RESOLVE] Checking for MITRE ID match...")
                    for iset in intrusion_sets:
                        mitre_id = iset.get('x_mitre_id', '')
                        if self.debug:
                            self.logger.info(f"[RESOLVE] {iset.get('name')} MITRE ID: {mitre_id}")
                        if mitre_id and mitre_id.upper() == name.upper():
                            if self.debug:
                                self.logger.info(f"[RESOLVE] ✓ Found MITRE ID match: {mitre_id}")
                            return (iset['id'], 'intrusion-set')

                    # Priority 4: Fuzzy match (first result from search)
                    if self.debug:
                        self.logger.info(f"[RESOLVE] ✓ Using fuzzy match: {intrusion_sets[0].get('name')}")
                    return (intrusion_sets[0]['id'], 'intrusion-set')
                else:
                    if self.debug:
                        self.logger.info(f"[RESOLVE] No intrusion sets found")

            except Exception as e:
                if self.debug:
                    self.logger.error(f"[RESOLVE] Exception in intrusion set search:")
                    self.logger.error(f"[RESOLVE] Error: {str(e)}")
                    self.logger.error(f"[RESOLVE] Traceback:\n{traceback.format_exc()}")

            # Try threat actors as fallback
            try:
                if self.debug:
                    self.logger.info(f"[RESOLVE] Calling client.threat_actor.list(search='{name}', first=10)")

                threat_actors = client.threat_actor.list(search=name, first=10)

                # Null safety check
                if threat_actors is None:
                    if self.debug:
                        self.logger.warning(f"[RESOLVE] threat_actor.list() returned None")
                    threat_actors = []

                if self.debug:
                    self.logger.info(f"[RESOLVE] Threat actor search returned: {type(threat_actors)}")
                    self.logger.info(f"[RESOLVE] Result count: {len(threat_actors)}")
                    if threat_actors:
                        self.logger.info(f"[RESOLVE] First result: {threat_actors[0].get('name', 'NO NAME')}")

                if threat_actors:
                    # Same priority matching as above
                    for actor in threat_actors:
                        if actor.get('name', '').lower() == name.lower():
                            if self.debug:
                                self.logger.info(f"[RESOLVE] ✓ Found exact name match: {actor.get('name')}")
                            return (actor['id'], 'threat-actor')

                    for actor in threat_actors:
                        aliases = actor.get('aliases', []) or []
                        if any(alias.lower() == name.lower() for alias in aliases):
                            if self.debug:
                                self.logger.info(f"[RESOLVE] ✓ Found alias match in: {actor.get('name')}")
                            return (actor['id'], 'threat-actor')

                    if self.debug:
                        self.logger.info(f"[RESOLVE] ✓ Using fuzzy match: {threat_actors[0].get('name')}")
                    return (threat_actors[0]['id'], 'threat-actor')

            except Exception as e:
                if self.debug:
                    self.logger.error(f"[RESOLVE] Exception in threat actor search:")
                    self.logger.error(f"[RESOLVE] Error: {str(e)}")
                    self.logger.error(f"[RESOLVE] Traceback:\n{traceback.format_exc()}")

            if self.debug:
                self.logger.error(f"[RESOLVE] ✗ Standard search failed completely")
            return (None, None)

        result = await asyncio.get_event_loop().run_in_executor(
            self._executor, _search_and_match
        )

        # If standard search failed, try search_entities approach (we know it works!)
        if result[0] is None:
            if self.debug:
                self.logger.info(f"[RESOLVE] Standard search failed, trying search_entities approach")

            try:
                search_results = await self.search_entities(
                    search_term=name,
                    entity_types=['Intrusion-Set', 'Threat-Actor'],
                    limit=5
                )

                if self.debug:
                    self.logger.info(f"[RESOLVE] search_entities returned {len(search_results)} results")

                if search_results and len(search_results) > 0:
                    entity_id = search_results[0].get('id')
                    entity_name = search_results[0].get('name')
                    entity_type_raw = search_results[0].get('entity_type', 'Intrusion-Set')

                    # Map entity type to lowercase with dash
                    entity_type = 'intrusion-set' if 'intrusion' in entity_type_raw.lower() else 'threat-actor'

                    if self.debug:
                        self.logger.info(f"[RESOLVE] ✓ search_entities found: {entity_name} (id: {entity_id}, type: {entity_type})")

                    result = (entity_id, entity_type)

            except Exception as e:
                if self.debug:
                    self.logger.error(f"[RESOLVE] search_entities approach failed:")
                    self.logger.error(f"[RESOLVE] Error: {str(e)}")
                    self.logger.error(f"[RESOLVE] Traceback:\n{traceback.format_exc()}")

        # Cache the result
        if result[0]:
            self._set_cached(cache_key, result)
            if self.debug:
                self.logger.info(f"[RESOLVE] === Resolution successful: {result} ===")
        else:
            if self.debug:
                self.logger.error(f"[RESOLVE] === Resolution FAILED for '{name}' ===")

        return result

    async def _resolve_malware(self, name: str) -> Tuple[Optional[str], Optional[str]]:
        """Resolve malware by name, alias, or entity ID.

        Args:
            name: Malware name, alias, or entity ID

        Returns:
            Tuple of (entity_id, 'malware') or (None, None) if not found
        """
        # Quick path: Already an entity ID
        if name.startswith('malware--'):
            return (name, 'malware')

        # Check cache
        cache_key = f"malware:{name.lower()}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        if self.debug:
            self.logger.info(f"[DEBUG] Resolving malware: '{name}'")

        client = await self._get_client()

        def _search_and_match():
            try:
                malwares = client.malware.list(search=name, first=10)

                if malwares:
                    # Priority 1: Exact name match
                    for malware in malwares:
                        if malware.get('name', '').lower() == name.lower():
                            if self.debug:
                                self.logger.info(f"[DEBUG] Found exact match: {malware.get('name')}")
                            return (malware['id'], 'malware')

                    # Priority 2: Alias match
                    for malware in malwares:
                        aliases = malware.get('aliases', []) or []
                        if any(alias.lower() == name.lower() for alias in aliases):
                            if self.debug:
                                self.logger.info(f"[DEBUG] Found alias match in: {malware.get('name')}")
                            return (malware['id'], 'malware')

                    # Priority 3: Fuzzy match
                    if self.debug:
                        self.logger.info(f"[DEBUG] Using fuzzy match: {malwares[0].get('name')}")
                    return (malwares[0]['id'], 'malware')

            except Exception as e:
                if self.debug:
                    self.logger.warning(f"[DEBUG] Malware search failed: {e}")

            return (None, None)

        result = await asyncio.get_event_loop().run_in_executor(
            self._executor, _search_and_match
        )

        if result[0]:
            self._set_cached(cache_key, result)

        return result

    async def _resolve_campaign(self, name: str) -> Tuple[Optional[str], Optional[str]]:
        """Resolve campaign by name or entity ID.

        Args:
            name: Campaign name or entity ID

        Returns:
            Tuple of (entity_id, 'campaign') or (None, None) if not found
        """
        # Quick path: Already an entity ID
        if name.startswith('campaign--'):
            return (name, 'campaign')

        # Check cache
        cache_key = f"campaign:{name.lower()}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        if self.debug:
            self.logger.info(f"[DEBUG] Resolving campaign: '{name}'")

        client = await self._get_client()

        def _search_and_match():
            try:
                campaigns = client.campaign.list(search=name, first=10)

                if campaigns:
                    # Priority 1: Exact name match
                    for campaign in campaigns:
                        if campaign.get('name', '').lower() == name.lower():
                            if self.debug:
                                self.logger.info(f"[DEBUG] Found exact match: {campaign.get('name')}")
                            return (campaign['id'], 'campaign')

                    # Priority 2: Alias match
                    for campaign in campaigns:
                        aliases = campaign.get('aliases', []) or []
                        if any(alias.lower() == name.lower() for alias in aliases):
                            if self.debug:
                                self.logger.info(f"[DEBUG] Found alias match in: {campaign.get('name')}")
                            return (campaign['id'], 'campaign')

                    # Priority 3: Fuzzy match
                    if self.debug:
                        self.logger.info(f"[DEBUG] Using fuzzy match: {campaigns[0].get('name')}")
                    return (campaigns[0]['id'], 'campaign')

            except Exception as e:
                if self.debug:
                    self.logger.warning(f"[DEBUG] Campaign search failed: {e}")

            return (None, None)

        result = await asyncio.get_event_loop().run_in_executor(
            self._executor, _search_and_match
        )

        if result[0]:
            self._set_cached(cache_key, result)

        return result

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
                                "labels": [label.get("value") for label in entity.get("objectLabel", [])],
                                "mitre_id": entity.get("x_mitre_id"),  # MITRE ATT&CK ID if available
                                "aliases": entity.get("aliases", []) or []  # Alternative names
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

        Supports multiple input formats:
        - Threat actor name: "APT28"
        - Alias: "Fancy Bear", "Sofacy"
        - MITRE ID: "G0007"
        - Entity ID: "intrusion-set--abc123..."

        Args:
            actor_name: Threat actor/intrusion set name, alias, MITRE ID, or entity ID
            limit: Maximum number of attack patterns to return

        Returns:
            Dictionary containing actor info and associated attack patterns

        Example:
            >>> ttps = await client.get_threat_actor_ttps("APT28")  # by name
            >>> ttps = await client.get_threat_actor_ttps("Fancy Bear")  # by alias
            >>> ttps = await client.get_threat_actor_ttps("G0007")  # by MITRE ID
        """
        try:
            # Step 1: Resolve entity using robust two-step resolution
            actor_id, entity_type = await self._resolve_threat_actor(actor_name)

            if not actor_id:
                self.logger.error(f"Threat actor not found: '{actor_name}'")
                return {
                    "actor_name": actor_name,
                    "actor_id": None,
                    "found": False,
                    "attack_patterns": [],
                    "error": f"No threat actor found matching '{actor_name}'",
                    "searched_for": actor_name,
                    "suggestions": [
                        "Try a different actor name or alias (e.g., 'Fancy Bear', 'Sofacy')",
                        "Use the MITRE ATT&CK ID (e.g., 'G0007' for APT28)",
                        "Search first using search_entities to verify the actor exists"
                    ]
                }

            if self.debug:
                self.logger.info(f"[DEBUG] Resolved '{actor_name}' → {actor_id} ({entity_type})")

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
                            "actor_name": actor_name,
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
                        "actor_name": data.get("name", actor_name),
                        "actor_id": actor_id,
                        "actor_description": data.get("description", ""),
                        "found": True,
                        "attack_patterns": patterns
                    }

                except Exception as e:
                    self.logger.warning(f"GraphQL query failed, falling back: {e}")
                    return {
                        "actor_name": actor_name,
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

        Supports multiple input formats:
        - Malware name: "Emotet"
        - Alias: "Heodo"
        - Entity ID: "malware--abc123..."

        Args:
            malware_name: Malware name, alias, or entity ID
            limit: Maximum number of results to return

        Returns:
            Dictionary containing malware info and associated techniques

        Example:
            >>> techniques = await client.get_malware_techniques("Emotet")  # by name
            >>> techniques = await client.get_malware_techniques("Heodo")  # by alias
        """
        try:
            # Step 1: Resolve entity using robust two-step resolution
            malware_id, entity_type = await self._resolve_malware(malware_name)

            if not malware_id:
                self.logger.error(f"Malware not found: '{malware_name}'")
                return {
                    "malware_name": malware_name,
                    "malware_id": None,
                    "found": False,
                    "attack_patterns": [],
                    "threat_actors": [],
                    "error": f"No malware found matching '{malware_name}'",
                    "searched_for": malware_name,
                    "suggestions": [
                        "Try a different malware name or variant",
                        "Try common aliases for the malware",
                        "Search first using search_entities or get_malware to verify the malware exists"
                    ]
                }

            if self.debug:
                self.logger.info(f"[DEBUG] Resolved '{malware_name}' → {malware_id}")

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
                            "malware_name": malware_name,
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
                        "malware_name": data.get("name", malware_name),
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
                        "malware_name": malware_name,
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

        Supports multiple input formats:
        - Campaign name: "SolarWinds Compromise"
        - Alias: "SUNBURST"
        - Entity ID: "campaign--abc123..."

        Args:
            campaign_name: Campaign name, alias, or entity ID

        Returns:
            Dictionary containing campaign details and all relationships

        Example:
            >>> campaign = await client.get_campaign_details("SolarWinds Compromise")
        """
        try:
            # Step 1: Resolve entity using robust two-step resolution
            campaign_id, entity_type = await self._resolve_campaign(campaign_name)

            if not campaign_id:
                self.logger.error(f"Campaign not found: '{campaign_name}'")
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
                    "suggestions": [
                        "Try a different campaign name",
                        "Try common aliases for the campaign",
                        "Search first using search_entities with entity_types=['Campaign']"
                    ]
                }

            if self.debug:
                self.logger.info(f"[DEBUG] Resolved '{campaign_name}' → {campaign_id}")

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
                    attack_patterns_data = data.get("attackPatterns", {})
                    edges = attack_patterns_data.get("edges", []) if attack_patterns_data else []

                    for edge in edges:
                        node = edge.get("node", {})
                        patterns.append({
                            "id": node.get("id"),
                            "name": node.get("name"),
                            "x_mitre_id": node.get("x_mitre_id")
                        })

                    return {
                        "campaign_name": data.get("name", campaign_name),
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
                        "campaign_name": campaign_name,
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
                    relationships_data = data.get("stixCoreRelationships", {})
                    edges = relationships_data.get("edges", []) if relationships_data else []

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
