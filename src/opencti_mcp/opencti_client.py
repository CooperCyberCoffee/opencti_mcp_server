"""
Cooper Cyber Coffee OpenCTI MCP Server
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

Contact: matt@coopercybercoffee.com
"""

import logging
import time
from typing import Dict, List, Optional, Any, Tuple, Callable, Awaitable
from pycti import OpenCTIApiClient
import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from datetime import datetime, timedelta

from .exceptions import OperationCancelled


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

        # Marking registry for server-side TLP filtering (v0.4.0+)
        # Will be initialized by server after TLP filter is loaded
        self.marking_registry = None
        self.tlp_filter = None

    async def _get_client(self) -> OpenCTIApiClient:
        """Lazy initialization of OpenCTI client with connection validation.

        Returns:
            Initialized OpenCTI API client

        Raises:
            ConnectionError: If unable to connect to OpenCTI
        """
        if self._client is None:
            try:
                # Set pycti log_level to ERROR to suppress verbose output
                self._client = OpenCTIApiClient(
                    url=self.url,
                    token=self.token,
                    ssl_verify=self.ssl_verify,
                    log_level="ERROR"
                )
                # Only log connection success at INFO level (no duplicate from pycti)
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
        - Connector status (optional)
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
                # Get platform version using health_check method
                version = "unknown"
                try:
                    health = client.health_check()
                    if isinstance(health, dict):
                        version = health.get('version', 'unknown')
                except Exception as e:
                    self.logger.debug(f"Could not retrieve version: {e}")

                # Check for indicators (basic data availability)
                has_indicators = False
                try:
                    indicators = client.indicator.list(first=1)
                    has_indicators = len(indicators) > 0
                except Exception as e:
                    self.logger.debug(f"Could not check indicators: {e}")

                # Check connectors (optional - not critical for core functionality)
                active_connectors = []
                try:
                    connectors = client.connector.list()  # No parameters
                    if connectors:
                        active_connectors = [c for c in connectors if c.get('active', False)]
                    else:
                        active_connectors = []
                except Exception as e:
                    # Connector checking is optional - gracefully skip if API doesn't support it
                    self.logger.debug(f"Connector check skipped (not critical): {e}")
                    active_connectors = []

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
                    f"OpenCTI 6.x recommended. Found version {version}. Some features may not work correctly."
                )
                # Don't raise error, just warn - allow connection to proceed

            # Single concise success message
            data_status = "data: available" if result["has_data"] else "data: empty"
            connector_count = result["active_connectors"]
            self.logger.info(
                f"OpenCTI validation successful (version: {version}, {data_status}, connectors: {connector_count} active)"
            )

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

    async def initialize_marking_registry(self, tlp_filter):
        """
        Initialize marking registry for server-side filtering (v0.4.0+).

        This queries OpenCTI for all marking definitions and builds
        the name→UUID cache. Called once at server startup.

        Args:
            tlp_filter: TLPFilter instance with policy configuration
        """
        from .marking_registry import TLPMarkingRegistry

        self.logger.info("=" * 70)
        self.logger.info("Initializing marking registry for server-side TLP filtering...")

        self.tlp_filter = tlp_filter
        self.marking_registry = TLPMarkingRegistry(await self._get_client())

        # Initialize (queries OpenCTI)
        await self.marking_registry.initialize()

        # Log cache stats
        stats = self.marking_registry.get_cache_stats()
        self.logger.info(
            f"✅ Marking registry ready: {stats['total_markings']} markings "
            f"({stats['tlp_markings']} TLP, {stats['pap_markings']} PAP, "
            f"{stats['custom_markings']} custom)"
        )
        self.logger.info("=" * 70)

    async def _apply_tlp_scoping(
        self,
        filters: Optional[List[Dict]] = None
    ) -> Tuple[Optional[List[Dict]], Dict[str, Any]]:
        """
        Apply TLP scoping to OpenCTI query filters (server-side filtering).

        This adds marking definition UUIDs to the filters so OpenCTI only
        returns objects with allowed TLP markings. This is much faster than
        client-side filtering and prevents sensitive data from being fetched.

        Args:
            filters: Existing filters list (or None)

        Returns:
            Tuple of (updated_filters, metadata)
            - updated_filters: Filters with TLP scope, or None if can't scope
            - metadata: Dict with scoping information for audit logging
        """
        metadata = {
            "scoping_attempted": True,
            "scoping_successful": False,
            "reason": None,
            "marking_uuids_count": 0
        }

        # If no marking registry, can't do server-side filtering
        if not self.marking_registry or not self.tlp_filter:
            metadata["reason"] = "marking_registry_not_initialized"
            self.logger.debug("Marking registry not initialized, skipping server-side scoping")
            return (None, metadata)

        # If registry initialization failed, can't scope
        if not self.marking_registry.initialized:
            metadata["reason"] = "marking_registry_initialization_failed"
            self.logger.warning("Marking registry failed to initialize, using client-side filtering")
            return (None, metadata)

        # If allow_unmarked=true, can't do server-side filtering efficiently
        # (would need to fetch all objects to see which are unmarked)
        if self.tlp_filter.policy.get('allow_unmarked', False):
            metadata["reason"] = "allow_unmarked_enabled"
            self.logger.info(
                "allow_unmarked=true in policy, using client-side filtering"
            )
            return (None, metadata)

        try:
            # Get allowed marking UUIDs from policy
            allowed_uuids = await self.marking_registry.get_allowed_marking_uuids(
                self.tlp_filter.policy
            )

            if not allowed_uuids:
                metadata["reason"] = "no_marking_uuids_resolved"
                self.logger.warning(
                    "No marking UUIDs resolved from policy, falling back to client-side filtering. "
                    "Check your tlp_policy.yaml against OpenCTI marking definitions."
                )
                return (None, metadata)

            # Create or update filters list
            if filters is None:
                filters = []
            else:
                # Make a copy so we don't modify original
                filters = filters.copy()

            # Add TLP marking filter
            tlp_filter = {
                "key": "objectMarking",
                "values": allowed_uuids,
                "operator": "eq",
                "mode": "or"  # Match ANY allowed marking
            }

            filters.append(tlp_filter)

            metadata["scoping_successful"] = True
            metadata["marking_uuids_count"] = len(allowed_uuids)

            self.logger.debug(
                f"✅ Applied TLP scoping: {len(allowed_uuids)} allowed marking UUIDs"
            )

            return (filters, metadata)

        except Exception as e:
            metadata["reason"] = f"scoping_error: {str(e)}"
            self.logger.error(f"Failed to apply TLP scoping: {e}")
            return (None, metadata)

    async def get_recent_indicators_scoped(
        self,
        limit: int = 10,
        indicator_types: Optional[List[str]] = None,
        days_back: int = 7,
        min_confidence: int = 50,
        use_server_side_filtering: bool = True,
        progress_callback: Optional[Callable[[int, int, str], Awaitable[None]]] = None,
        cancellation_token: Optional[Any] = None
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Get recent indicators with optional server-side TLP filtering (v0.4.0+).

        This method tries server-side filtering first (much faster), with
        graceful fallback to client-side filtering if needed.

        Args:
            limit: Number of indicators to retrieve
            indicator_types: Filter by indicator types
            days_back: How many days back to search
            min_confidence: Minimum confidence level
            use_server_side_filtering: Enable server-side TLP filtering
            progress_callback: Optional callback for progress updates (v0.4.1+)
                Signature: async def callback(current: int, total: int, message: str)
            cancellation_token: Optional cancellation token to check (v0.4.1+)

        Returns:
            Tuple of (indicators, metadata)

            metadata includes:
            - filtering_method: "server_side" or "client_side"
            - server_side_enabled: bool
            - scoping_successful: bool
            - performance_ms: int
            - indicators_returned: int

        Raises:
            OperationCancelled: If user cancels operation via cancellation_token
        """
        start_time = time.time()

        # Report starting progress
        if progress_callback:
            await progress_callback(0, limit, f"Starting query for {limit} indicators...")

        metadata = {
            "filtering_method": "none",
            "server_side_enabled": use_server_side_filtering,
            "scoping_successful": False,
            "performance_ms": 0,
            "indicators_returned": 0
        }

        try:
            # Check cancellation before starting
            if cancellation_token and hasattr(cancellation_token, 'is_cancelled'):
                if cancellation_token.is_cancelled():
                    self.logger.info("operation_cancelled", operation="get_recent_indicators", stage="pre_query")
                    raise OperationCancelled("User cancelled operation before query started")

            client = await self._get_client()

            # Build base filters
            filters = []

            if indicator_types:
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

            # Try to apply server-side TLP scoping
            scoped_filters = None
            scoping_metadata = {}

            if use_server_side_filtering:
                scoped_filters, scoping_metadata = await self._apply_tlp_scoping(filters)
                metadata.update(scoping_metadata)

            # Determine which filters to use
            final_filters = scoped_filters if scoped_filters is not None else (filters if filters else None)

            # Report progress before query
            if progress_callback:
                await progress_callback(0, limit, "Querying OpenCTI...")

            # Check cancellation before query
            if cancellation_token and hasattr(cancellation_token, 'is_cancelled'):
                if cancellation_token.is_cancelled():
                    self.logger.info("operation_cancelled", operation="get_recent_indicators", stage="before_query")
                    raise OperationCancelled("User cancelled operation before OpenCTI query")

            # Query OpenCTI
            def _query():
                return client.indicator.list(
                    first=limit,
                    filters=final_filters,
                    orderBy="created_at",
                    orderMode="desc"
                )

            indicators = await asyncio.get_event_loop().run_in_executor(
                self._executor, _query
            )

            # Report progress after query
            if progress_callback:
                await progress_callback(limit, limit, f"Retrieved {len(indicators)} indicators")

            # Check cancellation after query
            if cancellation_token and hasattr(cancellation_token, 'is_cancelled'):
                if cancellation_token.is_cancelled():
                    self.logger.info("operation_cancelled", operation="get_recent_indicators", stage="after_query", indicators_fetched=len(indicators))
                    raise OperationCancelled("User cancelled operation after OpenCTI query")

            # Format indicators
            if progress_callback:
                await progress_callback(limit, limit, "Formatting results...")

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
                    "objectMarking": indicator.get("objectMarking", [])
                }
                formatted.append(formatted_indicator)

            # Update metadata
            metadata["filtering_method"] = "server_side" if scoped_filters else "client_side"
            metadata["performance_ms"] = int((time.time() - start_time) * 1000)
            metadata["indicators_returned"] = len(formatted)

            # Final progress update
            if progress_callback:
                await progress_callback(limit, limit, f"Complete - retrieved {len(formatted)} indicators")

            self.logger.info(
                f"✅ Retrieved {len(formatted)} indicators "
                f"({metadata['filtering_method']} filtering, "
                f"{metadata['performance_ms']}ms)"
            )

            return (formatted, metadata)

        except OperationCancelled:
            # Re-raise cancellation exceptions (user-initiated, not an error)
            raise
        except Exception as e:
            self.logger.error(f"Failed to get indicators: {e}")
            raise

    async def _resolve_entity(
        self,
        name: str,
        entity_types: List[str],
        id_prefixes: Optional[List[str]] = None,
        cache_prefix: str = "entity"
    ) -> Tuple[Optional[str], Optional[str]]:
        """Universal entity resolution for any OpenCTI entity type.

        Handles all input formats:
        - Plain UUIDs (36 chars, 4 dashes): a777e02b-8a27-458f-8ed3-4b26bcfce87d
        - Prefixed IDs: malware--abc123, intrusion-set--xyz789
        - Entity names: APT28, Emotet, SolarWinds Compromise
        - Aliases: Fancy Bear, Feodo, SUNBURST
        - MITRE IDs: G0007, S0154, T1566.001

        Args:
            name: Entity name, UUID, MITRE ID, or prefixed ID
            entity_types: OpenCTI entity types (e.g., ['Malware'], ['Intrusion-Set', 'Threat-Actor'])
            id_prefixes: Expected ID prefixes (e.g., ['malware--', 'malware-family--'])
            cache_prefix: Prefix for cache key (e.g., 'malware', 'campaign')

        Returns:
            Tuple of (entity_id, entity_type) or (None, None) if not found

        Example:
            >>> entity_id, entity_type = await self._resolve_entity(
            ...     name="Emotet",
            ...     entity_types=['Malware'],
            ...     id_prefixes=['malware--'],
            ...     cache_prefix='malware'
            ... )
        """
        import traceback

        if self.debug:
            self.logger.info(f"[RESOLVE_ENTITY] === Starting resolution ===")
            self.logger.info(f"[RESOLVE_ENTITY] Input: '{name}'")
            self.logger.info(f"[RESOLVE_ENTITY] Entity types: {entity_types}")
            self.logger.info(f"[RESOLVE_ENTITY] Input length: {len(name)}, Dashes: {name.count('-')}")

        # Check if it's a prefixed ID
        if id_prefixes:
            for prefix in id_prefixes:
                if name.startswith(prefix):
                    if self.debug:
                        self.logger.info(f"[RESOLVE_ENTITY] ✓ Input has {prefix} prefix")
                    return (name, entity_types[0].lower().replace(' ', '-').replace('_', '-'))

        # Check if it's a plain UUID (OpenCTI 6.x format)
        # Format: a777e02b-8a27-458f-8ed3-4b26bcfce87d (36 chars, 4 dashes)
        if len(name) == 36 and name.count('-') == 4:
            if self.debug:
                self.logger.info(f"[RESOLVE_ENTITY] Detected plain UUID format: {name}")

            client = await self._get_client()

            # Try to verify UUID exists for each entity type
            for entity_type in entity_types:
                try:
                    entity_type_lower = entity_type.lower().replace('-', '_').replace(' ', '_')
                    if self.debug:
                        self.logger.info(f"[RESOLVE_ENTITY] Attempting {entity_type}.read(id={name})")

                    # Map entity type to client method
                    if hasattr(client, entity_type_lower):
                        entity_client = getattr(client, entity_type_lower)
                        test = entity_client.read(id=name)
                        if test:
                            normalized_type = entity_type.lower().replace(' ', '-').replace('_', '-')
                            if self.debug:
                                self.logger.info(f"[RESOLVE_ENTITY] ✓ Verified as {entity_type}: {test.get('name', 'N/A')}")
                            return (name, normalized_type)
                except Exception as e:
                    if self.debug:
                        self.logger.info(f"[RESOLVE_ENTITY] Not a {entity_type}: {e}")

            # If we can't verify but it looks like a UUID, assume first entity type
            if self.debug:
                self.logger.info(f"[RESOLVE_ENTITY] Assuming UUID is {entity_types[0]}")
            return (name, entity_types[0].lower().replace(' ', '-').replace('_', '-'))

        # Check cache
        cache_key = f"{cache_prefix}:{name.lower()}"
        cached = self._get_cached(cache_key)
        if cached:
            if self.debug:
                self.logger.info(f"[RESOLVE_ENTITY] ✓ Cache hit: {cached}")
            return cached

        if self.debug:
            self.logger.info(f"[RESOLVE_ENTITY] Not in cache, using search_entities")

        # Use search_entities (we know it works reliably!)
        try:
            if self.debug:
                self.logger.info(f"[RESOLVE_ENTITY] Calling search_entities('{name}', {entity_types})")

            search_results = await self.search_entities(
                search_term=name,
                entity_types=entity_types,
                limit=10
            )

            if self.debug:
                self.logger.info(f"[RESOLVE_ENTITY] search_entities returned {len(search_results)} results")

            if search_results and len(search_results) > 0:
                # Priority 1: Exact name match (case-insensitive)
                for result in search_results:
                    if result.get('name', '').lower() == name.lower():
                        entity_id = result.get('id')
                        entity_type = result.get('entity_type', entity_types[0])
                        entity_type_normalized = entity_type.lower().replace(' ', '-').replace('_', '-')
                        if self.debug:
                            self.logger.info(f"[RESOLVE_ENTITY] ✓ Exact match: {result.get('name')} ({entity_id})")
                        result_tuple = (entity_id, entity_type_normalized)
                        self._set_cached(cache_key, result_tuple)
                        return result_tuple

                # Priority 2: Alias match
                for result in search_results:
                    aliases = result.get('aliases', []) or []
                    if self.debug:
                        self.logger.info(f"[RESOLVE_ENTITY] Checking aliases for {result.get('name')}: {aliases}")
                    if any(alias.lower() == name.lower() for alias in aliases):
                        entity_id = result.get('id')
                        entity_type = result.get('entity_type', entity_types[0])
                        entity_type_normalized = entity_type.lower().replace(' ', '-').replace('_', '-')
                        if self.debug:
                            self.logger.info(f"[RESOLVE_ENTITY] ✓ Alias match: {result.get('name')} ({entity_id})")
                        result_tuple = (entity_id, entity_type_normalized)
                        self._set_cached(cache_key, result_tuple)
                        return result_tuple

                # Priority 3: MITRE ID match
                for result in search_results:
                    mitre_id = result.get('mitre_id', '')
                    if self.debug and mitre_id:
                        self.logger.info(f"[RESOLVE_ENTITY] {result.get('name')} MITRE ID: {mitre_id}")
                    if mitre_id and mitre_id.upper() == name.upper():
                        entity_id = result.get('id')
                        entity_type = result.get('entity_type', entity_types[0])
                        entity_type_normalized = entity_type.lower().replace(' ', '-').replace('_', '-')
                        if self.debug:
                            self.logger.info(f"[RESOLVE_ENTITY] ✓ MITRE ID match: {result.get('name')} ({entity_id})")
                        result_tuple = (entity_id, entity_type_normalized)
                        self._set_cached(cache_key, result_tuple)
                        return result_tuple

                # Priority 4: Fuzzy match (first result)
                entity_id = search_results[0].get('id')
                entity_name = search_results[0].get('name')
                entity_type = search_results[0].get('entity_type', entity_types[0])
                entity_type_normalized = entity_type.lower().replace(' ', '-').replace('_', '-')
                if self.debug:
                    self.logger.info(f"[RESOLVE_ENTITY] ✓ Fuzzy match: {entity_name} ({entity_id})")
                result_tuple = (entity_id, entity_type_normalized)
                self._set_cached(cache_key, result_tuple)
                return result_tuple

        except Exception as e:
            if self.debug:
                self.logger.error(f"[RESOLVE_ENTITY] search_entities failed:")
                self.logger.error(f"[RESOLVE_ENTITY] Error: {str(e)}")
                self.logger.error(f"[RESOLVE_ENTITY] Traceback:\n{traceback.format_exc()}")

        if self.debug:
            self.logger.error(f"[RESOLVE_ENTITY] ✗ Resolution FAILED for '{name}'")

        return (None, None)

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

        TEST CASES THAT MUST WORK:
        1. _resolve_malware("Emotet") → should find entity
        2. _resolve_malware("dcbbf768-e5a9-4d6a-...") → should work with UUID
        3. _resolve_malware("Feodo") → should find via alias
        4. _resolve_malware("S0154") → should find via MITRE ID

        Args:
            name: Malware name, alias, MITRE ID, or entity ID

        Returns:
            Tuple of (entity_id, 'malware') or (None, None) if not found
        """
        return await self._resolve_entity(
            name=name,
            entity_types=['Malware'],
            id_prefixes=['malware--'],
            cache_prefix='malware'
        )

    async def _resolve_campaign(self, name: str) -> Tuple[Optional[str], Optional[str]]:
        """Resolve campaign by name, alias, or entity ID.

        TEST CASES THAT MUST WORK:
        1. _resolve_campaign("SolarWinds Compromise") → should find entity
        2. _resolve_campaign("campaign-uuid-here") → should work with UUID
        3. _resolve_campaign("SUNBURST") → should find via alias

        Args:
            name: Campaign name, alias, or entity ID

        Returns:
            Tuple of (entity_id, 'campaign') or (None, None) if not found
        """
        return await self._resolve_entity(
            name=name,
            entity_types=['Campaign'],
            id_prefixes=['campaign--'],
            cache_prefix='campaign'
        )

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

                # Get indicators
                indicators = client.indicator.list(
                    first=limit,
                    filters=filters,
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

    async def search_observable(self, observable_value: str) -> List[Dict[str, Any]]:
        """Search for indicators by observable value (IP, domain, URL, email, hash).

        Supports multiple observable types with automatic detection:
        - IPv4 addresses (e.g., 192.168.1.1)
        - IPv6 addresses (e.g., 2001:0db8:85a3::8a2e:0370:7334)
        - Domain names (e.g., evil.com)
        - URLs (e.g., http://malicious.com/payload.exe)
        - Email addresses (e.g., attacker@evil.com)
        - File hashes (MD5, SHA1, SHA256)

        Args:
            observable_value: Observable value to search for

        Returns:
            List of matching indicators

        Example:
            >>> results = await client.search_observable("192.168.1.1")
            >>> if results:
            ...     print(f"Found {len(results)} indicators")
            >>> results = await client.search_observable("evil.com")
            >>> results = await client.search_observable("44d88612fea8a8f36de82e1278abb02f")
        """
        try:
            client = await self._get_client()

            def _search_observable():
                # Use pycti's search parameter - no GraphQL filters needed
                # pycti automatically searches pattern fields and other relevant fields
                indicators = client.indicator.list(
                    search=observable_value,
                    first=100  # Add reasonable limit
                )

                formatted = []
                for indicator in indicators:
                    formatted_indicator = {
                        "id": indicator.get("id"),
                        "pattern": indicator.get("pattern"),
                        "indicator_types": indicator.get("indicator_types", []),
                        "confidence": indicator.get("confidence"),
                        "created_at": indicator.get("created_at"),
                        "labels": [label.get("value") for label in indicator.get("objectLabel", [])],
                        "objectMarking": indicator.get("objectMarking", [])
                    }
                    formatted.append(formatted_indicator)

                return formatted

            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _search_observable
            )

            self.logger.info(f"Observable search for {observable_value} returned {len(result)} results")
            return result

        except Exception as e:
            self.logger.error(f"Observable search failed: {e}")
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
        - Entity ID: "intrusion-set--abc123..." or plain UUID

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
                self.logger.info(f"[TTP] Resolved '{actor_name}' → {actor_id} ({entity_type})")

            # Step 2: Get entity details and relationships using pycti client
            client = await self._get_client()

            def _get_ttps():
                import traceback
                try:
                    if self.debug:
                        self.logger.info(f"[TTP] Fetching entity details for {actor_id}")

                    # Get actor details first
                    if entity_type == 'intrusion-set':
                        actor_data = client.intrusion_set.read(id=actor_id)
                    else:
                        actor_data = client.threat_actor.read(id=actor_id)

                    if not actor_data:
                        if self.debug:
                            self.logger.warning(f"[TTP] Could not read entity {actor_id}")
                        return {
                            "actor_name": actor_name,
                            "actor_id": actor_id,
                            "found": False,
                            "attack_patterns": [],
                            "error": "Could not read entity details"
                        }

                    actor_name_actual = actor_data.get('name', actor_name)
                    actor_description = actor_data.get('description', '')

                    if self.debug:
                        self.logger.info(f"[TTP] Entity name: {actor_name_actual}")
                        self.logger.info(f"[TTP] Getting relationships from {actor_id}")

                    # Get 'uses' relationships to attack patterns
                    relationships = client.stix_core_relationship.list(
                        fromId=actor_id,
                        relationship_type='uses',
                        toTypes=['Attack-Pattern'],
                        first=limit
                    )

                    if self.debug:
                        self.logger.info(f"[TTP] Found {len(relationships) if relationships else 0} relationships")

                    if not relationships:
                        return {
                            "actor_name": actor_name_actual,
                            "actor_id": actor_id,
                            "actor_description": actor_description,
                            "found": True,
                            "attack_patterns": []
                        }

                    # Get full attack pattern details using pycti - no GraphQL!
                    patterns = []
                    for rel in relationships[:limit]:
                        try:
                            to_entity = rel.get('to')
                            if not to_entity:
                                continue

                            ttp_id = to_entity.get('id')
                            if not ttp_id:
                                continue

                            # Get complete attack pattern details with pycti
                            ttp = client.attack_pattern.read(id=ttp_id)
                            if ttp:
                                patterns.append({
                                    "id": ttp.get('id'),
                                    "name": ttp.get('name'),
                                    "description": ttp.get('description', '')[:500],
                                    "x_mitre_id": ttp.get('x_mitre_id', ''),
                                    "kill_chain_phases": [
                                        phase.get('phase_name', '')
                                        for phase in ttp.get('killChainPhases', []) or []
                                    ]
                                })

                                if self.debug:
                                    self.logger.info(f"[TTP] Added: {ttp.get('name')} ({ttp.get('x_mitre_id')})")

                        except Exception as e:
                            if self.debug:
                                self.logger.warning(f"[TTP] Error processing relationship: {e}")
                            continue

                    if self.debug:
                        self.logger.info(f"[TTP] Total patterns extracted: {len(patterns)}")

                    return {
                        "actor_name": actor_name_actual,
                        "actor_id": actor_id,
                        "actor_description": actor_description,
                        "aliases": actor_data.get('aliases', []),
                        "found": True,
                        "attack_patterns": patterns,
                        "total_ttps": len(patterns)
                    }

                except Exception as e:
                    if self.debug:
                        self.logger.error(f"[TTP] Error getting TTPs:")
                        self.logger.error(f"[TTP] {str(e)}")
                        self.logger.error(f"[TTP] Traceback:\n{traceback.format_exc()}")

                    return {
                        "actor_name": actor_name,
                        "actor_id": actor_id,
                        "found": False,
                        "attack_patterns": [],
                        "error": str(e)
                    }

            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _get_ttps
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
                self.logger.info(f"[MALWARE] Resolved '{malware_name}' → {malware_id}")

            # Step 2: Get malware details and relationships using pycti client
            client = await self._get_client()

            def _get_techniques():
                import traceback
                try:
                    if self.debug:
                        self.logger.info(f"[MALWARE] Fetching malware details for {malware_id}")

                    # Get malware details first
                    malware_data = client.malware.read(id=malware_id)

                    if not malware_data:
                        if self.debug:
                            self.logger.warning(f"[MALWARE] Could not read malware {malware_id}")
                        return {
                            "malware_name": malware_name,
                            "malware_id": malware_id,
                            "found": False,
                            "attack_patterns": [],
                            "threat_actors": [],
                            "error": "Could not read malware details"
                        }

                    malware_name_actual = malware_data.get('name', malware_name)
                    malware_description = malware_data.get('description', '')
                    malware_types = malware_data.get('malware_types', [])

                    if self.debug:
                        self.logger.info(f"[MALWARE] Malware name: {malware_name_actual}")
                        self.logger.info(f"[MALWARE] Getting relationships from {malware_id}")

                    # Get 'uses' relationships to attack patterns
                    relationships = client.stix_core_relationship.list(
                        fromId=malware_id,
                        relationship_type='uses',
                        toTypes=['Attack-Pattern'],
                        first=limit
                    )

                    if self.debug:
                        self.logger.info(f"[MALWARE] Found {len(relationships) if relationships else 0} relationships")

                    # Get full attack pattern details using pycti - no GraphQL!
                    patterns = []
                    if relationships:
                        for rel in relationships[:limit]:
                            try:
                                to_entity = rel.get('to')
                                if not to_entity:
                                    continue

                                ttp_id = to_entity.get('id')
                                if not ttp_id:
                                    continue

                                # Get complete attack pattern details with pycti
                                ttp = client.attack_pattern.read(id=ttp_id)
                                if ttp:
                                    patterns.append({
                                        "id": ttp.get('id'),
                                        "name": ttp.get('name'),
                                        "description": ttp.get('description', '')[:500],
                                        "x_mitre_id": ttp.get('x_mitre_id', ''),
                                        "kill_chain_phases": [
                                            phase.get('phase_name', '')
                                            for phase in ttp.get('killChainPhases', []) or []
                                        ]
                                    })

                                    if self.debug:
                                        self.logger.info(f"[MALWARE] Added: {ttp.get('name')} ({ttp.get('x_mitre_id')})")

                            except Exception as e:
                                if self.debug:
                                    self.logger.warning(f"[MALWARE] Error processing relationship: {e}")
                                continue

                    if self.debug:
                        self.logger.info(f"[MALWARE] Total patterns extracted: {len(patterns)}")

                    return {
                        "malware_name": malware_name_actual,
                        "malware_id": malware_id,
                        "malware_description": malware_description,
                        "malware_types": malware_types,
                        "aliases": malware_data.get('aliases', []),
                        "found": True,
                        "attack_patterns": patterns,
                        "total_techniques": len(patterns),
                        "threat_actors": []  # Could be extended with additional query
                    }

                except Exception as e:
                    if self.debug:
                        self.logger.error(f"[MALWARE] Error getting techniques:")
                        self.logger.error(f"[MALWARE] {str(e)}")
                        self.logger.error(f"[MALWARE] Traceback:\n{traceback.format_exc()}")

                    return {
                        "malware_name": malware_name,
                        "malware_id": malware_id,
                        "found": False,
                        "attack_patterns": [],
                        "threat_actors": [],
                        "error": str(e)
                    }

            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _get_techniques
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
                self.logger.info(f"[CAMPAIGN] Resolved '{campaign_name}' → {campaign_id}")

            # Step 2: Get campaign details and relationships using pycti client
            client = await self._get_client()

            def _get_details():
                import traceback
                try:
                    if self.debug:
                        self.logger.info(f"[CAMPAIGN] Fetching campaign details for {campaign_id}")

                    # Get campaign details first
                    campaign_data = client.campaign.read(id=campaign_id)

                    if not campaign_data:
                        if self.debug:
                            self.logger.warning(f"[CAMPAIGN] Could not read campaign {campaign_id}")
                        return {
                            "campaign_name": campaign_name,
                            "campaign_id": campaign_id,
                            "found": False,
                            "threat_actors": [],
                            "attack_patterns": [],
                            "malware": [],
                            "targets": [],
                            "error": "Could not read campaign details"
                        }

                    campaign_name_actual = campaign_data.get('name', campaign_name)
                    campaign_description = campaign_data.get('description', '')
                    first_seen = campaign_data.get('first_seen')
                    last_seen = campaign_data.get('last_seen')

                    if self.debug:
                        self.logger.info(f"[CAMPAIGN] Campaign name: {campaign_name_actual}")
                        self.logger.info(f"[CAMPAIGN] Getting relationships from {campaign_id}")

                    # Get 'uses' relationships to attack patterns
                    relationships = client.stix_core_relationship.list(
                        fromId=campaign_id,
                        relationship_type='uses',
                        toTypes=['Attack-Pattern'],
                        first=50
                    )

                    if self.debug:
                        self.logger.info(f"[CAMPAIGN] Found {len(relationships) if relationships else 0} attack pattern relationships")

                    # Get full attack pattern details using pycti - no GraphQL!
                    patterns = []
                    if relationships:
                        for rel in relationships:
                            try:
                                to_entity = rel.get('to')
                                if not to_entity:
                                    continue

                                ttp_id = to_entity.get('id')
                                if not ttp_id:
                                    continue

                                # Get complete attack pattern details with pycti
                                ttp = client.attack_pattern.read(id=ttp_id)
                                if ttp:
                                    patterns.append({
                                        "id": ttp.get('id'),
                                        "name": ttp.get('name'),
                                        "description": ttp.get('description', '')[:500],
                                        "x_mitre_id": ttp.get('x_mitre_id', ''),
                                        "kill_chain_phases": [
                                            phase.get('phase_name', '')
                                            for phase in ttp.get('killChainPhases', []) or []
                                        ]
                                    })

                                    if self.debug:
                                        self.logger.info(f"[CAMPAIGN] Added: {ttp.get('name')} ({ttp.get('x_mitre_id', '')})")

                            except Exception as e:
                                if self.debug:
                                    self.logger.warning(f"[CAMPAIGN] Error processing relationship: {e}")
                                continue

                    if self.debug:
                        self.logger.info(f"[CAMPAIGN] Total patterns extracted: {len(patterns)}")

                    # Get attributed-to relationships (threat actors)
                    threat_actor_rels = client.stix_core_relationship.list(
                        fromId=campaign_id,
                        relationship_type='attributed-to',
                        toTypes=['Intrusion-Set', 'Threat-Actor'],
                        first=20
                    )

                    threat_actors = []
                    if threat_actor_rels:
                        for rel in threat_actor_rels:
                            try:
                                to_entity = rel.get('to')
                                if not to_entity:
                                    continue

                                actor_id = to_entity.get('id')
                                if not actor_id:
                                    continue

                                # Get complete threat actor details with pycti
                                actor = client.intrusion_set.read(id=actor_id)
                                if actor:
                                    threat_actors.append({
                                        "id": actor.get('id'),
                                        "name": actor.get('name'),
                                        "description": actor.get('description', '')[:300],
                                        "aliases": actor.get('aliases', [])
                                    })

                            except Exception as e:
                                if self.debug:
                                    self.logger.warning(f"[CAMPAIGN] Error processing threat actor: {e}")
                                continue

                    # Get uses relationships to malware
                    malware_rels = client.stix_core_relationship.list(
                        fromId=campaign_id,
                        relationship_type='uses',
                        toTypes=['Malware'],
                        first=20
                    )

                    malware_list = []
                    if malware_rels:
                        for rel in malware_rels:
                            try:
                                to_entity = rel.get('to')
                                if not to_entity:
                                    continue

                                malware_id = to_entity.get('id')
                                if not malware_id:
                                    continue

                                # Get complete malware details with pycti
                                malware = client.malware.read(id=malware_id)
                                if malware:
                                    malware_list.append({
                                        "id": malware.get('id'),
                                        "name": malware.get('name'),
                                        "description": malware.get('description', '')[:300],
                                        "aliases": malware.get('aliases', [])
                                    })

                            except Exception as e:
                                if self.debug:
                                    self.logger.warning(f"[CAMPAIGN] Error processing malware: {e}")
                                continue

                    return {
                        "campaign_name": campaign_name_actual,
                        "campaign_id": campaign_id,
                        "campaign_description": campaign_description,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "aliases": campaign_data.get('aliases', []),
                        "found": True,
                        "threat_actors": threat_actors,
                        "attack_patterns": patterns,
                        "malware": malware_list,
                        "targets": [],  # Could be extended to get targets relationships
                        "total_threat_actors": len(threat_actors),
                        "total_attack_patterns": len(patterns),
                        "total_malware": len(malware_list)
                    }

                except Exception as e:
                    if self.debug:
                        self.logger.error(f"[CAMPAIGN] Error getting details:")
                        self.logger.error(f"[CAMPAIGN] {str(e)}")
                        self.logger.error(f"[CAMPAIGN] Traceback:\n{traceback.format_exc()}")

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
                self._executor, _get_details
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
                import traceback
                try:
                    # Use pycti methods to query relationships - no GraphQL!
                    if self.debug:
                        self.logger.info(f"[RELATIONSHIPS] Getting relationships for {entity_id}")

                    # Get entity details first to determine name and type
                    # Try common entity types
                    entity_name = "Unknown"
                    entity_type_str = "Unknown"
                    entity_data = None

                    for entity_type_check, client_attr in [
                        ('Intrusion-Set', 'intrusion_set'),
                        ('Malware', 'malware'),
                        ('Campaign', 'campaign'),
                        ('Attack-Pattern', 'attack_pattern'),
                        ('Threat-Actor', 'threat_actor'),
                        ('Vulnerability', 'vulnerability'),
                        ('Indicator', 'indicator')
                    ]:
                        try:
                            entity_client = getattr(client, client_attr)
                            entity_data = entity_client.read(id=entity_id)
                            if entity_data:
                                entity_name = entity_data.get('name', 'Unknown')
                                entity_type_str = entity_type_check
                                if self.debug:
                                    self.logger.info(f"[RELATIONSHIPS] Found entity: {entity_name} ({entity_type_str})")
                                break
                        except:
                            continue

                    if not entity_data:
                        if self.debug:
                            self.logger.warning(f"[RELATIONSHIPS] Could not read entity {entity_id}")
                        return None

                    # Get all relationships FROM this entity
                    from_rels = client.stix_core_relationship.list(
                        fromId=entity_id,
                        first=limit
                    )

                    # Get all relationships TO this entity
                    to_rels = client.stix_core_relationship.list(
                        toId=entity_id,
                        first=limit
                    )

                    if self.debug:
                        self.logger.info(f"[RELATIONSHIPS] Found {len(from_rels) if from_rels else 0} outbound, {len(to_rels) if to_rels else 0} inbound relationships")

                    relationships = []

                    # Process outbound relationships (from this entity)
                    if from_rels:
                        for rel in from_rels:
                            try:
                                rel_type = rel.get('relationship_type')

                                # Filter by relationship type if specified
                                if relationship_type and rel_type != relationship_type:
                                    continue

                                to_entity = rel.get('to')
                                if not to_entity:
                                    continue

                                relationships.append({
                                    "relationship_id": rel.get('id'),
                                    "relationship_type": rel_type,
                                    "direction": "outbound",
                                    "target": {
                                        "id": to_entity.get('id'),
                                        "entity_type": to_entity.get('entity_type', 'Unknown'),
                                        "name": to_entity.get('name', 'Unknown'),
                                        "description": to_entity.get('description', '')[:200]
                                    }
                                })

                            except Exception as e:
                                if self.debug:
                                    self.logger.warning(f"[RELATIONSHIPS] Error processing outbound rel: {e}")
                                continue

                    # Process inbound relationships (to this entity)
                    if to_rels:
                        for rel in to_rels:
                            try:
                                rel_type = rel.get('relationship_type')

                                # Filter by relationship type if specified
                                if relationship_type and rel_type != relationship_type:
                                    continue

                                from_entity = rel.get('from')
                                if not from_entity:
                                    continue

                                relationships.append({
                                    "relationship_id": rel.get('id'),
                                    "relationship_type": rel_type,
                                    "direction": "inbound",
                                    "target": {
                                        "id": from_entity.get('id'),
                                        "entity_type": from_entity.get('entity_type', 'Unknown'),
                                        "name": from_entity.get('name', 'Unknown'),
                                        "description": from_entity.get('description', '')[:200]
                                    }
                                })

                            except Exception as e:
                                if self.debug:
                                    self.logger.warning(f"[RELATIONSHIPS] Error processing inbound rel: {e}")
                                continue

                    if self.debug:
                        self.logger.info(f"[RELATIONSHIPS] Total relationships returned: {len(relationships)}")

                    return {
                        "entity_id": entity_id,
                        "entity_name": entity_name,
                        "entity_type": entity_type_str,
                        "relationships": relationships
                    }

                except Exception as e:
                    if self.debug:
                        self.logger.error(f"[RELATIONSHIPS] Error getting relationships:")
                        self.logger.error(f"[RELATIONSHIPS] {str(e)}")
                        self.logger.error(f"[RELATIONSHIPS] Traceback:\n{traceback.format_exc()}")
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

    async def get_reports(
        self,
        limit: int = 10,
        search_term: Optional[str] = None,
        published_after: Optional[str] = None,
        min_confidence: int = 0
    ) -> List[Dict[str, Any]]:
        """Get analytical reports from OpenCTI with filtering.

        Args:
            limit: Maximum number of reports to retrieve (default: 10)
            search_term: Optional search term to filter reports by title/content
            published_after: Optional ISO date (YYYY-MM-DD) for published date filter
            min_confidence: Minimum confidence level 0-100 (default: 0)

        Returns:
            List of report dictionaries with formatted data

        Example:
            >>> reports = await client.get_reports(
            ...     limit=10,
            ...     search_term="APT28",
            ...     published_after="2024-01-01",
            ...     min_confidence=50
            ... )
            >>> print(f"Found {len(reports)} reports")
        """
        try:
            client = await self._get_client()

            def _get_reports():
                # Build search parameters
                kwargs = {
                    "first": limit,
                    "orderBy": "published",
                    "orderMode": "desc"
                }

                if search_term:
                    kwargs["search"] = search_term

                # Build filters list for advanced filtering
                filters = []

                # Add confidence filter if specified
                if min_confidence > 0:
                    filters.append({
                        "key": "confidence",
                        "values": [str(min_confidence)],
                        "operator": "gte"
                    })

                # Add published date filter if specified
                if published_after:
                    filters.append({
                        "key": "published",
                        "values": [published_after],
                        "operator": "gte"
                    })

                # Add filters to kwargs if any exist
                if filters:
                    kwargs["filters"] = filters

                # Get reports using pycti
                reports_list = client.report.list(**kwargs)

                # Format for MCP consumption
                formatted = []
                for report in reports_list:
                    formatted_report = {
                        "id": report.get("id"),
                        "name": report.get("name"),
                        "description": report.get("description", "No description available"),
                        "published": report.get("published"),
                        "confidence": report.get("confidence", 0),
                        "report_types": report.get("report_types", []),
                        "labels": [label.get("value") for label in report.get("objectLabel", [])],
                        "object_refs_count": len(report.get("object_refs", [])),
                        "created": report.get("created"),
                        "modified": report.get("modified")
                    }
                    formatted.append(formatted_report)

                return formatted

            result = await asyncio.get_event_loop().run_in_executor(
                self._executor, _get_reports
            )

            self.logger.info(f"Retrieved {len(result)} reports")
            return result

        except Exception as e:
            self.logger.error(f"Failed to get reports: {e}")
            raise

    async def close(self):
        """Close the client and clean up resources."""
        if self._executor:
            self._executor.shutdown(wait=True)
            self.logger.info("OpenCTI client executor shutdown complete")
