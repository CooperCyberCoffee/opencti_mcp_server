"""
Cooper Cyber Coffee OpenCTI MCP Server - TLP Marking Registry
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

Contact: matt@coopercybercoffee.com

TLP Marking UUID registry for server-side filtering.
Queries OpenCTI for ALL marking definitions and caches name→UUID mapping.
"""

import logging
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timedelta
import asyncio
from concurrent.futures import ThreadPoolExecutor


class TLPMarkingRegistry:
    """
    Registry for ALL marking definitions in OpenCTI (TLP + PAP + custom).

    OpenCTI generates its own UUIDs for marking definitions, including
    standard TLP levels. These UUIDs are instance-specific, not universal.

    This registry queries OpenCTI at startup to build a complete name→UUID
    mapping for all markings, then caches the results for fast lookups.

    Supports:
    - Standard TLP markings (TLP:CLEAR, TLP:RED, etc.)
    - PAP markings (PAP:CLEAR, PAP:RED, etc.)
    - Custom organizational markings
    - Any other marking definitions in OpenCTI

    Example:
        >>> registry = TLPMarkingRegistry(opencti_client)
        >>> await registry.initialize()
        >>> uuid = registry.get_marking_uuid("TLP:CLEAR")
        >>> print(uuid)
        'b044348b-eff4-4b94-b060-1e0d0f0046fb'
    """

    def __init__(self, opencti_client):
        """
        Initialize TLP marking registry.

        Args:
            opencti_client: OpenCTI API client (pycti.OpenCTIApiClient instance)
        """
        self.client = opencti_client
        self.logger = logging.getLogger(__name__)
        self._executor = ThreadPoolExecutor(max_workers=1)

        # Cache ALL markings (TLP, PAP, custom, everything)
        # Format: {"TLP:CLEAR": "b044348b-...", "CUSTOM:FOO": "abc123-...", ...}
        self.marking_cache: Dict[str, str] = {}

        # Track when cache was populated
        self.cache_timestamp: Optional[datetime] = None

        # Initialization status
        self.initialized = False
        self.initialization_error: Optional[str] = None

    async def initialize(self):
        """
        Initialize registry by querying ALL marking definitions from OpenCTI.

        This is called once at server startup to populate the marking cache.
        Subsequent queries use the cache for instant lookups.

        Raises:
            Exception: If query fails (server cannot start without markings)
        """
        if self.initialized:
            self.logger.info("Marking registry already initialized, skipping")
            return

        self.logger.info("=" * 70)
        self.logger.info("Initializing TLP marking registry...")
        self.logger.info("Querying ALL marking definitions from OpenCTI...")

        try:
            # Query all marking definitions from OpenCTI
            # This includes TLP, PAP, custom markings - everything
            def _get_all_markings():
                # Use pycti client to get marking definitions
                # first=1000 should be more than enough for any OpenCTI instance
                return self.client.marking_definition.list(first=1000)

            # Run in thread pool (pycti is synchronous)
            markings = await asyncio.get_event_loop().run_in_executor(
                self._executor, _get_all_markings
            )

            if not markings:
                raise Exception("OpenCTI returned no marking definitions")

            # Build name → UUID mapping for ALL markings
            for marking in markings:
                # Get marking definition name and UUID
                definition = marking.get('definition', '')
                marking_id = marking.get('id', '')
                marking_type = marking.get('definition_type', '')

                if not definition or not marking_id:
                    self.logger.warning(
                        f"Skipping marking with missing definition or ID: {marking}"
                    )
                    continue

                # Normalize name to uppercase for case-insensitive comparison
                definition_upper = definition.upper()

                # Add to cache
                self.marking_cache[definition_upper] = marking_id

                self.logger.debug(
                    f"Cached marking: {definition_upper} → {marking_id} (type: {marking_type})"
                )

            self.cache_timestamp = datetime.now()
            self.initialized = True

            # Log summary
            self.logger.info("=" * 70)
            self.logger.info(
                f"✅ Marking registry initialized: {len(self.marking_cache)} markings cached"
            )

            # Log TLP markings specifically (for verification)
            tlp_markings = {k: v for k, v in self.marking_cache.items() if k.startswith('TLP:')}
            if tlp_markings:
                self.logger.info(f"📊 TLP markings found: {list(tlp_markings.keys())}")
            else:
                self.logger.warning("⚠️  No TLP markings found in OpenCTI!")

            # Log PAP markings (if any)
            pap_markings = {k: v for k, v in self.marking_cache.items() if k.startswith('PAP:')}
            if pap_markings:
                self.logger.info(f"📊 PAP markings found: {list(pap_markings.keys())}")

            # Log custom markings (anything not TLP or PAP)
            custom_markings = {
                k: v for k, v in self.marking_cache.items()
                if not k.startswith('TLP:') and not k.startswith('PAP:')
            }
            if custom_markings:
                custom_list = list(custom_markings.keys())[:10]  # First 10
                self.logger.info(
                    f"📊 Custom markings found: {custom_list}"
                    f"{' (+' + str(len(custom_markings) - 10) + ' more)' if len(custom_markings) > 10 else ''}"
                )

            self.logger.info("=" * 70)

        except Exception as e:
            self.initialization_error = str(e)
            self.logger.error("=" * 70)
            self.logger.error(f"❌ Failed to initialize marking registry: {e}")
            self.logger.error(
                "Server cannot start without marking definitions. "
                "Check OpenCTI connection and ensure marking definitions exist."
            )
            self.logger.error("=" * 70)
            raise

    def get_marking_uuid(self, marking_name: str) -> Optional[str]:
        """
        Get UUID for any marking (TLP, PAP, custom).

        Args:
            marking_name: Marking name (e.g., "TLP:CLEAR", "CUSTOM:PUBLIC")

        Returns:
            UUID string or None if marking not found
        """
        if not self.initialized:
            self.logger.error(
                "Marking registry not initialized. Call initialize() first."
            )
            return None

        # Normalize to uppercase
        marking_upper = marking_name.upper()

        # Lookup in cache
        uuid = self.marking_cache.get(marking_upper)

        if not uuid:
            # Not found - log available markings to help debug
            available = list(self.marking_cache.keys())[:20]  # First 20
            self.logger.warning(
                f"Marking '{marking_name}' not found in OpenCTI. "
                f"Available markings (first 20): {available}"
            )

        return uuid

    async def get_allowed_marking_uuids(self, policy: Dict[str, Any]) -> List[str]:
        """
        Convert TLP policy to list of OpenCTI marking UUIDs.

        Processes BOTH allowed_markings and custom_allowed_markings from
        policy, treating them identically (no distinction).

        Args:
            policy: TLP policy dict from TLPFilter

        Returns:
            List of marking definition UUIDs for OpenCTI query
        """
        if not self.initialized:
            self.logger.error("Marking registry not initialized")
            return []

        uuids: Set[str] = set()

        # Get ALL allowed markings (standard + custom combined)
        # No distinction between "standard" and "custom" anymore
        all_allowed_markings = (
            policy.get('allowed_markings', []) +
            policy.get('custom_allowed_markings', [])
        )

        if not all_allowed_markings:
            self.logger.warning("No allowed markings in policy")
            return []

        # Resolve each marking to UUID
        for marking in all_allowed_markings:
            uuid = self.get_marking_uuid(marking)
            if uuid:
                uuids.add(uuid)
                self.logger.debug(f"✅ Resolved {marking} → {uuid}")
            else:
                self.logger.error(
                    f"❌ Marking '{marking}' in policy not found in OpenCTI. "
                    f"This marking will be ignored for server-side filtering. "
                    f"Check spelling or create marking definition in OpenCTI."
                )

        if not uuids:
            self.logger.error(
                "❌ No marking UUIDs resolved from policy. "
                "Server-side filtering cannot work. "
                "Check your tlp_policy.yaml against OpenCTI marking definitions."
            )
        else:
            self.logger.info(
                f"✅ Resolved {len(uuids)} marking UUIDs for server-side filtering"
            )

        return list(uuids)

    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics for monitoring/debugging.

        Returns:
            Dict with cache statistics
        """
        tlp_count = len([k for k in self.marking_cache if k.startswith('TLP:')])
        pap_count = len([k for k in self.marking_cache if k.startswith('PAP:')])
        custom_count = len([
            k for k in self.marking_cache
            if not k.startswith('TLP:') and not k.startswith('PAP:')
        ])

        return {
            "initialized": self.initialized,
            "total_markings": len(self.marking_cache),
            "tlp_markings": tlp_count,
            "pap_markings": pap_count,
            "custom_markings": custom_count,
            "cache_timestamp": self.cache_timestamp.isoformat() if self.cache_timestamp else None,
            "initialization_error": self.initialization_error
        }


# Export
__all__ = ["TLPMarkingRegistry"]
