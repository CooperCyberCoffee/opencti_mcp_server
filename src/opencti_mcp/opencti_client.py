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
                raise ValueError(
                    f"OpenCTI 6.x required for Cooper Cyber Coffee MCP Server. "
                    f"Found version {version}. Please upgrade your OpenCTI instance."
                )

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

    async def close(self):
        """Close the client and clean up resources."""
        if self._executor:
            self._executor.shutdown(wait=True)
            self.logger.info("OpenCTI client executor shutdown complete")
