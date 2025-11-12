"""
Cooper Cyber Coffee OpenCTI MCP Server - Utility Functions
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

For consulting and enterprise inquiries: business@coopercybercoffee.com
"""

import os
import logging
import re
import sys
from typing import Dict, Any, Optional
from dotenv import load_dotenv
import structlog


def setup_logging(log_level: str = "INFO") -> structlog.BoundLogger:
    """Configure structured logging for the MCP server.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Configured structured logger instance

    Example:
        >>> logger = setup_logging("INFO")
        >>> logger.info("server_started", version="1.0.0")
    """
    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, log_level.upper(), logging.INFO),
        stream=sys.stderr  # CRITICAL: All logs must go to stderr for MCP protocol
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer()
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False
    )

    logger = structlog.get_logger()
    logger.info(
        "logging_configured",
        level=log_level,
        project="Cooper Cyber Coffee OpenCTI MCP Server"
    )
    return logger


def load_config() -> Dict[str, Any]:
    """Load configuration from environment variables with validation.

    Loads from .env file and validates required OpenCTI configuration.

    Returns:
        Dictionary containing validated configuration

    Raises:
        ValueError: If required configuration is missing
        ConnectionError: If OpenCTI URL is invalid

    Example:
        >>> config = load_config()
        >>> print(config['opencti_url'])
        'http://localhost:8080'
    """
    # Load .env file if it exists
    load_dotenv()

    # Required configuration
    opencti_url = os.getenv("OPENCTI_URL")
    opencti_token = os.getenv("OPENCTI_TOKEN")

    if not opencti_url:
        raise ValueError(
            "OPENCTI_URL environment variable is required. "
            "Please set it in your .env file or environment. "
            "Example: OPENCTI_URL=http://localhost:8080"
        )

    if not opencti_token:
        raise ValueError(
            "OPENCTI_TOKEN environment variable is required. "
            "Please set it in your .env file or environment. "
            "Get your token from OpenCTI Settings > API Access"
        )

    # Optional configuration with defaults
    config = {
        # OpenCTI Configuration
        "opencti_url": opencti_url.rstrip("/"),
        "opencti_token": opencti_token,
        "opencti_ssl_verify": os.getenv("OPENCTI_SSL_VERIFY", "false").lower() == "true",

        # MCP Server Configuration
        "mcp_server_port": int(os.getenv("MCP_SERVER_PORT", "8000")),
        "mcp_server_host": os.getenv("MCP_SERVER_HOST", "0.0.0.0"),
        "log_level": os.getenv("LOG_LEVEL", "INFO"),

        # Performance Configuration
        "timeout_seconds": int(os.getenv("TIMEOUT_SECONDS", "30")),
        "max_indicators_per_query": int(os.getenv("MAX_INDICATORS_PER_QUERY", "1000")),
        "enable_query_caching": os.getenv("ENABLE_QUERY_CACHING", "true").lower() == "true",
        "cache_ttl_seconds": int(os.getenv("CACHE_TTL_SECONDS", "300")),
        "thread_pool_size": int(os.getenv("THREAD_POOL_SIZE", "4")),

        # Enterprise Features
        "enable_health_checks": os.getenv("ENABLE_HEALTH_CHECKS", "true").lower() == "true",
        "enable_metrics": os.getenv("ENABLE_METRICS", "true").lower() == "true",
        "enable_audit_logging": os.getenv("ENABLE_AUDIT_LOGGING", "true").lower() == "true",
    }

    # Validate URL format
    if not validate_url(config["opencti_url"]):
        raise ConnectionError(
            f"Invalid OPENCTI_URL format: {config['opencti_url']}. "
            "Expected format: http://hostname:port or https://hostname:port"
        )

    return config


def validate_url(url: str) -> bool:
    """Validate URL format for OpenCTI endpoint.

    Args:
        url: URL string to validate

    Returns:
        True if URL is valid, False otherwise

    Example:
        >>> validate_url("http://localhost:8080")
        True
        >>> validate_url("invalid-url")
        False
    """
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP address
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    return bool(url_pattern.match(url))


def validate_hash(hash_value: str) -> Optional[str]:
    """Validate and identify hash type (MD5, SHA1, SHA256).

    Args:
        hash_value: Hash string to validate

    Returns:
        Hash type ('md5', 'sha1', 'sha256') or None if invalid

    Example:
        >>> validate_hash("44d88612fea8a8f36de82e1278abb02f")
        'md5'
        >>> validate_hash("invalid")
        None
    """
    hash_value = hash_value.strip().lower()

    # Check if it's valid hex
    if not re.match(r'^[a-f0-9]+$', hash_value):
        return None

    # Identify hash type by length
    hash_lengths = {
        32: 'md5',
        40: 'sha1',
        64: 'sha256'
    }

    return hash_lengths.get(len(hash_value))


def format_error_message(error: Exception, context: str = "") -> str:
    """Format exception as user-friendly error message.

    Args:
        error: Exception to format
        context: Additional context about where the error occurred

    Returns:
        Formatted error message string

    Example:
        >>> try:
        ...     raise ValueError("Invalid input")
        ... except Exception as e:
        ...     msg = format_error_message(e, "validation")
        ...     print(msg)
        'Error during validation: Invalid input'
    """
    error_type = type(error).__name__
    error_msg = str(error)

    if context:
        return f"Error during {context}: {error_msg} ({error_type})"
    return f"{error_type}: {error_msg}"


def sanitize_indicator_pattern(pattern: str) -> str:
    """Sanitize indicator pattern for safe display.

    Removes potentially dangerous characters while preserving
    indicator readability.

    Args:
        pattern: Indicator pattern to sanitize

    Returns:
        Sanitized pattern string

    Example:
        >>> sanitize_indicator_pattern("malware.exe")
        'malware.exe'
    """
    # Remove control characters but keep standard punctuation
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', pattern)
    return sanitized.strip()


def get_version_info() -> Dict[str, str]:
    """Get version information for the MCP server.

    Returns:
        Dictionary with version metadata

    Example:
        >>> info = get_version_info()
        >>> print(info['version'])
        '1.0.0'
    """
    return {
        "version": "1.0.0",
        "name": "Cooper Cyber Coffee OpenCTI MCP Server",
        "author": "Matthew Hopkins / Cooper Cyber Coffee",
        "license": "MIT",
        "opencti_version_required": "6.x",
        "project_url": "https://coopercybercoffee.com",
        "contact": "business@coopercybercoffee.com"
    }


def format_indicator_summary(indicators: list) -> Dict[str, Any]:
    """Generate summary statistics for a list of indicators.

    Args:
        indicators: List of indicator dictionaries

    Returns:
        Dictionary with summary statistics

    Example:
        >>> indicators = [{"indicator_types": ["file-sha256"], "confidence": 80}]
        >>> summary = format_indicator_summary(indicators)
        >>> print(summary['total_count'])
        1
    """
    if not indicators:
        return {
            "total_count": 0,
            "types": {},
            "avg_confidence": 0,
            "high_confidence_count": 0
        }

    type_counts = {}
    total_confidence = 0
    high_confidence = 0

    for indicator in indicators:
        # Count types
        for ioc_type in indicator.get("indicator_types", []):
            type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1

        # Track confidence
        confidence = indicator.get("confidence", 0)
        total_confidence += confidence
        if confidence >= 75:
            high_confidence += 1

    avg_confidence = total_confidence / len(indicators) if indicators else 0

    return {
        "total_count": len(indicators),
        "types": type_counts,
        "avg_confidence": round(avg_confidence, 2),
        "high_confidence_count": high_confidence,
        "high_confidence_percentage": round((high_confidence / len(indicators) * 100), 2) if indicators else 0
    }
