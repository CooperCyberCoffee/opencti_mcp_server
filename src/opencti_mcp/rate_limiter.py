"""
Cooper Cyber Coffee OpenCTI MCP Server - Rate Limiting
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

Contact: matt@coopercybercoffee.com

Token bucket rate limiter for DoS protection.
"""

import time
import logging
from collections import deque
from typing import Dict, Tuple, List, Any
from mcp import types
import functools


class RateLimiter:
    """
    Token bucket rate limiter for MCP tool calls.

    Prevents DoS attacks (accidental or malicious) by limiting:
    - Calls per minute (global across all tools)
    - Maximum response size
    - Query timeout

    Configuration via environment variables:
    - RATE_LIMIT_CALLS_PER_MINUTE (default: 60)
    - MAX_RESPONSE_SIZE_MB (default: 10)
    - QUERY_TIMEOUT_SECONDS (default: 30)

    Example:
        >>> limiter = RateLimiter(calls_per_minute=60)
        >>> allowed, message, reset_in = limiter.check_rate_limit()
        >>> if not allowed:
        >>>     return limiter.get_rate_limit_error(reset_in)
    """

    def __init__(
        self,
        calls_per_minute: int = 60,
        max_response_size_mb: int = 10,
        query_timeout_seconds: int = 30
    ):
        """
        Initialize rate limiter.

        Args:
            calls_per_minute: Maximum calls per minute (global)
            max_response_size_mb: Maximum response size in MB
            query_timeout_seconds: Query timeout in seconds
        """
        self.calls_per_minute = calls_per_minute
        self.max_response_size_mb = max_response_size_mb
        self.query_timeout_seconds = query_timeout_seconds

        # Track call timestamps (global across all clients/tools)
        # Using deque for efficient old timestamp removal
        self.call_timestamps: deque = deque()

        self.logger = logging.getLogger(__name__)

        self.logger.info(
            f"✅ Rate limiter initialized: {calls_per_minute} calls/min, "
            f"max {max_response_size_mb}MB response, "
            f"{query_timeout_seconds}s timeout"
        )

    def check_rate_limit(self) -> Tuple[bool, str, int]:
        """
        Check if request is within rate limit.

        Returns:
            Tuple of (allowed: bool, message: str, reset_in_seconds: int)
        """
        now = time.time()
        minute_ago = now - 60

        # Remove timestamps older than 1 minute
        while self.call_timestamps and self.call_timestamps[0] < minute_ago:
            self.call_timestamps.popleft()

        # Check if under limit
        if len(self.call_timestamps) >= self.calls_per_minute:
            # Calculate when rate limit resets
            oldest = self.call_timestamps[0]
            reset_in = int(oldest + 60 - now) + 1  # +1 to avoid 0 second message

            message = (
                f"Rate limit exceeded: {self.calls_per_minute} calls/minute. "
                f"Reset in {reset_in} seconds."
            )

            self.logger.warning(
                f"⚠️  Rate limit exceeded: {len(self.call_timestamps)}/{self.calls_per_minute} "
                f"calls in window, reset in {reset_in}s"
            )
            return (False, message, reset_in)

        # Under limit - add timestamp
        self.call_timestamps.append(now)

        self.logger.debug(
            f"✅ Rate limit check passed: {len(self.call_timestamps)}/{self.calls_per_minute} calls"
        )

        return (True, "", 0)

    def get_rate_limit_error(self, reset_in_seconds: int) -> List[types.TextContent]:
        """
        Generate user-friendly rate limit error message.

        Args:
            reset_in_seconds: Seconds until rate limit resets

        Returns:
            List of TextContent with error message
        """
        return [types.TextContent(
            type="text",
            text=(
                f"❌ Rate Limit Exceeded\n\n"
                f"You've reached the maximum of **{self.calls_per_minute} calls per minute**.\n\n"
                f"**Rate Limit Information:**\n"
                f"- Limit: {self.calls_per_minute} calls/minute\n"
                f"- Current calls in window: {len(self.call_timestamps)}\n"
                f"- Reset in: {reset_in_seconds} seconds\n\n"
                f"**What to do:**\n"
                f"1. Wait {reset_in_seconds} seconds before retrying\n"
                f"2. Reduce query frequency in your workflow\n"
                f"3. Consider batching requests where possible\n\n"
                f"**Why rate limiting?**\n"
                f"Rate limiting protects both the OpenCTI backend and Claude API from overload, "
                f"ensuring reliable service for all users.\n\n"
                f"**Need higher limits?** Contact: matt@coopercybercoffee.com"
            )
        )]

    def get_stats(self) -> Dict[str, Any]:
        """
        Get rate limiter statistics for monitoring.

        Returns:
            Dict with statistics
        """
        return {
            "calls_per_minute": self.calls_per_minute,
            "current_calls_in_window": len(self.call_timestamps),
            "calls_available": max(0, self.calls_per_minute - len(self.call_timestamps)),
            "max_response_size_mb": self.max_response_size_mb,
            "query_timeout_seconds": self.query_timeout_seconds
        }


def with_rate_limiting(rate_limiter: 'RateLimiter'):
    """
    Decorator that applies rate limiting to MCP tool handlers.

    This decorator should be applied BEFORE @with_tlp_filtering to ensure
    rate limiting happens first (don't waste resources on rate-limited calls).

    Args:
        rate_limiter: RateLimiter instance

    Returns:
        Decorated function with rate limiting

    Example:
        >>> @with_rate_limiting(server.rate_limiter)
        >>> @with_tlp_filtering("get_indicators")
        >>> async def handle_get_indicators(self, arguments):
        >>>     return await self.opencti_client.get_indicators_scoped(...)
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(self, arguments: Dict):
            # Check rate limit
            allowed, message, reset_in = rate_limiter.check_rate_limit()

            if not allowed:
                # Return rate limit error
                return rate_limiter.get_rate_limit_error(reset_in)

            # Under limit - proceed with tool call
            return await func(self, arguments)

        return wrapper
    return decorator


# Export
__all__ = ["RateLimiter", "with_rate_limiting"]
