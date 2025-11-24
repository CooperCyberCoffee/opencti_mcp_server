"""
Cooper Cyber Coffee OpenCTI MCP Server - MCP Context Wrapper
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

Contact: matt@coopercybercoffee.com

MCP Context wrapper for progress reporting and cancellation.
This provides a compatibility layer for MCP v0.4.1 features.
"""

import asyncio
import structlog
from typing import Optional, Any


class CancellationToken:
    """
    Simple cancellation token for MCP tool operations.

    Provides a way to check if user has cancelled the operation.
    """

    def __init__(self):
        self._cancelled = False
        self._event = asyncio.Event()

    def cancel(self):
        """Mark this operation as cancelled."""
        self._cancelled = True
        self._event.set()

    def is_cancelled(self) -> bool:
        """Check if operation has been cancelled."""
        return self._cancelled

    async def wait_cancelled(self):
        """Wait until operation is cancelled."""
        await self._event.wait()


class MCPToolContext:
    """
    MCP Tool Context for progress reporting and cancellation.

    Provides compatibility layer for MCP SDK progress/cancellation features.
    If MCP SDK provides native context, this can be replaced.

    Args:
        logger: Structured logger for progress messages
        cancellation_token: Optional cancellation token

    Example:
        >>> ctx = MCPToolContext(logger)
        >>> await ctx.send_progress(50, 100, "Processing...")
        >>> if ctx.cancellation_token and ctx.cancellation_token.is_cancelled():
        ...     raise OperationCancelled()
    """

    def __init__(
        self,
        logger: Optional[structlog.BoundLogger] = None,
        cancellation_token: Optional[CancellationToken] = None
    ):
        self.logger = logger or structlog.get_logger()
        self.cancellation_token = cancellation_token or CancellationToken()
        self._progress_enabled = True  # Can be disabled if MCP client doesn't support it

    async def send_progress(
        self,
        progress: int,
        total: int,
        message: str
    ) -> None:
        """
        Send progress update to MCP client.

        Args:
            progress: Current progress (0 to total)
            total: Total items/steps
            message: User-friendly progress message

        Example:
            >>> await ctx.send_progress(500, 1000, "Fetching indicators... 50%")
        """
        if not self._progress_enabled:
            return

        # For now, log to stderr with special marker
        # MCP client can parse these logs for progress UI
        percentage = int((progress / total) * 100) if total > 0 else 100

        self.logger.info(
            "mcp_progress",
            progress=progress,
            total=total,
            percentage=percentage,
            message=message,
            _mcp_progress=True  # Special marker for MCP client parsing
        )

    async def send_log(
        self,
        level: str,
        message: str,
        **kwargs
    ) -> None:
        """
        Send log message to MCP client.

        Args:
            level: Log level ("debug", "info", "warning", "error")
            message: Log message
            **kwargs: Additional context fields

        Example:
            >>> await ctx.send_log("info", "Starting OpenCTI query...")
        """
        log_method = getattr(self.logger, level, self.logger.info)
        log_method("mcp_log", message=message, **kwargs)

    def disable_progress(self):
        """Disable progress reporting (for fast operations)."""
        self._progress_enabled = False

    def enable_progress(self):
        """Enable progress reporting."""
        self._progress_enabled = True
