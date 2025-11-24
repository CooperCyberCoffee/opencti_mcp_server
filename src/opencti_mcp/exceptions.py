"""
Cooper Cyber Coffee OpenCTI MCP Server - Custom Exceptions
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

Contact: matt@coopercybercoffee.com
"""


class OperationCancelled(Exception):
    """
    Raised when a user cancels an operation via MCP cancellation token.

    This is a user-initiated action, not an error condition.
    Should be caught and handled gracefully with user-friendly message.

    Example:
        >>> try:
        ...     result = await long_operation(cancellation_token=token)
        ... except OperationCancelled:
        ...     return "Operation cancelled by user"
    """
    pass


class RateLimitExceeded(Exception):
    """
    Raised when rate limit is exceeded.

    Includes reset time information for user feedback.

    Args:
        message: Error message
        reset_in_seconds: Seconds until rate limit resets

    Example:
        >>> raise RateLimitExceeded("Rate limit exceeded", reset_in_seconds=30)
    """
    def __init__(self, message: str, reset_in_seconds: int):
        super().__init__(message)
        self.reset_in_seconds = reset_in_seconds
