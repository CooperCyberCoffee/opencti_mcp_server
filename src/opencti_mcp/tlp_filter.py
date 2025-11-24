"""
Cooper Cyber Coffee OpenCTI MCP Server - TLP Filtering
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

Traffic Light Protocol (TLP) filtering for threat intelligence data.
Filters OpenCTI objects based on configured TLP policy before sending
to Claude for analysis. Ensures only appropriately-marked data is
processed by cloud LLM.

CISA TLP Guidance:
https://www.cisa.gov/news-events/news/traffic-light-protocol-tlp-definitions-and-usage
"""

import yaml
import logging
import os
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path


class TLPFilter:
    """
    Traffic Light Protocol (TLP) filtering for threat intelligence data.

    Filters OpenCTI objects based on configured TLP policy before sending
    to Claude for analysis. Ensures only appropriately-marked data is
    processed by cloud LLM.

    CISA TLP Guidance:
    https://www.cisa.gov/news-events/news/traffic-light-protocol-tlp-definitions-and-usage
    """

    # TLP classification priority (for determining highest classification)
    TLP_PRIORITY = {
        "TLP:RED": 5,
        "TLP:AMBER+STRICT": 4,
        "TLP:AMBER": 3,
        "TLP:GREEN": 2,
        "TLP:CLEAR": 1,
        "TLP:WHITE": 1,  # Legacy, equivalent to TLP:CLEAR
    }

    def __init__(self, config_path: str = "config/tlp_policy.yaml"):
        """
        Initialize TLP filter with policy configuration.

        Args:
            config_path: Path to TLP policy YAML configuration file

        Raises:
            ValueError: If config_path contains path traversal or is outside project
        """
        self.logger = logging.getLogger(__name__)

        # Validate and resolve config path (security check)
        try:
            self.config_path = self._validate_config_path(config_path)
        except ValueError as e:
            self.logger.error(f"Invalid config path: {e}")
            # Fall back to default path if validation fails
            self.config_path = Path("config/tlp_policy.yaml")

        self.policy = self._load_policy()

        # Log policy loaded
        self.logger.info(
            f"TLP policy loaded: {len(self.policy['allowed_markings'])} allowed markings, "
            f"allow_unmarked={self.policy['allow_unmarked']}, "
            f"strict_mode={self.policy['strict_mode']}"
        )

        # Warn if allow_unmarked is true (security risk)
        if self.policy.get("allow_unmarked", False):
            self.logger.warning(
                "TLP policy allows unmarked objects - this may send sensitive data to Claude. "
                "Set allow_unmarked=false for better security."
            )

    def _validate_config_path(self, config_path: str) -> Path:
        """
        Validate configuration file path to prevent path traversal attacks.

        Security checks:
        - Resolves to absolute path
        - No parent directory traversal (..)
        - Must be regular file (if exists)
        - Not a symlink to external location
        - Readable permissions

        Args:
            config_path: Path to config file (relative or absolute)

        Returns:
            Validated absolute Path object

        Raises:
            ValueError: If path is suspicious or invalid
        """
        # Convert to Path and resolve to absolute
        path = Path(config_path).resolve()

        # Get current working directory as project root
        # (in production this is the repo root)
        project_root = Path.cwd().resolve()

        # Check for suspicious patterns in path string
        path_str = str(path)
        if '..' in path_str:
            raise ValueError(
                f"Path traversal detected in config path: {config_path}. "
                f"Path contains '..', which is not allowed."
            )

        # Check path is within or relative to project root
        # Allow paths within project or common config locations
        try:
            # Try to make path relative to project root
            relative_path = path.relative_to(project_root)
            # Check it doesn't go outside project
            if str(relative_path).startswith('..'):
                raise ValueError(
                    f"Config path outside project directory: {path}. "
                    f"Project root: {project_root}"
                )
        except ValueError:
            # Path is not relative to project_root
            # Allow /etc/opencti_mcp/ for system-wide config
            allowed_system_paths = [
                Path('/etc/opencti_mcp'),
                Path('/etc/opt/opencti_mcp'),
            ]

            path_allowed = False
            for allowed_path in allowed_system_paths:
                try:
                    path.relative_to(allowed_path)
                    path_allowed = True
                    break
                except ValueError:
                    continue

            if not path_allowed:
                raise ValueError(
                    f"Config path outside project and not in allowed system paths: {path}"
                )

        # If file exists, validate it
        if path.exists():
            # Check is regular file
            if not path.is_file():
                raise ValueError(f"Config path is not a regular file: {path}")

            # Check readable
            if not os.access(path, os.R_OK):
                raise ValueError(f"Config file not readable: {path}")

            # Warn if world-writable (security risk)
            if os.name != 'nt':  # Unix-like systems only
                mode = path.stat().st_mode
                if mode & 0o002:  # World-writable
                    self.logger.warning(
                        f"Config file is world-writable (security risk): {path}. "
                        f"Recommend: chmod 644 {path}"
                    )

        return path

    def _validate_policy_structure(self, policy: Dict[str, Any]) -> None:
        """
        Validate TLP policy has required fields with correct types.

        Args:
            policy: Policy dictionary from YAML

        Raises:
            ValueError: If policy structure is invalid
        """
        required_fields = {
            'allowed_markings': list,
            'allow_unmarked': bool,
            'strict_mode': bool,
        }

        for field, expected_type in required_fields.items():
            if field not in policy:
                raise ValueError(f"Missing required field in TLP policy: {field}")
            if not isinstance(policy[field], expected_type):
                raise ValueError(
                    f"Field '{field}' must be {expected_type.__name__}, "
                    f"got {type(policy[field]).__name__}"
                )

        # Validate allowed_markings is not empty (unless custom markings present)
        if not policy['allowed_markings'] and not policy.get('custom_allowed_markings'):
            raise ValueError("TLP policy must allow at least one marking")

        # Validate no duplicate markings
        all_markings = policy['allowed_markings'] + policy.get('custom_allowed_markings', [])
        if len(all_markings) != len(set(all_markings)):
            self.logger.warning("Duplicate markings detected in TLP policy")

    def _load_policy(self) -> Dict[str, Any]:
        """
        Load TLP policy from YAML config file with security hardening.

        Security measures:
        - Uses yaml.safe_load() not yaml.load() (prevents code execution)
        - Validates policy structure
        - Checks file permissions
        - Sanitizes marking strings

        Returns:
            Dictionary containing validated policy configuration

        Raises:
            None - always returns valid policy (default if load fails)
        """
        # Default policy (safest - TLP:CLEAR only)
        default_policy = {
            "allowed_markings": ["TLP:CLEAR", "TLP:WHITE"],
            "allow_unmarked": False,
            "custom_allowed_markings": [],
            "strict_mode": True,
            "log_filtered_objects": True,
            "log_level": "INFO",
            "policy_version": "1.0"
        }

        # Try to load config file
        if not self.config_path.exists():
            self.logger.warning(
                f"TLP policy file not found at {self.config_path}, using default policy (TLP:CLEAR only)"
            )
            return default_policy

        try:
            # Check file permissions before loading
            if os.name != 'nt':  # Unix-like systems only
                mode = self.config_path.stat().st_mode
                if mode & 0o002:  # World-writable
                    self.logger.warning(
                        f"TLP policy file is world-writable (security risk): {self.config_path}"
                    )

            # Load YAML using safe_load (SECURITY: never use yaml.load())
            # yaml.safe_load() only constructs simple Python objects (dict, list, str, etc.)
            # yaml.load() can execute arbitrary Python code - NEVER use it!
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            if not config:
                self.logger.warning("TLP policy file is empty, using default policy")
                return default_policy

            if not isinstance(config, dict):
                self.logger.error(
                    f"TLP policy must be a YAML dictionary, got {type(config).__name__}. "
                    f"Using default policy."
                )
                return default_policy

            # Merge with defaults for missing keys
            policy = {**default_policy, **config}

            # Validate policy structure
            try:
                self._validate_policy_structure(policy)
            except ValueError as e:
                self.logger.error(f"Invalid TLP policy structure: {e}. Using default policy.")
                return default_policy

            # Normalize markings to uppercase for comparison
            policy['allowed_markings'] = [
                m.upper() for m in policy.get('allowed_markings', [])
            ]

            # Combine allowed_markings + custom_allowed_markings
            custom = policy.get('custom_allowed_markings', [])
            if custom:
                policy['allowed_markings'].extend([m.upper() for m in custom])

            # Remove duplicates
            policy['allowed_markings'] = list(set(policy['allowed_markings']))

            # Warn about non-standard TLP levels
            standard_tlp = {
                "TLP:RED", "TLP:AMBER+STRICT", "TLP:AMBER",
                "TLP:GREEN", "TLP:CLEAR", "TLP:WHITE"
            }
            non_standard = set(policy['allowed_markings']) - standard_tlp
            if non_standard:
                self.logger.warning(
                    f"Non-standard TLP markings configured: {non_standard}. "
                    f"Ensure these match your OpenCTI marking definitions."
                )

            self.logger.info(f"TLP policy loaded successfully from {self.config_path}")
            return policy

        except yaml.YAMLError as e:
            self.logger.error(
                f"Failed to parse TLP policy YAML: {e}. "
                f"Check syntax at line {e.problem_mark.line if hasattr(e, 'problem_mark') else 'unknown'}. "
                f"Using default policy."
            )
            return default_policy
        except Exception as e:
            self.logger.error(f"Failed to load TLP policy: {e}. Using default policy.")
            return default_policy

    def _sanitize_marking(self, marking: str) -> str:
        """
        Sanitize TLP marking string to prevent injection attacks.

        Security measures:
        - Remove null bytes
        - Strip whitespace
        - Normalize case
        - Limit length
        - Remove control characters
        - Detect injection patterns

        Args:
            marking: Raw marking string from OpenCTI

        Returns:
            Sanitized marking string (uppercase)

        Raises:
            ValueError: If marking contains suspicious patterns or is invalid
        """
        if not isinstance(marking, str):
            raise ValueError(f"Marking must be string, got {type(marking).__name__}")

        # Remove null bytes (potential injection)
        if '\x00' in marking:
            self.logger.warning(f"Null byte detected in marking, rejecting")
            raise ValueError("Marking contains null bytes")

        # Strip whitespace
        marking = marking.strip()

        # Check if empty after stripping
        if not marking:
            raise ValueError("Marking is empty after sanitization")

        # Limit length (reasonable max: 100 chars for custom markings)
        if len(marking) > 100:
            self.logger.warning(f"Marking too long ({len(marking)} chars), truncating")
            marking = marking[:100]

        # Remove control characters except newline/tab (but warn)
        clean_marking = ''
        has_control_chars = False
        for char in marking:
            if char.isprintable() or char in '\n\t':
                clean_marking += char
            else:
                has_control_chars = True

        if has_control_chars:
            self.logger.warning(f"Control characters removed from marking: {repr(marking)}")
            marking = clean_marking

        # Check for suspicious patterns (SQL injection, script injection, etc.)
        suspicious_patterns = [
            ('DROP TABLE', 'SQL injection'),
            ('DELETE FROM', 'SQL injection'),
            ('INSERT INTO', 'SQL injection'),
            ('UPDATE SET', 'SQL injection'),
            ('<SCRIPT', 'XSS injection'),
            ('JAVASCRIPT:', 'XSS injection'),
            ('${', 'Template injection'),
            ('{{', 'Template injection'),
            ('#{', 'Template injection'),
            ('UNION SELECT', 'SQL injection'),
            ('OR 1=1', 'SQL injection'),
            ("'; --", 'SQL injection'),
        ]

        marking_upper = marking.upper()
        for pattern, attack_type in suspicious_patterns:
            if pattern in marking_upper:
                self.logger.error(
                    f"Suspicious pattern detected in marking: {pattern} ({attack_type})"
                )
                raise ValueError(f"Invalid marking: {attack_type} pattern detected")

        # Normalize to uppercase for comparison
        return marking.upper()

    def get_object_markings(self, obj: Dict[str, Any]) -> List[str]:
        """
        Extract and sanitize TLP markings from OpenCTI object.

        OpenCTI stores markings in:
        - objectMarking field (list of marking definition objects)
        - Each marking has 'definition' and 'definition_type' fields

        Security: All markings are sanitized to prevent injection attacks

        Args:
            obj: OpenCTI object dictionary

        Returns:
            List of sanitized marking strings (e.g., ["TLP:CLEAR", "PAP:WHITE"])
            All markings normalized to uppercase for comparison
        """
        markings = []

        # Get objectMarking field
        object_marking = obj.get("objectMarking", [])

        if not object_marking:
            return []

        # Extract and sanitize marking definitions
        for marking in object_marking:
            try:
                # Handle both marking objects and direct strings
                if isinstance(marking, dict):
                    definition = marking.get("definition", "")
                elif isinstance(marking, str):
                    definition = marking
                else:
                    self.logger.warning(f"Unexpected marking type: {type(marking)}")
                    continue

                if definition:
                    # Sanitize marking (protects against injection)
                    sanitized = self._sanitize_marking(definition)
                    markings.append(sanitized)

            except ValueError as e:
                # Invalid/malicious marking detected - log and skip
                obj_id = obj.get('id', 'unknown')
                self.logger.error(
                    f"Invalid marking detected in object {obj_id}: {e}. "
                    f"Skipping this marking."
                )
                # Don't add invalid marking to list
                continue

        return markings

    def is_object_allowed(self, obj: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Check if object is allowed based on TLP policy.

        Args:
            obj: OpenCTI object dictionary

        Returns:
            Tuple of (allowed: bool, reason: str)

        Reasons for rejection:
        - "no_marking" - Object has no TLP marking and allow_unmarked=false
        - "tlp_restricted" - Object has TLP marking not in allowed list
        - "strict_violation" - Strict mode enabled and object rejected
        """
        # Get markings from object
        markings = self.get_object_markings(obj)

        # If no markings
        if not markings:
            if self.policy['allow_unmarked']:
                return (True, "unmarked_allowed")
            else:
                return (False, "no_marking")

        # Check if ANY marking is in allowed list
        allowed_markings_set = set(self.policy['allowed_markings'])
        object_markings_set = set(markings)

        # If there's any overlap, allow the object
        if object_markings_set & allowed_markings_set:
            return (True, "allowed_marking")

        # No allowed markings found
        return (False, "tlp_restricted")

    def filter_objects(self, objects: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Filter list of OpenCTI objects based on TLP policy.

        Args:
            objects: List of OpenCTI object dictionaries

        Returns:
            Tuple of (filtered_objects, filter_stats)

        filter_stats contains:
        - total_objects: int
        - allowed_objects: int
        - filtered_objects: int
        - filter_reasons: Dict[str, int] (counts by reason)
        """
        filtered = []
        filter_reasons = {}

        # Iterate through objects
        for obj in objects:
            allowed, reason = self.is_object_allowed(obj)

            if allowed:
                filtered.append(obj)
            else:
                # Track rejection reason
                filter_reasons[reason] = filter_reasons.get(reason, 0) + 1

                # Log filtered object if configured
                if self.policy.get('log_filtered_objects', True):
                    obj_id = obj.get('id', 'unknown')
                    obj_name = obj.get('name', 'unknown')
                    markings = self.get_object_markings(obj)
                    self.logger.warning(
                        f"Filtered object: id={obj_id}, name={obj_name}, "
                        f"markings={markings}, reason={reason}"
                    )

        # Calculate statistics
        stats = {
            "total_objects": len(objects),
            "allowed_objects": len(filtered),
            "filtered_objects": len(objects) - len(filtered),
            "filter_reasons": filter_reasons
        }

        # If strict_mode and ANY filtered: return empty list with zero stats
        if self.policy['strict_mode'] and stats['filtered_objects'] > 0:
            self.logger.error(
                f"Strict mode: Rejecting entire query result. "
                f"{stats['filtered_objects']}/{stats['total_objects']} objects filtered. "
                f"Reasons: {filter_reasons}"
            )
            # Return empty stats - no information leakage about what was filtered
            # To external systems (Claude), this looks like "no results found"
            empty_stats = {
                "total_objects": 0,
                "allowed_objects": 0,
                "filtered_objects": 0,
                "filter_reasons": {}
            }
            return ([], empty_stats)

        # Return filtered list + stats
        return (filtered, stats)

    def get_classification_label(self, obj: Dict[str, Any]) -> str:
        """
        Get classification label for audit logging.

        Returns highest classification marking present, or "UNMARKED"
        Priority: RED > AMBER+STRICT > AMBER > GREEN > CLEAR

        Args:
            obj: OpenCTI object dictionary

        Returns:
            Classification label string (e.g., "TLP:CLEAR", "TLP:AMBER", "UNMARKED")
        """
        markings = self.get_object_markings(obj)

        if not markings:
            return "UNMARKED"

        # Find highest priority marking
        highest_priority = 0
        highest_marking = "UNMARKED"

        for marking in markings:
            # Only consider TLP markings for classification
            if marking.startswith("TLP:"):
                priority = self.TLP_PRIORITY.get(marking, 0)
                if priority > highest_priority:
                    highest_priority = priority
                    highest_marking = marking

        return highest_marking if highest_priority > 0 else "UNMARKED"


def with_tlp_filtering(tool_name: str):
    """
    Decorator that applies TLP filtering to MCP tool handler results.

    This centralizes TLP filtering logic that was previously duplicated across
    all tool handlers. The decorator:
    1. Calls the original tool handler
    2. Applies TLP filtering to results
    3. Logs filtering statistics
    4. Handles policy violations (strict mode)
    5. Returns filtered results or error

    Args:
        tool_name: Name of the tool (for logging and error messages)

    Returns:
        Decorated function that includes TLP filtering

    Example:
        >>> @with_tlp_filtering("get_threat_actor_ttps")
        >>> async def handle_get_threat_actor_ttps(self, arguments):
        >>>     results = await self.opencti_client.get_ttps(...)
        >>>     return results

    Security Notes:
        - Filtering happens BEFORE results returned to Claude
        - Strict mode prevents partial data leakage
        - All filtering logged for audit compliance
        - Errors return user-friendly messages with remediation steps

    Implementation Note:
        This decorator expects the handler to return raw OpenCTI objects
        (list of dicts). The decorator will filter these objects and return
        them to the handler, which can then format them for display.
    """
    import functools
    from mcp import types

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(self, arguments: Dict[str, Any]):
            """Wrapper function that applies TLP filtering to tool results."""

            # Call the original tool handler to get raw results
            # The handler should return either:
            # 1. List of OpenCTI objects (dicts) - will be filtered
            # 2. List of types.TextContent - already formatted, pass through
            # 3. Empty list or None - pass through
            try:
                raw_results = await func(self, arguments)
            except Exception as e:
                # If handler raises exception, propagate it
                self.logger.error(f"Error in {tool_name} handler: {e}")
                raise

            # If results is already formatted (types.TextContent), return as-is
            if isinstance(raw_results, list) and len(raw_results) > 0:
                if isinstance(raw_results[0], types.TextContent):
                    # Already formatted (probably an error message), return unchanged
                    return raw_results

            # If no results or not a list of objects, return as-is
            if not raw_results:
                return raw_results

            # Verify we have a list of dict objects to filter
            if not isinstance(raw_results, list):
                self.logger.warning(
                    f"{tool_name}: Expected list of objects, got {type(raw_results)}. "
                    f"Returning unchanged."
                )
                return raw_results

            # Check if list contains dicts (OpenCTI objects)
            if not all(isinstance(obj, dict) for obj in raw_results):
                self.logger.warning(
                    f"{tool_name}: List contains non-dict objects. Returning unchanged."
                )
                return raw_results

            # Apply TLP filtering
            try:
                filtered_results, stats = self.tlp_filter.filter_objects(raw_results)

                # Log filtering statistics if objects were filtered
                if stats['filtered_objects'] > 0:
                    self.logger.warning(
                        f"TLP filter [{tool_name}]: {stats['filtered_objects']}/{stats['total_objects']} "
                        f"objects filtered. Reasons: {stats['filter_reasons']}"
                    )

                # Handle strict mode: if policy filtered everything, return error
                if self.tlp_filter.policy.get('strict_mode', True):
                    if stats['filtered_objects'] > 0 and stats['allowed_objects'] == 0:
                        # All objects were filtered - return error message
                        return [types.TextContent(
                            type="text",
                            text=(
                                f"❌ TLP Policy Violation - {tool_name}\n\n"
                                f"All {stats['total_objects']} objects were filtered by TLP policy.\n\n"
                                f"**Filter Statistics:**\n"
                                f"- Total objects: {stats['total_objects']}\n"
                                f"- Filtered: {stats['filtered_objects']}\n"
                                f"- Reasons: {stats['filter_reasons']}\n\n"
                                f"**Resolution:**\n"
                                f"1. Review your TLP policy in `config/tlp_policy.yaml`\n"
                                f"2. If using sensitive data, configure local LLM deployment\n"
                                f"3. Contact your security team for policy guidance\n\n"
                                f"**Current Policy:**\n"
                                f"- Allowed markings: {self.tlp_filter.policy.get('allowed_markings', [])}\n"
                                f"- Allow unmarked: {self.tlp_filter.policy.get('allow_unmarked', False)}\n"
                                f"- Strict mode: {self.tlp_filter.policy.get('strict_mode', True)}\n\n"
                                f"**Security Note:** This filtering protects sensitive threat intelligence "
                                f"from being sent to cloud LLM services. For classified/CUI data, use "
                                f"local LLM deployment (see README.md)."
                            )
                        )]

                # Return filtered results
                # Handler will format these for display
                return filtered_results

            except Exception as e:
                # TLP filtering error - log and return error message
                self.logger.error(f"TLP filtering error in {tool_name}: {e}")
                return [types.TextContent(
                    type="text",
                    text=(
                        f"❌ TLP Filtering Error\n\n"
                        f"An error occurred while filtering results: {str(e)}\n\n"
                        f"Please check your TLP policy configuration in `config/tlp_policy.yaml` "
                        f"and ensure it is valid YAML with the required fields.\n\n"
                        f"If the problem persists, contact support: matt@coopercybercoffee.com"
                    )
                )]

        return wrapper
    return decorator


# Export
__all__ = ["TLPFilter", "with_tlp_filtering"]
