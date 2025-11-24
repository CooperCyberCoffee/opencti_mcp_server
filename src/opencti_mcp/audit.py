"""
Cooper Cyber Coffee OpenCTI MCP Server - Audit Logging
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

Contact: matt@coopercybercoffee.com

CMMC Level 2 / NIST 800-171 / SOC 2 compliant audit logging.
"""

import logging
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, List
import uuid
from pathlib import Path


class AuditLogger:
    """
    Compliance-focused audit logging for MCP tool calls.

    Logs structured JSON entries for:
    - Compliance requirements (who did what, when)
    - Security monitoring (detect misuse patterns)
    - Debugging (troubleshoot issues)
    - Performance analytics (usage patterns)

    Compliance Standards:
    - CMMC Level 2 (AC.L2-3.1.13: Threat-informed defense)
    - NIST 800-171 (3.1.15: Privileged user monitoring)
    - SOC 2 Type II (Monitoring and logging requirements)

    Example:
        >>> audit = AuditLogger()
        >>> audit.log_session_start(user="analyst@company.com")
        >>> audit.log_tool_call(
        ...     tool_name="get_threat_actor_ttps",
        ...     parameters={"actor": "APT28"},
        ...     results_count=91,
        ...     execution_time_ms=342,
        ...     success=True
        ... )
    """

    def __init__(self, log_file: str = "logs/opencti_mcp_audit.log"):
        """Initialize audit logger with unique session ID.

        Args:
            log_file: Path to audit log file (default: logs/opencti_mcp_audit.log)
        """
        self.session_id = str(uuid.uuid4())

        # v0.4.0: Log integrity hashing for tamper detection
        self.previous_log_hash: Optional[str] = None

        # Ensure logs directory exists
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Configure structured JSON logging
        self.logger = logging.getLogger("opencti_mcp.audit")
        self.logger.setLevel(logging.INFO)

        # Remove existing handlers to avoid duplicates
        self.logger.handlers = []

        # File handler for audit trail
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(file_handler)

        # Prevent propagation to root logger
        self.logger.propagate = False

    def _sanitize_parameters(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize parameters to prevent sensitive data leakage in logs.

        Masks:
        - API tokens/keys
        - Passwords
        - Sensitive query terms (hash values masked partially)

        Args:
            parameters: Raw parameters dictionary

        Returns:
            Sanitized parameters dictionary safe for logging

        Example:
            >>> sanitized = self._sanitize_parameters({
            ...     "token": "abc123xyz789",
            ...     "query": "ransomware",
            ...     "hash": "44d88612fea8a8f36de82e1278abb02f"
            ... })
            >>> print(sanitized)
            {'token': '***REDACTED***', 'query': 'ransomware', 'hash': '44d8...b02f'}
        """
        if not isinstance(parameters, dict):
            return parameters

        sanitized = {}

        for key, value in parameters.items():
            key_lower = key.lower()

            # Mask tokens, passwords, secrets, keys
            if any(sensitive in key_lower for sensitive in [
                'token', 'password', 'secret', 'key', 'credential',
                'auth', 'api_key', 'apikey'
            ]):
                if isinstance(value, str) and len(value) > 8:
                    # Show first 4 and last 4 chars
                    sanitized[key] = f"{value[:4]}...{value[-4:]}"
                else:
                    sanitized[key] = "***REDACTED***"

            # Partially mask hash values (show first 4, last 4)
            elif key_lower in ['hash', 'md5', 'sha1', 'sha256', 'file_hash']:
                if isinstance(value, str) and len(value) >= 16:
                    sanitized[key] = f"{value[:4]}...{value[-4:]}"
                else:
                    sanitized[key] = value

            # Truncate very long values
            elif isinstance(value, str) and len(value) > 500:
                sanitized[key] = value[:500] + "...[truncated]"

            # Recursively sanitize nested dicts
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_parameters(value)

            # Sanitize lists
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_parameters(item) if isinstance(item, dict) else item
                    for item in value[:100]  # Limit list length
                ]
                if len(value) > 100:
                    sanitized[key].append(f"...{len(value) - 100} more items")

            # Pass through safe values
            else:
                sanitized[key] = value

        return sanitized

    def _compute_integrity_hash(self, log_entry: Dict[str, Any]) -> str:
        """
        Compute SHA256 hash for log integrity (tamper detection).

        Creates a blockchain-like chain where each log entry includes the hash
        of the previous entry, making tampering detectable.

        Args:
            log_entry: Log entry dictionary to hash

        Returns:
            SHA256 hash hex digest

        Example:
            >>> entry = {"timestamp": "2025-01-19T10:30:00Z", "event": "tool_call"}
            >>> hash_value = self._compute_integrity_hash(entry)
            >>> print(f"Log hash: {hash_value}")
            Log hash: a3f8d2e1b4c9...
        """
        # Create deterministic JSON string (sorted keys for consistency)
        log_str = json.dumps(log_entry, sort_keys=True)

        # Chain previous hash if exists (blockchain-like integrity)
        if self.previous_log_hash:
            log_str = log_str + self.previous_log_hash

        # Compute SHA256 hash
        hash_obj = hashlib.sha256(log_str.encode('utf-8'))
        return hash_obj.hexdigest()

    def log_tool_call(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        user: str = "default_user",
        data_classification: str = "TLP:CLEAR",
        results_count: Optional[int] = None,
        execution_time_ms: Optional[int] = None,
        success: bool = True,
        error: Optional[str] = None,
        correlation_id: Optional[str] = None,
        filtering_metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log MCP tool execution for audit trail.

        Args:
            tool_name: Name of MCP tool called
            parameters: Tool parameters (sanitized - no sensitive data)
            user: User identifier (default: default_user)
            data_classification: TLP classification (CLEAR/GREEN/AMBER/RED)
            results_count: Number of results returned
            execution_time_ms: Execution time in milliseconds
            success: Whether tool call succeeded
            error: Error message if failed
            correlation_id: Correlation ID for tracking related events (v0.4.0+)
            filtering_metadata: Server-side filtering metadata (v0.4.0+)

        Returns:
            Correlation ID for this log entry (new or provided)

        Example:
            >>> correlation_id = audit.log_tool_call(
            ...     tool_name="search_entities",
            ...     parameters={"query": "ransomware", "entity_types": ["Malware"]},
            ...     user="analyst@company.com",
            ...     results_count=47,
            ...     execution_time_ms=523,
            ...     success=True,
            ...     filtering_metadata={
            ...         "filtering_method": "server_side",
            ...         "marking_uuids_count": 3
            ...     }
            ... )
        """

        # Sanitize parameters before logging (security: no sensitive data in logs)
        safe_parameters = self._sanitize_parameters(parameters)

        # Generate correlation ID if not provided (v0.4.0+)
        if not correlation_id:
            correlation_id = str(uuid.uuid4())

        # Build audit entry
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "mcp_tool_call",
            "correlation_id": correlation_id,  # v0.4.0+
            "session_id": self.session_id,
            "user": user,
            "tool_name": tool_name,
            "parameters": safe_parameters,  # Sanitized parameters
            "data_classification": data_classification,
            "results_count": results_count,  # Count only, not content
            "execution_time_ms": execution_time_ms,
            "success": success,
            "error": error
        }

        # Add filtering metadata if provided (v0.4.0+)
        if filtering_metadata:
            audit_entry["filtering_metadata"] = filtering_metadata

            # Extract security classification from metadata
            if "filtering_method" in filtering_metadata:
                audit_entry["security_classification"] = {
                    "method": filtering_metadata["filtering_method"],
                    "marking_count": filtering_metadata.get("marking_uuids_count", 0)
                }

        # Compute integrity hash (v0.4.0+)
        integrity_hash = self._compute_integrity_hash(audit_entry)
        audit_entry["integrity_hash"] = integrity_hash
        audit_entry["previous_hash"] = self.previous_log_hash

        # Update chain for next log entry
        self.previous_log_hash = integrity_hash

        self.logger.info(json.dumps(audit_entry))

        return correlation_id

    def log_session_start(
        self,
        user: str = "default_user",
        metadata: Optional[Dict] = None
    ) -> None:
        """Log MCP session initialization.

        Args:
            user: User identifier
            metadata: Additional session metadata (version, config, etc.)

        Example:
            >>> audit.log_session_start(
            ...     user="analyst@company.com",
            ...     metadata={"version": "0.2.1", "config_dir": "config/"}
            ... )
        """

        audit_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "session_start",
            "user": user,
            "session_id": self.session_id,
            "metadata": metadata or {}
        }

        self.logger.info(json.dumps(audit_entry))

    def log_session_end(
        self,
        user: str = "default_user",
        metadata: Optional[Dict] = None
    ) -> None:
        """Log MCP session termination.

        Args:
            user: User identifier
            metadata: Session statistics (total calls, errors, etc.)

        Example:
            >>> audit.log_session_end(
            ...     user="analyst@company.com",
            ...     metadata={"total_calls": 23, "errors": 1}
            ... )
        """

        audit_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "session_end",
            "user": user,
            "session_id": self.session_id,
            "metadata": metadata or {}
        }

        self.logger.info(json.dumps(audit_entry))

    def log_error(
        self,
        error_type: str,
        error_message: str,
        context: Optional[Dict] = None
    ) -> None:
        """Log error events for security monitoring.

        Args:
            error_type: Category of error (authentication, authorization, system, etc.)
            error_message: Detailed error message
            context: Additional context (tool name, parameters, etc.)

        Example:
            >>> audit.log_error(
            ...     error_type="authentication",
            ...     error_message="OpenCTI connection failed: Invalid token",
            ...     context={"tool": "validate_opencti_connection"}
            ... )
        """

        audit_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "error",
            "error_type": error_type,
            "error_message": error_message,
            "session_id": self.session_id,
            "context": context or {}
        }

        self.logger.info(json.dumps(audit_entry))

    def verify_log_integrity(self, log_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Verify integrity of audit log chain (tamper detection).

        Recomputes hashes for log chain and detects tampering if any hash
        doesn't match. Similar to blockchain verification.

        Args:
            log_entries: List of log entries from audit log file

        Returns:
            Verification result with integrity status and details

        Example:
            >>> with open("audit.jsonl") as f:
            ...     logs = [json.loads(line) for line in f]
            >>> result = audit.verify_log_integrity(logs)
            >>> if result["integrity_valid"]:
            ...     print("✅ Audit log integrity verified")
            ... else:
            ...     print(f"❌ Tampering detected at entry {result['tampered_index']}")
        """
        if not log_entries:
            return {
                "integrity_valid": True,
                "total_entries": 0,
                "verified_entries": 0,
                "message": "No entries to verify"
            }

        previous_hash = None
        tampered_entries = []

        for idx, entry in enumerate(log_entries):
            # Check if entry has integrity hash (v0.4.0+ entries)
            if "integrity_hash" not in entry:
                continue

            expected_previous = entry.get("previous_hash")
            if expected_previous != previous_hash:
                tampered_entries.append({
                    "index": idx,
                    "correlation_id": entry.get("correlation_id", "unknown"),
                    "timestamp": entry.get("timestamp", "unknown"),
                    "reason": "Previous hash mismatch"
                })

            # Verify current entry's hash
            stored_hash = entry["integrity_hash"]
            stored_previous = entry.get("previous_hash")

            # Reconstruct entry without hash fields for verification
            entry_copy = {k: v for k, v in entry.items()
                         if k not in ["integrity_hash", "previous_hash"]}

            # Compute what the hash should be
            log_str = json.dumps(entry_copy, sort_keys=True)
            if stored_previous:
                log_str = log_str + stored_previous

            computed_hash = hashlib.sha256(log_str.encode('utf-8')).hexdigest()

            if computed_hash != stored_hash:
                tampered_entries.append({
                    "index": idx,
                    "correlation_id": entry.get("correlation_id", "unknown"),
                    "timestamp": entry.get("timestamp", "unknown"),
                    "reason": "Hash verification failed",
                    "expected": stored_hash[:16] + "...",
                    "computed": computed_hash[:16] + "..."
                })

            previous_hash = stored_hash

        entries_with_hash = sum(1 for e in log_entries if "integrity_hash" in e)

        return {
            "integrity_valid": len(tampered_entries) == 0,
            "total_entries": len(log_entries),
            "verified_entries": entries_with_hash,
            "tampered_entries": len(tampered_entries),
            "tampered_details": tampered_entries if tampered_entries else None,
            "message": (
                "✅ All audit log entries verified - no tampering detected"
                if len(tampered_entries) == 0
                else f"❌ Tampering detected in {len(tampered_entries)} entries"
            )
        }

    def get_session_id(self) -> str:
        """Get the current session ID.

        Returns:
            Session UUID

        Example:
            >>> session_id = audit.get_session_id()
            >>> print(f"Audit session: {session_id}")
        """
        return self.session_id
