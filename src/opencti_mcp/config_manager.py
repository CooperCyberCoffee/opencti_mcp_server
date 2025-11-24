"""
Cooper Cyber Coffee OpenCTI MCP Server - Configuration Manager
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

Contact: matt@coopercybercoffee.com
"""

from pathlib import Path
from typing import Dict, List, Optional
import logging


class ConfigManager:
    """Load and manage configuration from Markdown files.

    This class provides a simple interface for loading threat intelligence
    configuration from human-editable Markdown files instead of hard-coded
    Python templates.

    Configuration includes:
    - PIRs (Priority Intelligence Requirements)
    - Security stack/posture
    - Analysis templates

    Example:
        >>> config = ConfigManager()
        >>> full_context = config.get_full_context('executive_briefing')
        >>> # Pass full_context to Claude for analysis
    """

    def __init__(self, config_dir: str = "config"):
        """Initialize configuration manager.

        Args:
            config_dir: Path to configuration directory containing templates/,
                       pirs.md, and security_stack.md
        """
        self.config_dir = Path(config_dir)
        self.templates_dir = self.config_dir / "templates"
        self.logger = logging.getLogger(__name__)

        # Load all context files
        self.pirs = self._load_file("pirs.md")
        self.security_stack = self._load_file("security_stack.md")
        self.templates = self._load_templates()

        self.logger.info(
            f"ConfigManager initialized: {len(self.templates)} templates loaded"
        )

    def _load_file(self, filename: str) -> str:
        """Load a single configuration file.

        Args:
            filename: Name of file to load (relative to config_dir)

        Returns:
            File contents as string, or empty string if file not found
        """
        filepath = self.config_dir / filename

        if not filepath.exists():
            self.logger.warning(
                f"Config file not found: {filename} "
                f"(expected at {filepath.absolute()})"
            )
            return ""

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            self.logger.info(f"Loaded config file: {filename} ({len(content)} chars)")
            return content
        except Exception as e:
            self.logger.error(f"Error loading {filename}: {e}")
            return ""

    def _load_templates(self) -> Dict[str, str]:
        """Load all template files from templates directory.

        Returns:
            Dictionary mapping template names (without .md extension) to content
        """
        templates = {}

        if not self.templates_dir.exists():
            self.logger.error(
                f"Templates directory not found: {self.templates_dir.absolute()}"
            )
            return templates

        for template_file in self.templates_dir.glob("*.md"):
            template_name = template_file.stem
            try:
                with open(template_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                templates[template_name] = content
                self.logger.info(
                    f"Loaded template: {template_name} ({len(content)} chars)"
                )
            except Exception as e:
                self.logger.error(f"Error loading template {template_name}: {e}")

        return templates

    def get_template(self, name: str) -> str:
        """Get a template by name.

        Args:
            name: Template name (without .md extension)

        Returns:
            Template content

        Raises:
            ValueError: If template not found

        Example:
            >>> config = ConfigManager()
            >>> template = config.get_template('executive_briefing')
        """
        if name not in self.templates:
            available = ", ".join(sorted(self.templates.keys()))
            raise ValueError(
                f"Template '{name}' not found. "
                f"Available templates: {available}"
            )
        return self.templates[name]

    def get_full_context(
        self,
        template_name: str,
        include_pirs: bool = True,
        include_security_stack: bool = True
    ) -> str:
        """Get complete context for Claude analysis.

        Combines PIRs + Security Stack + Template into single context string
        that provides Claude with organization-specific context for analysis.

        Args:
            template_name: Name of template to include
            include_pirs: Whether to include PIRs context
            include_security_stack: Whether to include security stack context

        Returns:
            Combined context string ready to pass to Claude

        Example:
            >>> config = ConfigManager()
            >>> context = config.get_full_context('technical_analysis')
            >>> # Build prompt with threat data
            >>> prompt = f'''
            ... {context}
            ...
            ... THREAT INTELLIGENCE DATA:
            ... {threat_data}
            ...
            ... Analyze considering organization context above.
            ... '''
        """
        template = self.get_template(template_name)

        context_parts = []

        # Add PIRs if requested and available
        if include_pirs and self.pirs:
            context_parts.append("# ORGANIZATION CONTEXT (PIRs)")
            context_parts.append("")
            context_parts.append(self.pirs)
            context_parts.append("")
            context_parts.append("---")
            context_parts.append("")

        # Add security stack if requested and available
        if include_security_stack and self.security_stack:
            context_parts.append("# SECURITY POSTURE")
            context_parts.append("")
            context_parts.append(self.security_stack)
            context_parts.append("")
            context_parts.append("---")
            context_parts.append("")

        # Always add template
        if template:
            context_parts.append("# ANALYSIS TEMPLATE")
            context_parts.append("")
            context_parts.append(template)
            context_parts.append("")

        return "\n".join(context_parts)

    def list_templates(self) -> List[str]:
        """List available template names.

        Returns:
            List of template names (sorted alphabetically)

        Example:
            >>> config = ConfigManager()
            >>> templates = config.list_templates()
            >>> print(templates)
            ['executive_briefing', 'incident_response', 'technical_analysis', 'trend_analysis']
        """
        return sorted(self.templates.keys())

    def reload(self):
        """Reload all configuration from disk.

        Useful during development or when configuration files are updated
        without restarting the server.

        Example:
            >>> config = ConfigManager()
            >>> # Edit config files...
            >>> config.reload()  # Pick up changes
        """
        self.pirs = self._load_file("pirs.md")
        self.security_stack = self._load_file("security_stack.md")
        self.templates = self._load_templates()
        self.logger.info(
            f"Configuration reloaded: {len(self.templates)} templates available"
        )

    def get_template_info(self) -> Dict[str, Dict[str, any]]:
        """Get information about all loaded templates.

        Returns:
            Dictionary with template metadata (name, size, preview)

        Example:
            >>> config = ConfigManager()
            >>> info = config.get_template_info()
            >>> for name, details in info.items():
            ...     print(f"{name}: {details['size']} chars")
        """
        info = {}
        for name, content in self.templates.items():
            lines = content.split('\n')
            info[name] = {
                'name': name,
                'size': len(content),
                'lines': len(lines),
                'preview': lines[0] if lines else ""
            }
        return info

    def has_pirs(self) -> bool:
        """Check if PIRs configuration is loaded.

        Returns:
            True if PIRs file was successfully loaded
        """
        return bool(self.pirs)

    def has_security_stack(self) -> bool:
        """Check if security stack configuration is loaded.

        Returns:
            True if security stack file was successfully loaded
        """
        return bool(self.security_stack)

    def get_config_status(self) -> Dict[str, any]:
        """Get status of all configuration components.

        Returns:
            Dictionary with configuration status and statistics

        Example:
            >>> config = ConfigManager()
            >>> status = config.get_config_status()
            >>> if not status['has_pirs']:
            ...     print("Warning: No PIRs configured")
        """
        return {
            'config_dir': str(self.config_dir.absolute()),
            'templates_dir': str(self.templates_dir.absolute()),
            'has_pirs': self.has_pirs(),
            'has_security_stack': self.has_security_stack(),
            'pirs_size': len(self.pirs) if self.pirs else 0,
            'security_stack_size': len(self.security_stack) if self.security_stack else 0,
            'templates_count': len(self.templates),
            'templates_available': self.list_templates(),
            'total_config_size': len(self.pirs) + len(self.security_stack) + sum(
                len(t) for t in self.templates.values()
            )
        }
