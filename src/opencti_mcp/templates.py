"""
Cooper Cyber Coffee OpenCTI MCP Server - Professional Analysis Templates
Copyright (c) 2025 Matthew Hopkins / Cooper Cyber Coffee

Licensed under the MIT License - see LICENSE.md for details
Built by: Matthew Hopkins (https://linkedin.com/in/matthew-hopkins)
Project: Cooper Cyber Coffee (https://coopercybercoffee.com)

Contact: matt@coopercybercoffee.com
"""

from typing import Dict, Any


class AnalysisTemplates:
    """Professional analysis templates for structured threat intelligence output.

    These templates provide consistent, executive-ready formatting for threat
    intelligence analysis, inspired by industry-leading platforms like Censys.

    Each template is designed to guide Claude in producing structured,
    actionable intelligence for different audiences and use cases.
    """

    @staticmethod
    def executive_briefing_template() -> str:
        """Executive briefing template for board-ready threat summaries.

        This template produces high-level summaries suitable for:
        - Executive leadership briefings
        - Board presentations
        - Strategic decision-making
        - Business risk assessment

        Returns:
            Formatted template string for executive analysis
        """
        return """
Please analyze the provided threat intelligence data and format as an executive briefing:

## Executive Summary
- **Threat Level**: [Critical/High/Medium/Low] based on indicators
- **Key Finding**: One-sentence summary of most important threat
- **Business Impact**: Potential impact to organization operations
- **Immediate Actions Required**: Top 3 specific actions needed

## Threat Landscape Overview
- **Active Campaigns**: Currently observed threat campaigns
- **Attribution Confidence**: Assessment of threat actor attribution
- **Geographic Focus**: Primary regions/sectors being targeted
- **Timeline**: When these threats were first observed

## Strategic Recommendations
1. **Short-term (24-48 hours)**: Immediate protective measures
2. **Medium-term (1-2 weeks)**: Enhanced monitoring and detection
3. **Long-term (1-3 months)**: Strategic security improvements

## Technical Appendix
- **Indicator Summary**: Count and types of IOCs
- **Confidence Levels**: Overall data quality assessment
- **Data Sources**: Primary intelligence sources used

*This analysis was generated using Cooper Cyber Coffee methodology*
"""

    @staticmethod
    def technical_analysis_template() -> str:
        """Technical analysis template for detailed attribution and TTP analysis.

        This template produces detailed technical assessments for:
        - Security operations teams
        - Threat hunters
        - Incident responders
        - Security researchers

        Returns:
            Formatted template string for technical analysis
        """
        return """
Please provide a detailed technical analysis of the threat intelligence:

## Threat Actor Analysis
- **Primary Attribution**: Most likely threat actor or group
- **Attribution Confidence**: [High/Medium/Low] with reasoning
- **Known TTPs**: Tactics, techniques, and procedures observed
- **Historical Activity**: Previous campaigns and patterns

## Indicator Analysis
- **IOC Breakdown**: Categorize indicators by type and confidence
- **Pattern Recognition**: Common elements across indicators
- **Infrastructure Analysis**: Hosting patterns, registrations, etc.
- **Timeline Correlation**: Temporal relationships between indicators

## Campaign Assessment
- **Campaign Scope**: Scale and targeting of observed activity
- **Victimology**: Industries, regions, or entities targeted
- **Operational Security**: Adversary OPSEC and detection evasion
- **Success Indicators**: Evidence of successful compromises

## Detection and Response
- **Detection Opportunities**: Where these threats can be identified
- **Hunting Queries**: Specific search patterns for threat hunting
- **Mitigation Strategies**: Technical controls to reduce risk
- **Monitoring Recommendations**: Long-term surveillance strategies

*Technical analysis by Cooper Cyber Coffee threat intelligence methodology*
"""

    @staticmethod
    def incident_response_template() -> str:
        """Incident response template for structured response guidance.

        This template produces actionable IR guidance for:
        - Incident response teams
        - Security analysts during active incidents
        - Forensic investigators
        - Crisis management teams

        Returns:
            Formatted template string for incident response
        """
        return """
Please analyze the threat data for incident response planning:

## Immediate Response Actions
- **Containment**: Steps to prevent spread of identified threats
- **Evidence Preservation**: Critical data to collect and preserve
- **Stakeholder Notification**: Who needs to be informed immediately
- **Resource Requirements**: Personnel and tools needed

## Investigation Priorities
1. **Primary IOCs**: Most critical indicators to investigate first
2. **System Targeting**: Likely systems and assets at risk
3. **Lateral Movement**: Potential paths for threat expansion
4. **Data at Risk**: Information likely targeted by threat actors

## Response Procedures
- **Isolation Criteria**: When to isolate affected systems
- **Forensic Collection**: Evidence collection priorities
- **Communication Plan**: Internal and external communication needs
- **Recovery Planning**: Steps to restore normal operations

## Lessons Learned Integration
- **Detection Gaps**: Where current security controls failed
- **Process Improvements**: Recommended changes to response procedures
- **Training Needs**: Skills development for response team
- **Technology Enhancements**: Security tool improvements needed

*Incident response guidance by Cooper Cyber Coffee methodology*
"""

    @staticmethod
    def trend_analysis_template() -> str:
        """Trend analysis template for strategic threat landscape insights.

        This template produces forward-looking analysis for:
        - Security strategy planning
        - Investment prioritization
        - Risk management
        - Long-term threat forecasting

        Returns:
            Formatted template string for trend analysis
        """
        return """
Please analyze the threat intelligence data for strategic trends:

## Threat Landscape Trends
- **Emerging Patterns**: New or evolving threat behaviors
- **Threat Actor Evolution**: Changes in adversary capabilities
- **Campaign Trends**: Shifts in targeting or methodology
- **Infrastructure Patterns**: Changes in adversary infrastructure use

## Strategic Implications
- **Industry Impact**: How trends affect specific sectors
- **Geographic Shifts**: Changes in regional threat activity
- **Technology Adaptation**: How threats adapt to new technologies
- **Defensive Effectiveness**: Success/failure of current defenses

## Predictive Insights
- **Future Threat Vectors**: Likely evolution of current threats
- **Preparation Strategies**: Proactive measures for emerging threats
- **Investment Priorities**: Security spending recommendations
- **Capability Development**: Skills and tools needed for future threats

## Strategic Recommendations
- **Policy Updates**: Recommended changes to security policies
- **Architecture Modifications**: Infrastructure security improvements
- **Partnership Opportunities**: External collaboration benefits
- **Research Priorities**: Areas needing additional investigation

*Strategic trend analysis by Cooper Cyber Coffee threat intelligence methodology*
"""

    @staticmethod
    def get_template(analysis_type: str) -> str:
        """Get the appropriate analysis template based on analysis type.

        Args:
            analysis_type: Type of analysis ('executive', 'technical',
                          'incident_response', or 'trend_analysis')

        Returns:
            Formatted template string

        Raises:
            ValueError: If analysis_type is not recognized

        Example:
            >>> template = AnalysisTemplates.get_template('executive')
            >>> print(template[:50])
            'Please analyze the provided threat intelligence...'
        """
        templates = {
            "executive": AnalysisTemplates.executive_briefing_template,
            "technical": AnalysisTemplates.technical_analysis_template,
            "incident_response": AnalysisTemplates.incident_response_template,
            "trend_analysis": AnalysisTemplates.trend_analysis_template,
        }

        if analysis_type not in templates:
            raise ValueError(
                f"Unknown analysis type: {analysis_type}. "
                f"Valid types: {list(templates.keys())}"
            )

        return templates[analysis_type]()

    @staticmethod
    def format_indicator_data(indicators: list, analysis_type: str = "executive") -> str:
        """Format indicator data with appropriate template for Claude analysis.

        Args:
            indicators: List of indicator dictionaries from OpenCTI
            analysis_type: Type of analysis template to use

        Returns:
            Formatted string ready for Claude analysis

        Example:
            >>> indicators = await client.get_recent_indicators(limit=5)
            >>> formatted = AnalysisTemplates.format_indicator_data(
            ...     indicators, 'executive'
            ... )
            >>> # Send formatted to Claude for analysis
        """
        template = AnalysisTemplates.get_template(analysis_type)

        # Build indicator summary
        indicator_summary = f"\n\n## Indicator Data ({len(indicators)} total)\n\n"

        for idx, indicator in enumerate(indicators, 1):
            indicator_summary += f"### Indicator {idx}\n"
            indicator_summary += f"- **Pattern**: {indicator.get('pattern', 'N/A')}\n"
            indicator_summary += f"- **Type**: {', '.join(indicator.get('indicator_types', ['unknown']))}\n"
            indicator_summary += f"- **Confidence**: {indicator.get('confidence', 0)}%\n"
            indicator_summary += f"- **Created**: {indicator.get('created_at', 'N/A')}\n"

            labels = indicator.get('labels', [])
            if labels:
                indicator_summary += f"- **Labels**: {', '.join(labels)}\n"

            indicator_summary += "\n"

        return template + indicator_summary
