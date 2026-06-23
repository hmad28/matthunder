"""
Output Formatter for Ouroboros

Formats AI outputs according to Ouroboros persona rules.
"""
import json
from typing import Dict, Any, Optional
from datetime import datetime


class OutputFormatter:
    """Formats AI outputs according to Ouroboros persona rules"""

    def __init__(self):
        """Initialize output formatter"""
        self._supported_formats = ["json", "markdown", "text", "structured"]

    def format_output(
        self,
        output: str,
        format_type: str = "json",
        hypothesis: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Format output according to type

        Args:
            output: Raw output to format
            format_type: Output format (json, markdown, text, structured)
            hypothesis: Optional hypothesis data for cycle tick

        Returns:
            Formatted output
        """
        if format_type == "json":
            return self._format_json(output, hypothesis)
        elif format_type == "markdown":
            return self._format_markdown(output)
        elif format_type == "structured":
            return self._format_structured(output, hypothesis)
        else:  # text
            return self._format_text(output)

    def _format_json(self, output: str, hypothesis: Optional[Dict[str, Any]] = None) -> str:
        """Format output as JSON with cycle tick"""
        if hypothesis:
            cycle_tick = self._generate_cycle_tick(hypothesis)
            return json.dumps({
                "cycle_tick": cycle_tick,
                "output": output,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "format": "json"
            }, indent=2)
        else:
            return output

    def _format_markdown(self, output: str) -> str:
        """Format output as markdown"""
        lines = output.split('\n')
        formatted_lines = []

        for line in lines:
            if line.strip().startswith('{'):
                formatted_line = f"```json\n{line}\n```"
            elif line.strip().startswith('['):
                formatted_line = f"```json\n{line}\n```"
            elif ':' in line:
                formatted_line = line
            else:
                formatted_line = f"- {line}"

            formatted_lines.append(formatted_line)

        return '\n'.join(formatted_lines)

    def _format_structured(self, output: str, hypothesis: Optional[Dict[str, Any]] = None) -> str:
        """Format output as structured format"""
        if hypothesis:
            return self._generate_cycle_tick(hypothesis)
        return output

    def _format_text(self, output: str) -> str:
        """Format output as plain text"""
        # Clean up extra whitespace
        lines = [line.strip() for line in output.split('\n')]
        return '\n'.join(line for line in lines if line)

    def _generate_cycle_tick(self, hypothesis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate JSON cycle tick

        Args:
            hypothesis: Active hypothesis data

        Returns:
            Cycle tick object
        """
        return {
            "active_hypothesis": hypothesis.get("active_hypothesis", ""),
            "target": hypothesis.get("target", ""),
            "recommended_tool": hypothesis.get("recommended_tool", ""),
            "command_arguments": hypothesis.get("command_arguments", ""),
            "confidence": hypothesis.get("confidence", 0.5),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def format_finding_report(
        self,
        finding: Dict[str, Any]
    ) -> str:
        """
        Format a single finding report

        Args:
            finding: Finding data

        Returns:
            Formatted finding report
        """
        lines = [
            f"## {finding.get('title', 'Untitled Finding')}",
            f"**Severity:** {finding.get('severity', 'Unknown').upper()}",
            f"**Type:** {finding.get('category', finding.get('scanner', 'Unknown'))}",
            f"**URL:** {finding.get('url', 'N/A')}",
            f"**Description:** {finding.get('description', 'No description')}",
            "",
            "### Evidence",
            f"```",
            finding.get('evidence', 'No evidence collected'),
            "```",
            "",
            "### Remediation",
            finding.get('remediation', 'No remediation provided'),
            ""
        ]
        return '\n'.join(lines)

    def format_scan_summary(
        self,
        scan_id: str,
        target_id: str,
        findings_count: int,
        scan_duration: float,
        status: str
    ) -> str:
        """
        Format scan summary

        Args:
            scan_id: Scan ID
            target_id: Target domain or ID
            findings_count: Number of findings
            scan_duration: Scan duration in seconds
            status: Scan status

        Returns:
            Formatted summary
        """
        return json.dumps({
            "scan_summary": {
                "scan_id": scan_id,
                "target_id": target_id,
                "findings_count": findings_count,
                "scan_duration_seconds": scan_duration,
                "status": status,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        }, indent=2)

    def format_error(
        self,
        error_type: str,
        error_message: str,
        severity: str = "error"
    ) -> str:
        """
        Format error output

        Args:
            error_type: Type of error
            error_message: Error message
            severity: Error severity

        Returns:
            Formatted error
        """
        return json.dumps({
            "error": {
                "type": error_type,
                "message": error_message,
                "severity": severity,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "source": "ouroboros"
            }
        }, indent=2)

    def validate_output_format(self, output: str) -> bool:
        """
        Validate that output conforms to Ouroboros format

        Args:
            output: Output to validate

        Returns:
            True if format is valid
        """
        try:
            parsed = json.loads(output)
            return isinstance(parsed, dict)
        except (json.JSONDecodeError, ValueError):
            return output.startswith("#") or output.startswith("```")

    def get_cycle_tick_schema(self) -> Dict[str, Any]:
        """
        Get JSON cycle tick schema

        Returns:
            Cycle tick schema
        """
        return {
            "type": "object",
            "properties": {
                "active_hypothesis": {
                    "type": "string",
                    "description": "Current active hypothesis"
                },
                "target": {
                    "type": "string",
                    "description": "Target URL or domain"
                },
                "recommended_tool": {
                    "type": "string",
                    "description": "Recommended tool for execution"
                },
                "command_arguments": {
                    "type": "string",
                    "description": "Command-line arguments"
                },
                "confidence": {
                    "type": "number",
                    "description": "Confidence score (0-1)",
                    "minimum": 0,
                    "maximum": 1
                },
                "timestamp": {
                    "type": "string",
                    "description": "ISO timestamp"
                }
            },
            "required": ["active_hypothesis", "target", "recommended_tool", "command_arguments"]
        }