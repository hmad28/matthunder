"""
Response Parser for AI Offensive AI

Parses and validates AI responses for pentesting.
"""
from typing import Dict, Any, List, Optional
import json


class ResponseParser:
    """Parses and validates AI responses"""

    def __init__(self):
        """Initialize response parser"""
        self._supported_formats = [
            "json",
            "markdown",
            "text",
            "structured"
        ]

    def parse_response(
        self,
        response: str,
        expected_format: str = "json"
    ) -> Dict[str, Any]:
        """
        Parse AI response

        Args:
            response: AI response string
            expected_format: Expected format type

        Returns:
            Parsed response data
        """
        if expected_format == "json":
            return self._parse_json_response(response)
        elif expected_format == "markdown":
            return self._parse_markdown_response(response)
        elif expected_format == "text":
            return self._parse_text_response(response)
        else:
            return self._parse_structured_response(response)

    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON response"""
        try:
            # Try to parse as JSON
            data = json.loads(response)
            return {"success": True, "data": data, "format": "json"}
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            lines = response.split('\n')
            for line in lines:
                if line.strip().startswith('{') or line.strip().startswith('['):
                    try:
                        data = json.loads(line)
                        return {"success": True, "data": data, "format": "json"}
                    except json.JSONDecodeError:
                        continue

            return {"success": False, "data": {}, "format": "json", "error": "Invalid JSON"}

    def _parse_markdown_response(self, response: str) -> Dict[str, Any]:
        """Parse markdown response"""
        # Extract sections from markdown
        sections = {}
        current_section = None
        current_content = []

        for line in response.split('\n'):
            if line.strip().startswith('#'):
                # Save previous section
                if current_section:
                    sections[current_section] = '\n'.join(current_content).strip()

                # Start new section
                current_section = line.strip('#').strip()
                current_content = []
            else:
                if current_section:
                    current_content.append(line)

        # Save last section
        if current_section:
            sections[current_section] = '\n'.join(current_content).strip()

        return {
            "success": True,
            "data": sections,
            "format": "markdown"
        }

    def _parse_text_response(self, response: str) -> Dict[str, Any]:
        """Parse plain text response"""
        lines = response.strip().split('\n')

        return {
            "success": True,
            "data": {
                "content": response,
                "lines": lines,
                "word_count": len(response.split())
            },
            "format": "text"
        }

    def _parse_structured_response(self, response: str) -> Dict[str, Any]:
        """Parse structured response"""
        # Try to parse as structured format
        lines = response.strip().split('\n')
        structured = {}

        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                structured[key] = value

        return {
            "success": True,
            "data": structured,
            "format": "structured"
        }

    def validate_response(
        self,
        response: str,
        validation_rules: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate response against rules

        Args:
            response: Response to validate
            validation_rules: Validation rules

        Returns:
            Validation result
        """
        parsed = self.parse_response(response)

        if not parsed["success"]:
            return {
                "valid": False,
                "errors": [parsed["error"]]
            }

        data = parsed["data"]

        errors = []
        warnings = []

        # Validate required fields
        if "required_fields" in validation_rules:
            for field in validation_rules["required_fields"]:
                if field not in data:
                    errors.append(f"Missing required field: {field}")

        # Validate field types
        if "field_types" in validation_rules:
            for field, expected_type in validation_rules["field_types"].items():
                if field in data:
                    if not isinstance(data[field], expected_type):
                        errors.append(f"Field {field} has wrong type: {type(data[field])}")

        # Validate ranges
        if "ranges" in validation_rules:
            for field, (min_val, max_val) in validation_rules["ranges"].items():
                if field in data:
                    try:
                        value = float(data[field])
                        if value < min_val or value > max_val:
                            errors.append(f"Field {field} out of range: {value}")
                    except (ValueError, TypeError):
                        errors.append(f"Field {field} must be numeric")

        # Validate regex patterns
        if "patterns" in validation_rules:
            import re
            for field, pattern in validation_rules["patterns"].items():
                if field in data:
                    if not re.match(pattern, str(data[field])):
                        errors.append(f"Field {field} doesn't match pattern: {pattern}")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "data": data
        }

    def extract_findings(self, response: str) -> List[Dict[str, Any]]:
        """
        Extract findings from response

        Args:
            response: Response containing findings

        Returns:
            List of findings
        """
        findings = []

        # Try to parse as JSON
        parsed = self.parse_response(response)

        if not parsed["success"]:
            return []

        data = parsed["data"]

        # Handle different response formats
        if isinstance(data, list):
            findings = data
        elif isinstance(data, dict):
            if "findings" in data:
                findings = data["findings"]
            elif "results" in data:
                findings = data["results"]
            else:
                # Try to find nested finding objects
                for key, value in data.items():
                    if isinstance(value, dict) and any(
                        field in value for field in ["type", "severity", "description"]
                    ):
                        findings.append(value)

        return findings

    def extract_attack_path(self, response: str) -> Optional[str]:
        """
        Extract attack path from response

        Args:
            response: Response containing attack path

        Returns:
            Attack path string or None
        """
        parsed = self.parse_response(response)

        if not parsed["success"]:
            return None

        data = parsed["data"]

        if isinstance(data, dict):
            # Look for attack path in different formats
            for key in ["attack_path", "attack_chain", "attack_chain_path"]:
                if key in data:
                    return str(data[key])

            # Look for structured attack path
            if "steps" in data:
                steps = data["steps"]
                if isinstance(steps, list):
                    return " -> ".join(steps)

        return None

    def extract_step_to_reproduce(self, response: str) -> Optional[str]:
        """
        Extract step-by-step reproduction instructions

        Args:
            response: Response containing reproduction steps

        Returns:
            Reproduction steps string or None
        """
        parsed = self.parse_response(response)

        if not parsed["success"]:
            return None

        data = parsed["data"]

        if isinstance(data, dict):
            # Look for reproduction steps
            for key in ["reproduce", "reproduce_steps", "reproduction_steps", "steps_to_reproduce"]:
                if key in data:
                    return str(data[key])

            # Look for numbered list
            lines = []
            for line in str(data).split('\n'):
                if line.strip().startswith(('-', '*', '1.', '2.', '3.', '4.', '5.')):
                    lines.append(line.strip())

            if lines:
                return '\n'.join(lines)

        return None

    def validate_step_to_reproduce(self, steps: str) -> Dict[str, Any]:
        """
        Validate reproduction steps

        Args:
            steps: Reproduction steps to validate

        Returns:
            Validation result
        """
        lines = [line.strip() for line in steps.split('\n') if line.strip()]

        errors = []
        warnings = []

        # Check for minimum steps
        if len(lines) < 3:
            errors.append("At least 3 steps required for reproduction")

        # Check for clear commands
        command_lines = [line for line in lines if any(word in line for word in ["curl", "python", "bash", "sqlmap", "nuclei"])]
        if len(command_lines) == 0:
            warnings.append("No executable commands found in steps")

        # Check for evidence collection
        evidence_lines = [line for line in lines if any(word in line for word in ["evidence", "proof", "screenshot", "log"])]
        if len(evidence_lines) == 0:
            warnings.append("No evidence collection mentioned")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "steps_count": len(lines)
        }

    def get_response_type(self, response: str) -> str:
        """
        Determine response type

        Args:
            response: Response string

        Returns:
            Response type
        """
        if response.strip().startswith('{') or response.strip().startswith('['):
            return "json"
        elif response.strip().startswith('#'):
            return "markdown"
        else:
            return "text"