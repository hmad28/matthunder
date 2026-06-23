"""
Constraint Validator for Ouroboros

Validates AI outputs against persona constraints and security rules.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime


class ConstraintValidator:
    """Validates AI outputs against Ouroboros constraints"""

    def __init__(self):
        """Initialize constraint validator"""
        self._forbidden_patterns = self._load_forbidden_patterns()
        self._required_patterns = self._load_required_patterns()

    def _load_forbidden_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that must not appear in AI outputs"""
        return {
            "greetings": [
                "hello", "hi there", "hey", "greetings", "welcome",
                "how are you", "howdy", "dear user"
            ],
            "apologies": [
                "sorry", "apologize", "my apologies", "i'm sorry",
                "i apologize", "please forgive"
            ],
            "vague_references": [
                "might be", "could be", "potentially", "possibly",
                "it seems like", "it appears that", "i think"
            ],
            "theoretical": [
                "theoretically", "in theory", "hypothetically",
                "it should work", "i believe"
            ],
            "social_engineering": [
                "password reset", "social engineering",
                "phishing", "pretend to be"
            ]
        }

    def _load_required_patterns(self) -> Dict[str, List[str]]:
        """Load patterns that must appear in AI outputs"""
        return {
            "json_format": [
                "{", "active_hypothesis", "recommended_tool"
            ],
            "evidence": [
                "evidence", "proof", "request", "response"
            ],
            "scope": [
                "scope", "authorized", "target"
            ],
            "tool_usage": [
                "tool", "command", "execute", "scan"
            ]
        }

    def validate_output(self, output: str) -> Dict[str, Any]:
        """
        Validate AI output against all constraints

        Args:
            output: AI output to validate

        Returns:
            Validation result
        """
        violations = []
        warnings = []

        # Check forbidden patterns
        violations.extend(self._check_forbidden_patterns(output))

        # Check required patterns
        violations.extend(self._check_required_patterns(output))

        # Check format
        format_result = self._check_format(output)
        if not format_result["valid"]:
            violations.extend(format_result["violations"])

        # Check security
        security_result = self._check_security(output)
        if not security_result["valid"]:
            violations.extend(security_result["violations"])

        return {
            "valid": len(violations) == 0,
            "violations": violations,
            "warnings": warnings,
            "violations_count": len(violations),
            "validated_at": datetime.utcnow().isoformat() + "Z"
        }

    def _check_forbidden_patterns(self, output: str) -> List[Dict[str, Any]]:
        """Check for forbidden patterns"""
        violations = []
        output_lower = output.lower()

        for category, patterns in self._forbidden_patterns.items():
            for pattern in patterns:
                if pattern.lower() in output_lower:
                    violations.append({
                        "type": f"forbidden_{category}",
                        "message": f"Output contains forbidden pattern '{pattern}' in category '{category}'",
                        "severity": "high"
                    })
        return violations

    def _check_required_patterns(self, output: str) -> List[Dict[str, Any]]:
        """Check for required patterns"""
        violations = []
        output_lower = output.lower()

        for category, patterns in self._required_patterns.items():
            found = any(pattern.lower() in output_lower for pattern in patterns)
            if not found:
                violations.append({
                    "type": f"missing_{category}",
                    "message": f"Output is missing required pattern in category '{category}'",
                    "severity": "medium"
                })
        return violations

    def _check_format(self, output: str) -> Dict[str, Any]:
        """Check output format"""
        violations = []

        if not output.strip():
            violations.append({
                "type": "empty_output",
                "message": "Output is empty",
                "severity": "high"
            })

        # Check line length
        for i, line in enumerate(output.split('\n'), 1):
            if len(line) > 1000:
                violations.append({
                    "type": "long_line",
                    "message": f"Line {i} exceeds 1000 characters ({len(line)} chars)",
                    "severity": "low"
                })

        # Check for unbalanced brackets
        if output.count('{') != output.count('}'):
            violations.append({
                "type": "unbalanced_brackets",
                "message": "Output has unbalanced curly brackets",
                "severity": "medium"
            })

        return {
            "valid": len(violations) == 0,
            "violations": violations
        }

    def _check_security(self, output: str) -> Dict[str, Any]:
        """Check security constraints"""
        violations = []

        # Check for API keys
        api_key_patterns = [
            "api_key", "api-key", "apikey",
            "sk-", "pk-", "ghp_", "gho_", "ghu_",
            "AKIA", "AKIAIOSFODNN7EXAMPLE"
        ]
        for pattern in api_key_patterns:
            if pattern.lower() in output.lower():
                violations.append({
                    "type": "api_key_exposure",
                    "message": f"Potential API key exposure detected: '{pattern}'",
                    "severity": "critical"
                })

        # Check for sensitive data
        sensitive_patterns = [
            "password", "credential", "secret",
            "authorization: bearer", "authorization: basic"
        ]
        for pattern in sensitive_patterns:
            if pattern.lower() in output.lower():
                violations.append({
                    "type": "sensitive_data_exposure",
                    "message": f"Potential sensitive data exposure detected: '{pattern}'",
                    "severity": "high"
                })

        return {
            "valid": len(violations) == 0,
            "violations": violations
        }

    def validate_scope_compliance(
        self,
        target_id: str,
        output: str
    ) -> Dict[str, Any]:
        """
        Validate scope compliance of AI output

        Args:
            target_id: Authorized target
            output: AI output

        Returns:
            Scope compliance result
        """
        violations = []

        # Check if target is mentioned correctly
        if target_id not in output:
            violations.append({
                "type": "target_not_found",
                "message": f"Authorized target '{target_id}' not mentioned in output",
                "severity": "low"
            })

        # Check for out-of-scope targets
        # (Would check against scope rules in production)
        out_of_scope_indicators = [
            "elsewhere", "other target", "additional target",
            "also check", "more targets"
        ]
        for indicator in out_of_scope_indicators:
            if indicator in output.lower():
                violations.append({
                    "type": "potential_scope_issue",
                    "message": f"Possible out-of-scope reference detected: '{indicator}'",
                    "severity": "low"
                })

        return {
            "valid": len(violations) == 0,
            "violations": violations,
            "target_id": target_id
        }

    def validate_evidence_quality(
        self,
        evidence: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate evidence quality

        Args:
            evidence: Evidence to validate

        Returns:
            Evidence quality result
        """
        issues = []

        # Check required evidence fields
        required_fields = ["url", "type", "severity"]
        for field in required_fields:
            if field not in evidence:
                issues.append(f"Missing required field: {field}")

        # Check content quality
        if "evidence" in evidence:
            ev = evidence["evidence"]
            if len(str(ev)) < 10:
                issues.append("Evidence content is too short")
            elif len(str(ev)) > 10000:
                issues.append("Evidence content is too long")

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "quality_score": max(0, 1 - len(issues) * 0.2)
        }

    def get_validation_statistics(self) -> Dict[str, Any]:
        """
        Get validation statistics

        Returns:
            Validation statistics
        """
        return {
            "forbidden_patterns": {
                category: len(patterns)
                for category, patterns in self._forbidden_patterns.items()
            },
            "required_patterns": {
                category: len(patterns)
                for category, patterns in self._required_patterns.items()
            },
            "total_forbidden": sum(len(p) for p in self._forbidden_patterns.values()),
            "total_required": sum(len(p) for p in self._required_patterns.values())
        }