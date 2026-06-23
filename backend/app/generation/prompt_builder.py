"""
Prompt Builder for AI Offensive AI

Builds dynamic prompts for AI-driven pentesting reasoning.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime


class PromptBuilder:
    """Builds dynamic prompts for AI interactions"""

    def __init__(self):
        """Initialize prompt builder"""
        self._prompt_templates = self._load_prompt_templates()

    def _load_prompt_templates(self) -> Dict[str, str]:
        """Load prompt templates"""
        return {
            "ouroboros": """You are Ouroboros-Pentester, a specialized AI agent for offensive security testing.
Your role is to identify and exploit vulnerabilities in authorized targets.
You operate with strict discipline and focus on actionable intelligence.

OPERATIONAL RULES:
- ALWAYS verify target is within authorized scope
- NEVER report theoretical vulnerabilities without proof
- Follow the 5-minute timeout rule for authentication failures
- Provide results in structured JSON format
- Focus on actionable intelligence""",

            "reasoning": """You are a pentesting AI assistant. Think through the following:

TARGET: {target_id}
FINDING: {finding_type}
CONTEXT: {context}

Provide your reasoning in a structured format with:
1. Analysis of the situation
2. Recommended actions
3. Expected outcomes
4. Risk assessment""",

            "payload": """Generate an exploit payload for:
TARGET: {target_url}
VULNERABILITY: {vulnerability_type}
LANGUAGE: {language}

Context: {context}

Generate a safe, testable payload that:
- Exploits the vulnerability
- Evades detection where possible
- Has clear documentation
- Is ready for authorized testing""",

            "validation": """Validate the following pentest findings:

FINDINGS: {findings}
CONTEXT: {context}

Check:
1. Is the target in scope?
2. Is authorization obtained?
3. Are objectives defined?
4. Is the methodology safe?
5. What is the impact?
6. Is mitigation provided?
7. Is the timeline defined?

Provide a score (0-1) and recommendations.""",

            "summary": """Generate a summary of pentest activities:

SCAN_ID: {scan_id}
TARGET: {target_id}
FINDINGS: {findings_count}
STATUS: {status}

Provide:
- Key accomplishments
- Remaining tasks
- Risk assessment
- Recommendations"""
        }

    def build_ouroboros_prompt(
        self,
        target_id: str,
        current_task: Optional[str] = None
    ) -> str:
        """
        Build Ouroboros persona prompt

        Args:
            target_id: Target domain or ID
            current_task: Current task description

        Returns:
            Ouroboros prompt
        """
        prompt = self._prompt_templates["ouroboros"]

        if current_task:
            prompt += f"\n\nCURRENT TASK: {current_task}"

        return prompt

    def build_reasoning_prompt(
        self,
        target_id: str,
        finding_type: str,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Build reasoning prompt

        Args:
            target_id: Target domain or ID
            finding_type: Type of finding
            context: Context for reasoning

        Returns:
            Reasoning prompt
        """
        template = self._prompt_templates["reasoning"]
        context_str = self._format_context(context)

        return template.format(
            target_id=target_id,
            finding_type=finding_type,
            context=context_str
        )

    def build_payload_prompt(
        self,
        target_url: str,
        vulnerability_type: str,
        language: str,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Build payload generation prompt

        Args:
            target_url: Target URL
            vulnerability_type: Type of vulnerability
            language: Payload language
            context: Context for payload generation

        Returns:
            Payload prompt
        """
        template = self._prompt_templates["payload"]
        context_str = self._format_context(context)

        return template.format(
            target_url=target_url,
            vulnerability_type=vulnerability_type,
            language=language,
            context=context_str
        )

    def build_validation_prompt(
        self,
        findings: List[str],
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Build validation prompt

        Args:
            findings: List of findings to validate
            context: Context for validation

        Returns:
            Validation prompt
        """
        template = self._prompt_templates["validation"]
        findings_str = "\n".join(f"- {finding}" for finding in findings)
        context_str = self._format_context(context)

        return template.format(
            findings=findings_str,
            context=context_str
        )

    def build_summary_prompt(
        self,
        scan_id: str,
        target_id: str,
        findings_count: int,
        status: str
    ) -> str:
        """
        Build summary prompt

        Args:
            scan_id: Scan session ID
            target_id: Target domain or ID
            findings_count: Number of findings
            status: Current status

        Returns:
            Summary prompt
        """
        template = self._prompt_templates["summary"]

        return template.format(
            scan_id=scan_id,
            target_id=target_id,
            findings_count=findings_count,
            status=status
        )

    def _format_context(self, context: Optional[Dict[str, Any]]) -> str:
        """Format context for prompt"""
        if not context:
            return "No context available"

        lines = []
        if "target_metadata" in context:
            lines.append(f"Target: {context['target_metadata'].get('host', 'Unknown')}")
        if "reconnaissance_map" in context:
            lines.append(f"Reconnaissance: {context['reconnaissance_map'].get('live_hosts', [])}")
        if "vulnerability_journal" in context:
            lines.append(f"Active Leads: {len(context['vulnerability_journal'].get('active_leads', []))}")

        return "\n".join(lines)

    def get_available_prompts(self) -> List[str]:
        """Get list of available prompt types"""
        return list(self._prompt_templates.keys())