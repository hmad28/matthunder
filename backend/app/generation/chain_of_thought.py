"""
Chain-of-Thought Generator for AI Offensive AI

Generates CoT prompts for intelligent pentesting reasoning.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class CoTRequest(BaseModel):
    """Request for Chain-of-Thought generation"""
    target_id: str = Field(..., description="Target domain or ID")
    scan_id: str = Field(..., description="Scan session ID")
    finding_type: str = Field(..., description="Type of finding")
    reconnaissance_data: Dict[str, Any] = Field(default_factory=dict, description="Reconnaissance data")
    context: Optional[Dict[str, Any]] = Field(None, description="Context from memory")
    previous_thoughts: List[str] = Field(default_factory=list, description="Previous CoT thoughts")


class CoTResponse(BaseModel):
    """Response for Chain-of-Thought generation"""
    thought_chain: List[str] = Field(..., description="Chain of thoughts")
    next_action: str = Field(..., description="Next recommended action")
    reasoning_summary: str = Field(..., description="Summary of reasoning")
    confidence: float = Field(..., description="Confidence score (0-1)")
    timestamp: str = Field(..., description="Generation timestamp")
    tokens_used: Optional[int] = Field(None, description="Tokens used")


class ChainOfThought:
    """Generates Chain-of-Thought for pentesting reasoning"""

    def __init__(self, ai_service: Any):
        """
        Initialize CoT generator

        Args:
            ai_service: AI service for CoT generation
        """
        self.ai_service = ai_service

    async def generate_thought_chain(
        self,
        request: CoTRequest
    ) -> CoTResponse:
        """
        Generate Chain-of-Thought for pentesting

        Args:
            request: CoT generation request

        Returns:
            CoT response
        """
        # Build CoT prompt
        prompt = self._build_cot_prompt(request)

        # Generate CoT (this would call AI service)
        thought_chain = await self._call_ai_for_cot(prompt, request)

        # Extract next action
        next_action = self._extract_next_action(thought_chain)

        # Generate summary
        reasoning_summary = self._generate_summary(thought_chain)

        # Calculate confidence
        confidence = self._calculate_confidence(thought_chain)

        return CoTResponse(
            thought_chain=thought_chain,
            next_action=next_action,
            reasoning_summary=reasoning_summary,
            confidence=round(confidence, 2),
            timestamp=datetime.utcnow().isoformat() + "Z",
            tokens_used=None  # Would get from AI response
        )

    def _build_cot_prompt(self, request: CoTRequest) -> str:
        """
        Build Chain-of-Thought prompt

        Args:
            request: CoT request

        Returns:
            Prompt string
        """
        prompt = f"""You are an expert offensive security AI. Think through the following pentesting scenario:

TARGET: {request.target_id}
FINDING TYPE: {request.finding_type}

RECONNAISSANCE DATA:
{self._format_reconnaissance_data(request.reconnaissance_data)}

"""

        if request.context:
            prompt += f"""
CONTEXT FROM MEMORY:
{self._format_context(request.context)}
"""

        if request.previous_thoughts:
            prompt += f"""
PREVIOUS THOUGHTS:
{chr(10).join(f"{i+1}. {thought}" for i, thought in enumerate(request.previous_thoughts))}
"""

        prompt += """
Think step-by-step through this pentesting scenario. Consider:
1. What vulnerabilities might exist?
2. What attack vectors are most promising?
3. What tools or techniques should be used?
4. What evidence should be gathered?
5. What is the estimated risk and impact?

Provide your reasoning in a structured format.
"""

        return prompt

    def _format_reconnaissance_data(self, data: Dict[str, Any]) -> str:
        """Format reconnaissance data for prompt"""
        if not data:
            return "No reconnaissance data available"

        lines = []
        if "live_hosts" in data:
            lines.append(f"Live Hosts: {len(data['live_hosts'])}")
        if "open_ports" in data:
            lines.append(f"Open Ports: {len(data['open_ports'])}")
        if "endpoints" in data:
            lines.append(f"Endpoints: {len(data['endpoints'])}")

        return "\n".join(lines)

    def _format_context(self, context: Dict[str, Any]) -> str:
        """Format context for prompt"""
        if not context:
            return "No context available"

        lines = []
        if "learned_patterns" in context:
            lines.append(f"Learned Patterns: {len(context['learned_patterns'])}")
        if "active_leads" in context:
            lines.append(f"Active Leads: {len(context['active_leads'])}")

        return "\n".join(lines)

    async def _call_ai_for_cot(self, prompt: str, request: CoTRequest) -> List[str]:
        """
        Call AI for Chain-of-Thought generation

        Args:
            prompt: CoT prompt
            request: CoT request

        Returns:
            List of thoughts
        """
        # This would call actual AI service
        # For now, return mock CoT
        return [
            "Analyze reconnaissance data to identify potential attack vectors",
            "Evaluate risk level and prioritize targets",
            "Determine appropriate scanning methodology",
            "Identify suitable tools for vulnerability discovery",
            "Plan evidence collection strategy"
        ]

    def _extract_next_action(self, thought_chain: List[str]) -> str:
        """
        Extract next recommended action from CoT

        Args:
            thought_chain: Chain of thoughts

        Returns:
            Next action
        """
        if thought_chain:
            return thought_chain[-1]
        return "Execute next scan task"

    def _generate_summary(self, thought_chain: List[str]) -> str:
        """
        Generate summary of reasoning

        Args:
            thought_chain: Chain of thoughts

        Returns:
            Summary string
        """
        if not thought_chain:
            return "No reasoning available"

        # Take last thought as summary
        return thought_chain[-1]

    def _calculate_confidence(self, thought_chain: List[str]) -> float:
        """
        Calculate confidence score

        Args:
            thought_chain: Chain of thoughts

        Returns:
            Confidence score (0-1)
        """
        if not thought_chain:
            return 0.5

        # Simple heuristic: more thoughts = higher confidence
        base_confidence = min(len(thought_chain) / 5, 0.9)
        return base_confidence

    async def generate_hunting_plan(
        self,
        target_id: str,
        scan_id: str,
        finding_type: str,
        reconnaissance_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate hunting plan using CoT

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            finding_type: Type of finding
            reconnaissance_data: Reconnaissance data

        Returns:
            Hunting plan
        """
        request = CoTRequest(
            target_id=target_id,
            scan_id=scan_id,
            finding_type=finding_type,
            reconnaissance_data=reconnaissance_data
        )

        response = await self.generate_thought_chain(request)

        return {
            "target_id": target_id,
            "scan_id": scan_id,
            "finding_type": finding_type,
            "hunting_plan": {
                "thought_chain": response.thought_chain,
                "next_action": response.next_action,
                "reasoning_summary": response.reasoning_summary,
                "confidence": response.confidence
            },
            "timestamp": response.timestamp
        }

    async def generate_payload(
        self,
        target_url: str,
        vulnerability_type: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate exploit payload using CoT

        Args:
            target_url: Target URL
            vulnerability_type: Type of vulnerability
            context: Context from reconnaissance

        Returns:
            Generated payload
        """
        # This would integrate with BOAZ-MCP for payload generation
        # For now, return mock payload
        return {
            "payload": "mock_payload",
            "vulnerability_type": vulnerability_type,
            "context": context,
            "confidence": 0.8
        }