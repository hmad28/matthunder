"""
7-Question Gate Validator

Validates pentest findings using 7-question gate system before reporting.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field

from .question_engine import QuestionEngine


class GateValidationRequest(BaseModel):
    """Request for gate validation"""
    target_id: str = Field(..., description="Target domain or ID")
    finding_type: str = Field(..., description="Type of finding")
    evidence: Dict[str, Any] = Field(..., description="Evidence for the finding")
    risk_level: str = Field(..., description="Risk level (low, medium, high, critical)")
    requestor_id: Optional[str] = Field(None, description="Requestor user ID")


class GateValidationResponse(BaseModel):
    """Response for gate validation"""
    valid: bool
    score: float = Field(..., description="Validation score (0-1)")
    passed_questions: int = Field(..., description="Number of questions passed")
    failed_questions: int = Field(..., description="Number of questions failed")
    issues: List[Dict[str, Any]] = Field(default_factory=list, description="Failed validation issues")
    recommendations: List[str] = Field(default_factory=list, description="Recommendations")
    timestamp: str = Field(..., description="Validation timestamp")


class GateValidator:
    """Validates pentest findings using 7-question gate system"""

    def __init__(self, question_engine: QuestionEngine):
        """
        Initialize gate validator

        Args:
            question_engine: Question engine for generating questions
        """
        self.question_engine = question_engine

        # Question IDs
        self.QUESTION_1 = "scope_verification"
        self.QUESTION_2 = "authorization"
        self.QUESTION_3 = "testing_objectives"
        self.QUESTION_4 = "methodology"
        self.QUESTION_5 = "impact_assessment"
        self.QUESTION_6 = "mitigation_strategy"
        self.QUESTION_7 = "timeline_definition"

    async def validate_finding(
        self,
        request: GateValidationRequest
    ) -> GateValidationResponse:
        """
        Validate a finding using 7-question gate

        Args:
            request: Validation request

        Returns:
            Validation response
        """
        # Generate questions based on finding type
        questions = await self.question_engine.generate_questions(request.finding_type)

        # Evaluate each question
        passed = 0
        failed = 0
        issues = []

        for question in questions:
            result = await self._evaluate_question(
                question,
                request
            )

            if result["passed"]:
                passed += 1
            else:
                failed += 1
                issues.append({
                    "question_id": question["id"],
                    "question": question["text"],
                    "issue": result["issue"],
                    "severity": question["severity"]
                })

        # Calculate score
        score = passed / 7.0 if questions else 0.0

        # Generate recommendations
        recommendations = self._generate_recommendations(
            passed,
            failed,
            request.finding_type,
            request.evidence
        )

        return GateValidationResponse(
            valid=score >= 0.7,  # Must pass 70%+ to be valid
            score=round(score, 2),
            passed_questions=passed,
            failed_questions=failed,
            issues=issues,
            recommendations=recommendations,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

    async def _evaluate_question(
        self,
        question: Dict[str, Any],
        request: GateValidationRequest
    ) -> Dict[str, Any]:
        """
        Evaluate a single question

        Args:
            question: Question definition
            request: Validation request

        Returns:
            Evaluation result
        """
        if question["id"] == self.QUESTION_1:
            return self._validate_scope(request)
        elif question["id"] == self.QUESTION_2:
            return self._validate_authorization(request)
        elif question["id"] == self.QUESTION_3:
            return self._validate_objectives(request)
        elif question["id"] == self.QUESTION_4:
            return self._validate_methodology(request)
        elif question["id"] == self.QUESTION_5:
            return self._validate_impact(request)
        elif question["id"] == self.QUESTION_6:
            return self._validate_mitigation(request)
        elif question["id"] == self.QUESTION_7:
            return self._validate_timeline(request)
        else:
            return {"passed": False, "issue": "Unknown question"}

    def _validate_scope(self, request: GateValidationRequest) -> Dict[str, Any]:
        """Question 1: Scope verification"""
        evidence = request.evidence
        target_id = request.target_id

        # Check if target is in scope
        # (This would check against scope rules in production)
        scope_verified = True  # Simplified for now

        if not scope_verified:
            return {
                "passed": False,
                "issue": "Target is not within authorized scope"
            }

        return {"passed": True}

    def _validate_authorization(self, request: GateValidationRequest) -> Dict[str, Any]:
        """Question 2: Authorization confirmation"""
        evidence = request.evidence

        # Check if written permission exists
        # (This would check against approval workflow in production)
        has_permission = True  # Simplified for now

        if not has_permission:
            return {
                "passed": False,
                "issue": "No written authorization found"
            }

        return {"passed": True}

    def _validate_objectives(self, request: GateValidationRequest) -> Dict[str, Any]:
        """Question 3: Testing objectives"""
        evidence = request.evidence
        finding_type = request.finding_type

        # Check if objectives are specific
        objectives = evidence.get("objectives", [])

        if not objectives:
            return {
                "passed": False,
                "issue": "No specific testing objectives specified"
            }

        # Check if objectives match finding type
        valid_objectives = [
            obj for obj in objectives
            if self._is_valid_objective_for_finding(obj, finding_type)
        ]

        if len(valid_objectives) < len(objectives) * 0.5:
            return {
                "passed": False,
                "issue": "Objectives do not match the finding type"
            }

        return {"passed": True}

    def _is_valid_objective_for_finding(self, objective: str, finding_type: str) -> bool:
        """Check if objective is valid for finding type"""
        valid_pairs = {
            "xss": ["reflected_xss", "stored_xss", "dom_xss"],
            "sqli": ["sql_injection", "blind_sql_injection"],
            "lfi": ["local_file_inclusion", "remote_file_inclusion"],
            "cors": ["cors_misconfiguration"],
            "ssrf": ["server_side_request_forger"],
            "sssti": ["server_side_template_injection"]
        }

        valid_objectives = valid_pairs.get(finding_type, [])
        return any(obj.lower() in objective.lower() for obj in valid_objectives)

    def _validate_methodology(self, request: GateValidationRequest) -> Dict[str, Any]:
        """Question 4: Methodology selection"""
        evidence = request.evidence

        # Check if methodology is appropriate
        methodology = evidence.get("methodology", "")

        if not methodology:
            return {
                "passed": False,
                "issue": "No methodology specified"
            }

        # Check for safe methodologies
        safe_methods = ["non-destructive", "verification", "proof-of-concept"]
        is_safe = any(method.lower() in methodology.lower() for method in safe_methods)

        if not is_safe:
            return {
                "passed": False,
                "issue": "Methodology may cause damage"
            }

        return {"passed": True}

    def _validate_impact(self, request: GateValidationRequest) -> Dict[str, Any]:
        """Question 5: Impact assessment"""
        evidence = request.evidence
        risk_level = request.risk_level

        # Check if impact is realistic
        impact_assessment = evidence.get("impact_assessment", "")

        if not impact_assessment:
            return {
                "passed": False,
                "issue": "No impact assessment provided"
            }

        # Check if impact is proportional to risk level
        if risk_level in ["high", "critical"]:
            if len(impact_assessment) < 50:
                return {
                    "passed": False,
                    "issue": "Impact assessment too brief for high-risk finding"
                }

        return {"passed": True}

    def _validate_mitigation(self, request: GateValidationRequest) -> Dict[str, Any]:
        """Question 6: Mitigation strategy"""
        evidence = request.evidence

        # Check if mitigation is provided
        mitigation = evidence.get("mitigation", "")

        if not mitigation:
            return {
                "passed": False,
                "issue": "No mitigation strategy provided"
            }

        # Check if mitigation is actionable
        if len(mitigation) < 10:
            return {
                "passed": False,
                "issue": "Mitigation strategy too brief"
            }

        return {"passed": True}

    def _validate_timeline(self, request: GateValidationRequest) -> Dict[str, Any]:
        """Question 7: Timeline definition"""
        evidence = request.evidence

        # Check if timeline is defined
        timeline = evidence.get("timeline", "")

        if not timeline:
            return {
                "passed": False,
                "issue": "No timeline defined"
            }

        # Check if timeline is realistic
        if "days" in timeline.lower() and int(timeline.split()[0]) > 7:
            return {
                "passed": False,
                "issue": "Timeline exceeds acceptable duration"
            }

        return {"passed": True}

    def _generate_recommendations(
        self,
        passed: int,
        failed: int,
        finding_type: str,
        evidence: Dict[str, Any]
    ) -> List[str]:
        """
        Generate recommendations based on validation results

        Args:
            passed: Number of questions passed
            failed: Number of questions failed
            finding_type: Type of finding
            evidence: Finding evidence

        Returns:
            List of recommendations
        """
        recommendations = []

        if failed > 0:
            recommendations.append(
                "Address failed validation questions before reporting this finding"
            )

        if finding_type == "xss":
            if not evidence.get("evidence", ""):
                recommendations.append("Provide proof-of-concept PoC for XSS")
            if not evidence.get("payload", ""):
                recommendations.append("Capture actual XSS payload used")

        elif finding_type == "sqli":
            if not evidence.get("query", ""):
                recommendations.append("Document the SQL query used")
            if not evidence.get("result", ""):
                recommendations.append("Show database response")

        elif finding_type == "lfi":
            if not evidence.get("path", ""):
                recommendations.append("Document the file path accessed")
            if not evidence.get("response", ""):
                recommendations.append("Show file content retrieved")

        if not evidence.get("methodology", ""):
            recommendations.append("Define appropriate testing methodology")

        if not evidence.get("impact", ""):
            recommendations.append("Provide detailed impact assessment")

        if passed < 5:
            recommendations.append("Consider lowering risk level or gathering more evidence")

        return recommendations