"""
Question Engine for 7-Question Gate

Generates validation questions based on finding type and severity.
"""
from typing import Dict, Any, List
from pydantic import BaseModel, Field


class Question(BaseModel):
    """Validation question"""
    id: str = Field(..., description="Question ID")
    text: str = Field(..., description="Question text")
    severity: str = Field(..., description="Severity (low, medium, high)")
    category: str = Field(..., description="Category of question")


class QuestionEngine:
    """Generates validation questions based on finding type"""

    def __init__(self):
        """Initialize question engine"""
        self._question_templates = self._load_question_templates()

    def _load_question_templates(self) -> Dict[str, List[Question]]:
        """Load question templates for different finding types"""
        return {
            "xss": [
                Question(
                    id="scope_verification",
                    text="Is the target domain within authorized scope?",
                    severity="high",
                    category="scope"
                ),
                Question(
                    id="authorization",
                    text="Do you have written authorization for XSS testing?",
                    severity="high",
                    category="authorization"
                ),
                Question(
                    id="testing_objectives",
                    text="Have you defined specific XSS testing objectives?",
                    severity="medium",
                    category="objectives"
                ),
                Question(
                    id="methodology",
                    text="Is your methodology non-destructive and safe?",
                    severity="high",
                    category="methodology"
                ),
                Question(
                    id="impact_assessment",
                    text="Have you assessed the potential impact of XSS?",
                    severity="medium",
                    category="impact"
                ),
                Question(
                    id="mitigation_strategy",
                    text="Is there a mitigation strategy for this XSS?",
                    severity="medium",
                    category="mitigation"
                ),
                Question(
                    id="timeline_definition",
                    text="Is the timeline for resolution defined?",
                    severity="low",
                    category="timeline"
                )
            ],
            "sqli": [
                Question(
                    id="scope_verification",
                    text="Is the target database within authorized scope?",
                    severity="high",
                    category="scope"
                ),
                Question(
                    id="authorization",
                    text="Do you have authorization for SQL injection testing?",
                    severity="high",
                    category="authorization"
                ),
                Question(
                    id="testing_objectives",
                    text="Have you defined specific SQL injection objectives?",
                    severity="medium",
                    category="objectives"
                ),
                Question(
                    id="methodology",
                    text="Is your methodology safe and controlled?",
                    severity="high",
                    category="methodology"
                ),
                Question(
                    id="impact_assessment",
                    text="Have you assessed the potential database impact?",
                    severity="high",
                    category="impact"
                ),
                Question(
                    id="mitigation_strategy",
                    text="Is there a mitigation strategy for SQL injection?",
                    severity="medium",
                    category="mitigation"
                ),
                Question(
                    id="timeline_definition",
                    text="Is the timeline for resolution defined?",
                    severity="low",
                    category="timeline"
                )
            ],
            "lfi": [
                Question(
                    id="scope_verification",
                    text="Is the target file system within authorized scope?",
                    severity="medium",
                    category="scope"
                ),
                Question(
                    id="authorization",
                    text="Do you have authorization for LFI testing?",
                    severity="medium",
                    category="authorization"
                ),
                Question(
                    id="testing_objectives",
                    text="Have you defined specific LFI testing objectives?",
                    severity="low",
                    category="objectives"
                ),
                Question(
                    id="methodology",
                    text="Is your methodology safe and controlled?",
                    severity="medium",
                    category="methodology"
                ),
                Question(
                    id="impact_assessment",
                    text="Have you assessed the potential file system impact?",
                    severity="medium",
                    category="impact"
                ),
                Question(
                    id="mitigation_strategy",
                    text="Is there a mitigation strategy for LFI?",
                    severity="low",
                    category="mitigation"
                ),
                Question(
                    id="timeline_definition",
                    text="Is the timeline for resolution defined?",
                    severity="low",
                    category="timeline"
                )
            ],
            "cors": [
                Question(
                    id="scope_verification",
                    text="Is the target application within authorized scope?",
                    severity="low",
                    category="scope"
                ),
                Question(
                    id="authorization",
                    text="Do you have authorization for CORS testing?",
                    severity="low",
                    category="authorization"
                ),
                Question(
                    id="testing_objectives",
                    text="Have you defined specific CORS testing objectives?",
                    severity="low",
                    category="objectives"
                ),
                Question(
                    id="methodology",
                    text="Is your methodology safe and controlled?",
                    severity="low",
                    category="methodology"
                ),
                Question(
                    id="impact_assessment",
                    text="Have you assessed the potential CORS impact?",
                    severity="low",
                    category="impact"
                ),
                Question(
                    id="mitigation_strategy",
                    text="Is there a mitigation strategy for CORS?",
                    severity="low",
                    category="mitigation"
                ),
                Question(
                    id="timeline_definition",
                    text="Is the timeline for resolution defined?",
                    severity="low",
                    category="timeline"
                )
            ],
            "ssrf": [
                Question(
                    id="scope_verification",
                    text="Is the target network within authorized scope?",
                    severity="high",
                    category="scope"
                ),
                Question(
                    id="authorization",
                    text="Do you have authorization for SSRF testing?",
                    severity="high",
                    category="authorization"
                ),
                Question(
                    id="testing_objectives",
                    text="Have you defined specific SSRF testing objectives?",
                    severity="medium",
                    category="objectives"
                ),
                Question(
                    id="methodology",
                    text="Is your methodology safe and controlled?",
                    severity="high",
                    category="methodology"
                ),
                Question(
                    id="impact_assessment",
                    text="Have you assessed the potential network impact?",
                    severity="high",
                    category="impact"
                ),
                Question(
                    id="mitigation_strategy",
                    text="Is there a mitigation strategy for SSRF?",
                    severity="medium",
                    category="mitigation"
                ),
                Question(
                    id="timeline_definition",
                    text="Is the timeline for resolution defined?",
                    severity="low",
                    category="timeline"
                )
            ],
            "generic": [
                Question(
                    id="scope_verification",
                    text="Is the target within authorized scope?",
                    severity="medium",
                    category="scope"
                ),
                Question(
                    id="authorization",
                    text="Do you have authorization for this testing?",
                    severity="high",
                    category="authorization"
                ),
                Question(
                    id="testing_objectives",
                    text="Have you defined specific testing objectives?",
                    severity="medium",
                    category="objectives"
                ),
                Question(
                    id="methodology",
                    text="Is your methodology safe and controlled?",
                    severity="high",
                    category="methodology"
                ),
                Question(
                    id="impact_assessment",
                    text="Have you assessed the potential impact?",
                    severity="medium",
                    category="impact"
                ),
                Question(
                    id="mitigation_strategy",
                    text="Is there a mitigation strategy?",
                    severity="low",
                    category="mitigation"
                ),
                Question(
                    id="timeline_definition",
                    text="Is the timeline for resolution defined?",
                    severity="low",
                    category="timeline"
                )
            ]
        }

    async def generate_questions(self, finding_type: str) -> List[Question]:
        """
        Generate validation questions for a finding type

        Args:
            finding_type: Type of finding

        Returns:
            List of questions
        """
        # Get questions for the finding type or generic
        questions = self._question_templates.get(finding_type, self._question_templates["generic"])

        # Add timestamp to questions
        from datetime import datetime
        for question in questions:
            question.id = f"{question.id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        return questions

    def get_question_categories(self) -> List[str]:
        """
        Get list of question categories

        Returns:
            List of category names
        """
        return [
            "scope",
            "authorization",
            "objectives",
            "methodology",
            "impact",
            "mitigation",
            "timeline"
        ]

    def get_question_count_by_category(self, finding_type: str) -> Dict[str, int]:
        """
        Get question count by category for a finding type

        Args:
            finding_type: Type of finding

        Returns:
            Dictionary with category counts
        """
        questions = self.generate_questions(finding_type)
        category_counts = {}

        for question in questions:
            category = question.category
            category_counts[category] = category_counts.get(category, 0) + 1

        return category_counts

    def get_severity_distribution(self, finding_type: str) -> Dict[str, int]:
        """
        Get severity distribution for a finding type

        Args:
            finding_type: Type of finding

        Returns:
            Dictionary with severity counts
        """
        questions = self.generate_questions(finding_type)
        severity_counts = {}

        for question in questions:
            severity = question.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return severity_counts