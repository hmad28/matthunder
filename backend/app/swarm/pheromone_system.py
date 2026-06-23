"""
Pheromone System for Swarm Intelligence 

Manages pheromone-based coordination for decentralized agent orchestration.
Pheromones decay exponentially to prioritize time-sensitive findings.
"""
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import math
from enum import Enum


class FindingPriority(str, Enum):
    """Priority levels for findings based on pheromone"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class PheromoneMatrix:
    """Single pheromone entry in the swarm matrix"""
    target_id: str
    scanner_name: str
    finding_type: str
    target_url: Optional[str] = None
    success_rate: float = 0.5
    confidence: float = 0.5
    concentration: float = 0.5  # τ (tau) - pheromone concentration (0-1)
    initial_concentration: float = 0.5  # τ₀ initial concentration
    decay_constant: float = 0.5  # λd decay constant
    iterations: int = 1
    last_update: datetime = field(default_factory=datetime.utcnow)
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_current_concentration(self) -> float:
        """
        Calculate current concentration with exponential decay
        τ(t) = τ₀ * e^(-λd * t)

        Returns:
            Current concentration (0-1)
        """
        elapsed = (datetime.utcnow() - self.last_update).total_seconds()
        # Convert seconds to hours
        elapsed_hours = elapsed / 3600
        return self.initial_concentration * math.exp(-self.decay_constant * elapsed_hours)

    def get_half_life(self) -> float:
        """
        Calculate half-life in hours
        t(½) = ln(2) / λd

        Returns:
            Half-life in hours
        """
        return math.log(2) / self.decay_constant if self.decay_constant > 0 else float('inf')

    def is_expired(self, threshold: float = 0.1) -> bool:
        """Check if pheromone has expired"""
        return self.get_current_concentration() < threshold

    def get_priority(self) -> FindingPriority:
        """Get priority based on current concentration"""
        conc = self.get_current_concentration()
        if conc >= 0.8:
            return FindingPriority.CRITICAL
        elif conc >= 0.6:
            return FindingPriority.HIGH
        elif conc >= 0.4:
            return FindingPriority.MEDIUM
        else:
            return FindingPriority.LOW

    def reinforce(self, factor: float = 0.1) -> None:
        """
        Reinforce pheromone trail
        τ(t) = τ(t) + factor * (1 - τ(t))

        Args:
            factor: Reinforcement factor
        """
        current = self.get_current_concentration()
        self.concentration = current + factor * (1 - current)
        self.initial_concentration = self.concentration
        self.iterations += 1
        self.last_update = datetime.utcnow()

    def decay(self, decay_constant: float = None) -> None:
        """
        Decay pheromone over time
        τ(t) = τ₀ * e^(-λd * t)

        Args:
            decay_constant: Decay constant (defaults to object's decay_constant)
        """
        if decay_constant is not None:
            self.decay_constant = decay_constant
        self.concentration = self.get_current_concentration()
        self.last_update = datetime.utcnow()


class PheromoneSystem:
    """Manages pheromone matrix for swarm coordination"""

    def __init__(self):
        """Initialize pheromone system"""
        self._matrix: Dict[str, PheromoneMatrix] = {}
        self._decay_constants = {
            FindingPriority.CRITICAL: 5.0,  # ~8 minutes half-life
            FindingPriority.HIGH: 2.0,      # ~21 minutes half-life
            FindingPriority.MEDIUM: 0.5,    # ~1.4 hours half-life
            FindingPriority.LOW: 0.1        # ~6.9 hours half-life
        }

    def deposit_pheromone(
        self,
        target_id: str,
        scanner_name: str,
        finding_type: str,
        success_rate: float = 0.5,
        confidence: float = 0.5,
        target_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> PheromoneMatrix:
        """
        Deposit pheromone for a finding

        Args:
            target_id: Target domain or ID
            scanner_name: Scanner name
            finding_type: Type of finding
            success_rate: Success rate (0-1)
            confidence: Confidence score (0-1)
            target_url: Target URL
            metadata: Additional metadata

        Returns:
            PheromoneMatrix entry
        """
        key = self._get_key(target_id, scanner_name, finding_type, target_url)

        if key in self._matrix:
            # Update existing entry
            entry = self._matrix[key]
            entry.success_rate = (entry.success_rate + success_rate) / 2
            entry.confidence = (entry.confidence + confidence) / 2
            entry.reinforce()
            if metadata:
                entry.metadata.update(metadata)
        else:
            # Create new entry
            priority = self._determine_initial_priority(success_rate, confidence)
            decay_constant = self._decay_constants[priority]

            entry = PheromoneMatrix(
                target_id=target_id,
                scanner_name=scanner_name,
                finding_type=finding_type,
                target_url=target_url,
                success_rate=success_rate,
                confidence=confidence,
                concentration=success_rate,
                initial_concentration=success_rate,
                decay_constant=decay_constant,
                metadata=metadata or {}
            )
            self._matrix[key] = entry

        return entry

    def _get_key(
        self,
        target_id: str,
        scanner_name: str,
        finding_type: str,
        target_url: Optional[str] = None
    ) -> str:
        """Generate unique key for pheromone entry"""
        base = f"{target_id}:{scanner_name}:{finding_type}"
        if target_url:
            base += f":{target_url}"
        return base

    def _determine_initial_priority(
        self,
        success_rate: float,
        confidence: float
    ) -> FindingPriority:
        """Determine initial priority based on scores"""
        score = (success_rate + confidence) / 2

        if score >= 0.8:
            return FindingPriority.CRITICAL
        elif score >= 0.6:
            return FindingPriority.HIGH
        elif score >= 0.4:
            return FindingPriority.MEDIUM
        else:
            return FindingPriority.LOW

    def get_target_recommendations(
        self,
        target_id: str,
        min_concentration: float = 0.1
    ) -> List[PheromoneMatrix]:
        """
        Get pheromone recommendations for a target

        Args:
            target_id: Target domain or ID
            min_concentration: Minimum concentration threshold

        Returns:
            List of pheromone entries sorted by concentration
        """
        recommendations = []
        now = datetime.utcnow()

        for entry in self._matrix.values():
            if entry.target_id != target_id:
                continue

            current_conc = entry.get_current_concentration()
            if current_conc >= min_concentration:
                recommendations.append(entry)

        # Sort by concentration descending
        recommendations.sort(
            key=lambda x: x.get_current_concentration(),
            reverse=True
        )

        return recommendations

    def get_all_recommendations(
        self,
        min_concentration: float = 0.1
    ) -> List[PheromoneMatrix]:
        """
        Get all pheromone recommendations across targets

        Args:
            min_concentration: Minimum concentration threshold

        Returns:
            List of pheromone entries
        """
        recommendations = []

        for entry in self._matrix.values():
            if entry.get_current_concentration() >= min_concentration:
                recommendations.append(entry)

        return recommendations

    def get_target_statistics(self, target_id: str) -> Dict[str, Any]:
        """
        Get pheromone statistics for a target

        Args:
            target_id: Target domain or ID

        Returns:
            Statistics dictionary
        """
        entries = [e for e in self._matrix.values() if e.target_id == target_id]

        if not entries:
            return {
                "target_id": target_id,
                "total_entries": 0,
                "active_entries": 0,
                "avg_concentration": 0.0,
                "avg_success_rate": 0.0,
                "avg_confidence": 0.0
            }

        active = [e for e in entries if e.get_current_concentration() >= 0.1]

        return {
            "target_id": target_id,
            "total_entries": len(entries),
            "active_entries": len(active),
            "avg_concentration": sum(e.get_current_concentration() for e in entries) / len(entries),
            "avg_success_rate": sum(e.success_rate for e in entries) / len(entries),
            "avg_confidence": sum(e.confidence for e in entries) / len(entries)
        }

    def get_overall_statistics(self) -> Dict[str, Any]:
        """
        Get overall swarm statistics

        Returns:
            Statistics dictionary
        """
        targets = set(e.target_id for e in self._matrix.values())

        return {
            "total_targets": len(targets),
            "total_entries": len(self._matrix),
            "active_entries": sum(1 for e in self._matrix.values() if e.get_current_concentration() >= 0.1),
            "critical_entries": sum(1 for e in self._matrix.values() if e.get_priority() == FindingPriority.CRITICAL),
            "high_entries": sum(1 for e in self._matrix.values() if e.get_priority() == FindingPriority.HIGH),
            "medium_entries": sum(1 for e in self._matrix.values() if e.get_priority() == FindingPriority.MEDIUM),
            "low_entries": sum(1 for e in self._matrix.values() if e.get_priority() == FindingPriority.LOW),
            "scanner_distribution": self._get_scanner_distribution(),
            "finding_type_distribution": self._get_finding_type_distribution()
        }

    def _get_scanner_distribution(self) -> Dict[str, int]:
        """Get distribution of pheromones by scanner"""
        distribution = {}
        for entry in self._matrix.values():
            scanner = entry.scanner_name
            distribution[scanner] = distribution.get(scanner, 0) + 1
        return distribution

    def _get_finding_type_distribution(self) -> Dict[str, int]:
        """Get distribution of pheromones by finding type"""
        distribution = {}
        for entry in self._matrix.values():
            ftype = entry.finding_type
            distribution[ftype] = distribution.get(ftype, 0) + 1
        return distribution

    def decay_all(self) -> int:
        """
        Decay all pheromone entries

        Returns:
            Number of entries decayed
        """
        count = 0
        expired_keys = []

        for key, entry in self._matrix.items():
            entry.decay()
            count += 1
            if entry.is_expired():
                expired_keys.append(key)

        # Remove expired entries
        for key in expired_keys:
            del self._matrix[key]

        return count

    def clear_target(self, target_id: str) -> int:
        """
        Clear all pheromone entries for a target

        Args:
            target_id: Target domain or ID

        Returns:
            Number of entries cleared
        """
        keys_to_clear = [
            key for key, entry in self._matrix.items()
            if entry.target_id == target_id
        ]

        for key in keys_to_clear:
            del self._matrix[key]

        return len(keys_to_clear)

    def get_pheromone_heatmap(
        self,
        target_id: Optional[str] = None
    ) -> Dict[str, Dict[str, float]]:
        """
        Get pheromone heatmap for visualization

        Args:
            target_id: Optional target filter

        Returns:
            Heatmap data
        """
        heatmap = {}

        for key, entry in self._matrix.items():
            if target_id and entry.target_id != target_id:
                continue

            concentration = entry.get_current_concentration()
            heatmap[key] = {
                "concentration": concentration,
                "priority": entry.get_priority().value,
                "success_rate": entry.success_rate,
                "confidence": entry.confidence,
                "iterations": entry.iterations,
                "half_life": round(entry.get_half_life(), 2),
                "is_expired": entry.is_expired()
            }

        return heatmap

    def update_from_finding(
        self,
        target_id: str,
        scanner_name: str,
        finding_type: str,
        findings: List[Dict[str, Any]]
    ) -> None:
        """
        Update pheromone matrix based on findings

        Args:
            target_id: Target domain or ID
            scanner_name: Scanner name
            finding_type: Type of finding
            findings: List of findings
        """
        if not findings:
            return

        # Calculate success rate based on number of findings
        success_rate = min(len(findings) / 10, 1.0)
        confidence = min(sum(f.get("confidence", 0.5) for f in findings) / len(findings), 1.0)

        self.deposit_pheromone(
            target_id=target_id,
            scanner_name=scanner_name,
            finding_type=finding_type,
            success_rate=success_rate,
            confidence=confidence
        )

    def get_priority_recommendation(
        self,
        target_id: Optional[str] = None,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Get prioritized recommendations

        Args:
            target_id: Optional target filter
            limit: Maximum recommendations

        Returns:
            List of prioritized recommendations
        """
        recommendations = self.get_target_recommendations(target_id) if target_id else self.get_all_recommendations()

        recommendations.sort(
            key=lambda x: (x.get_current_concentration(), x.success_rate, x.confidence),
            reverse=True
        )

        result = []
        for entry in recommendations[:limit]:
            result.append({
                "target_id": entry.target_id,
                "scanner": entry.scanner_name,
                "finding_type": entry.finding_type,
                "url": entry.target_url,
                "concentration": round(entry.get_current_concentration(), 3),
                "priority": entry.get_priority().value,
                "success_rate": round(entry.success_rate, 2),
                "confidence": round(entry.confidence, 2),
                "iterations": entry.iterations,
                "half_life_hours": round(entry.get_half_life(), 2)
            })

        return result

    def get_swarm_matrix(self) -> Dict[str, Any]:
        """
        Get full swarm matrix for dashboard visualization

        Returns:
            Swarm matrix data
        """
        return {
            "statistics": self.get_overall_statistics(),
            "heatmap": self.get_pheromone_heatmap(),
            "priority_recommendations": self.get_priority_recommendation(limit=10),
            "last_decay": datetime.utcnow().isoformat() + "Z"
        }