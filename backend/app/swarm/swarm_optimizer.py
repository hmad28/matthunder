"""
Swarm Optimizer for Swarm Intelligence

Optimizes swarm performance by tuning pheromone parameters.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import math

from .pheromone_system import PheromoneSystem, FindingPriority


class SwarmOptimizer:
    """Optimizes swarm intelligence parameters"""

    def __init__(self, pheromone_system: PheromoneSystem):
        """
        Initialize swarm optimizer

        Args:
            pheromone_system: Pheromone system
        """
        self.pheromone_system = pheromone_system
        self._performance_history: List[Dict[str, Any]] = []
        self._optimization_iterations = 0

    def optimize_decay_constants(self) -> Dict[str, float]:
        """
        Optimize decay constants based on performance

        Returns:
            Optimized decay constants
        """
        history = self._performance_history[-10:]  # Last 10 iterations

        if not history:
            return self._get_default_decay_constants()

        # Calculate average performance metrics
        avg_success_rate = sum(h.get("success_rate", 0.5) for h in history) / len(history)
        avg_completion_time = sum(h.get("completion_time_seconds", 300) for h in history) / len(history)

        # Adjust decay constants based on performance
        decay_constants = {
            FindingPriority.CRITICAL: self._optimize_single_constant(
                5.0, avg_success_rate, avg_completion_time
            ),
            FindingPriority.HIGH: self._optimize_single_constant(
                2.0, avg_success_rate, avg_completion_time
            ),
            FindingPriority.MEDIUM: self._optimize_single_constant(
                0.5, avg_success_rate, avg_completion_time
            ),
            FindingPriority.LOW: self._optimize_single_constant(
                0.1, avg_success_rate, avg_completion_time
            )
        }

        self._optimization_iterations += 1
        return decay_constants

    def _get_default_decay_constants(self) -> Dict[str, float]:
        """Get default decay constants"""
        return {
            FindingPriority.CRITICAL: 5.0,
            FindingPriority.HIGH: 2.0,
            FindingPriority.MEDIUM: 0.5,
            FindingPriority.LOW: 0.1
        }

    def _optimize_single_constant(
        self,
        base_constant: float,
        success_rate: float,
        completion_time: float
    ) -> float:
        """
        Optimize single decay constant

        Args:
            base_constant: Base decay constant
            success_rate: Success rate (0-1)
            completion_time: Average completion time in seconds

        Returns:
            Optimized decay constant
        """
        # Increase decay (faster decay) if success rate is high
        if success_rate > 0.7:
            return base_constant * 1.2
        # Decrease decay if completion time is long
        elif completion_time > 600:
            return base_constant * 0.8
        else:
            return base_constant

    def record_performance(
        self,
        success_rate: float,
        completion_time_seconds: float,
        findings_count: int,
        workers_used: int
    ) -> None:
        """
        Record performance metrics

        Args:
            success_rate: Success rate (0-1)
            completion_time_seconds: Average completion time
            findings_count: Number of findings
            workers_used: Number of workers used
        """
        self._performance_history.append({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "success_rate": success_rate,
            "completion_time_seconds": completion_time_seconds,
            "findings_count": findings_count,
            "workers_used": workers_used
        })

        # Keep last 100 entries
        if len(self._performance_history) > 100:
            self._performance_history = self._performance_history[-100:]

    def get_optimization_recommendations(self) -> Dict[str, Any]:
        """
        Get swarm optimization recommendations

        Returns:
            Optimization recommendations
        """
        history = self._performance_history[-20:]  # Last 20 iterations

        if not history:
            return {"message": "Not enough data for recommendations"}

        recommendations = {}
        avg_success = sum(h["success_rate"] for h in history) / len(history)
        avg_time = sum(h["completion_time_seconds"] for h in history) / len(history)

        # Worker scaling recommendations
        if avg_time > 300:
            recommendations["worker_scaling"] = {
                "suggested_addition": min(int(avg_time / 300), 5),
                "reason": "Average completion time exceeds 5 minutes"
            }

        # Pheromone concentration recommendations
        if avg_success < 0.5:
            recommendations["pheromone_concentration"] = {
                "suggested_adjustment": "decrease by 20%",
                "reason": "Low success rate indicates aggressive exploration"
            }
        elif avg_success > 0.8:
            recommendations["pheromone_concentration"] = {
                "suggested_adjustment": "increase by 20%",
                "reason": "High success rate indicates conservative exploration"
            }

        return recommendations

    def get_performance_summary(self) -> Dict[str, Any]:
        """
        Get performance summary

        Returns:
            Performance summary
        """
        if not self._performance_history:
            return {"message": "No performance data available"}

        total_iterations = len(self._performance_history)
        recent = self._performance_history[-10:]

        avg_success = sum(h["success_rate"] for h in recent) / len(recent) if recent else 0
        avg_time = sum(h["completion_time_seconds"] for h in recent) / len(recent) if recent else 0
        avg_findings = sum(h["findings_count"] for h in recent) / len(recent) if recent else 0
        avg_workers = sum(h["workers_used"] for h in recent) / len(recent) if recent else 0

        return {
            "total_iterations": total_iterations,
            "recent_stats": {
                "avg_success_rate": round(avg_success, 3),
                "avg_completion_time_seconds": round(avg_time, 2),
                "avg_findings_per_scan": round(avg_findings, 1),
                "avg_workers_per_scan": round(avg_workers, 1)
            },
            "trend": self._calculate_trend(),
            "optimization_iterations": self._optimization_iterations
        }

    def _calculate_trend(self) -> str:
        """Calculate performance trend"""
        if len(self._performance_history) < 5:
            return "neutral"

        recent = self._performance_history[-5:]
        older = self._performance_history[-10:-5]

        recent_avg = sum(h["success_rate"] for h in recent) / len(recent)
        older_avg = sum(h["success_rate"] for h in older) / len(older)

        if recent_avg > older_avg * 1.1:
            return "improving"
        elif recent_avg < older_avg * 0.9:
            return "degrading"
        else:
            return "stable"

    def calculate_swarm_efficiency(self) -> float:
        """
        Calculate overall swarm efficiency

        Returns:
            Efficiency score (0-1)
        """
        if not self._performance_history:
            return 0.5

        recent = self._performance_history[-10:]
        if not recent:
            return 0.5

        avg_success = sum(h["success_rate"] for h in recent) / len(recent)
        avg_workers = sum(h["workers_used"] for h in recent) / len(recent)
        avg_findings = sum(h["findings_count"] for h in recent) / len(recent)

        # Efficiency = (success_rate * findings_per_worker) / base_line
        efficiency = (avg_success * avg_findings) / max(avg_workers, 1)
        return min(efficiency, 1.0)

    def get_swarm_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive swarm metrics for dashboard

        Returns:
            Swarm metrics
        """
        return {
            "efficiency": round(self.calculate_swarm_efficiency(), 3),
            "performance": self.get_performance_summary(),
            "optimization": self.get_optimization_recommendations(),
            "decay_constants": {
                "critical": 5.0,
                "high": 2.0,
                "medium": 0.5,
                "low": 0.1
            },
            "performance_history": self._performance_history[-5:]
        }