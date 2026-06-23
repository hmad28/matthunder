"""
Coordination Engine for Swarm Intelligence

Coordinates worker agents using pheromone-based stigmergy.
"""
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from enum import Enum

from .pheromone_system import PheromoneSystem, PheromoneMatrix, FindingPriority


class WorkerState(str, Enum):
    """Worker agent states"""
    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    OFFLINE = "offline"


class CoordinationEngine:
    """Coordinates worker agents using pheromone stigmergy"""

    def __init__(self, pheromone_system: PheromoneSystem):
        """
        Initialize coordination engine

        Args:
            pheromone_system: Pheromone system for coordination
        """
        self.pheromone_system = pheromone_system
        self._workers: Dict[str, Dict[str, Any]] = {}
        self._task_handlers: Dict[str, Callable] = {}

    def register_worker(
        self,
        worker_id: str,
        worker_type: str,
        capabilities: List[str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Register a worker agent

        Args:
            worker_id: Worker ID
            worker_type: Type of worker (exploit, recon, etc.)
            capabilities: List of capabilities
            metadata: Additional metadata
        """
        self._workers[worker_id] = {
            "id": worker_id,
            "type": worker_type,
            "capabilities": capabilities,
            "state": WorkerState.IDLE,
            "current_task": None,
            "registered_at": datetime.utcnow().isoformat() + "Z",
            "last_heartbeat": datetime.utcnow().isoformat() + "Z",
            "metadata": metadata or {}
        }

    def unregister_worker(self, worker_id: str) -> bool:
        """Unregister a worker"""
        if worker_id in self._workers:
            del self._workers[worker_id]
            return True
        return False

    def get_worker(self, worker_id: str) -> Optional[Dict[str, Any]]:
        """Get worker information"""
        return self._workers.get(worker_id)

    def get_available_workers(self) -> List[Dict[str, Any]]:
        """Get all idle workers"""
        return [
            worker for worker in self._workers.values()
            if worker["state"] == WorkerState.IDLE
        ]

    def get_busy_workers(self) -> List[Dict[str, Any]]:
        """Get all busy workers"""
        return [
            worker for worker in self._workers.values()
            if worker["state"] == WorkerState.BUSY
        ]

    def assign_task(
        self,
        worker_id: str,
        task: Dict[str, Any]
    ) -> bool:
        """
        Assign task to a worker

        Args:
            worker_id: Worker ID
            task: Task to assign

        Returns:
            True if task assigned
        """
        worker = self._workers.get(worker_id)
        if not worker or worker["state"] != WorkerState.IDLE:
            return False

        worker["state"] = WorkerState.BUSY
        worker["current_task"] = task
        worker["task_assigned_at"] = datetime.utcnow().isoformat() + "Z"

        # Register task handler
        task_type = task.get("type", "generic")
        if task_type in self._task_handlers:
            handler = self._task_handlers[task_type]
            handler(worker_id, task)

        return True

    def complete_task(
        self,
        worker_id: str,
        task_result: Dict[str, Any]
    ) -> bool:
        """
        Mark worker task as completed

        Args:
            worker_id: Worker ID
            task_result: Task completion result

        Returns:
            True if successful
        """
        worker = self._workers.get(worker_id)
        if not worker:
            return False

        worker["state"] = WorkerState.IDLE
        worker["current_task"] = None
        worker["last_completed"] = datetime.utcnow().isoformat() + "Z"

        # Update pheromone matrix based on task result
        if task_result.get("success"):
            self._update_pheromone_from_result(task_result)

        return True

    def _update_pheromone_from_result(self, result: Dict[str, Any]) -> None:
        """Update pheromone based on task result"""
        findings = result.get("findings", [])
        if findings:
            self.pheromone_system.update_from_finding(
                target_id=result.get("target_id", ""),
                scanner_name=result.get("scanner", "unknown"),
                finding_type=result.get("finding_type", "generic"),
                findings=findings
            )

    def find_best_worker(
        self,
        task_type: str,
        required_capabilities: List[str]
    ) -> Optional[Dict[str, Any]]:
        """
        Find best worker for a task

        Args:
            task_type: Type of task
            required_capabilities: Required capabilities

        Returns:
            Best worker or None
        """
        available_workers = self.get_available_workers()

        # Filter by capabilities
        qualified_workers = [
            worker for worker in available_workers
            if self._has_capabilities(worker, required_capabilities)
        ]

        if not qualified_workers:
            return None

        # Score workers based on pheromone data
        scored_workers = []
        for worker in qualified_workers:
            score = self._calculate_worker_score(worker, task_type)
            scored_workers.append((score, worker))

        # Sort by score descending
        scored_workers.sort(key=lambda x: x[0], reverse=True)

        return scored_workers[0][1] if scored_workers else None

    def _has_capabilities(
        self,
        worker: Dict[str, Any],
        required_capabilities: List[str]
    ) -> bool:
        """Check if worker has required capabilities"""
        worker_caps = worker.get("capabilities", [])
        return all(cap in worker_caps for cap in required_capabilities)

    def _calculate_worker_score(
        self,
        worker: Dict[str, Any],
        task_type: str
    ) -> float:
        """
        Calculate worker score based on pheromone data

        Args:
            worker: Worker data
            task_type: Type of task

        Returns:
            Score (0-1)
        """
        score = 0.5  # Default score
        worker_id = worker["id"]

        # Get pheromone data for this worker
        pheromone_entries = self.pheromone_system.get_all_recommendations()

        # Calculate based on success rate
        successful_tasks = sum(
            1 for entry in pheromone_entries
            if entry.scanner_name == worker_id and entry.success_rate > 0.5
        )

        total_tasks = sum(
            1 for entry in pheromone_entries
            if entry.scanner_name == worker_id
        )

        if total_tasks > 0:
            score += (successful_tasks / total_tasks) * 0.3

        # Calculate based on experience
        score += min(worker.get("iterations", 0) * 0.01, 0.2)

        return min(score, 1.0)

    def register_task_handler(
        self,
        task_type: str,
        handler: Callable
    ) -> None:
        """
        Register handler for task type

        Args:
            task_type: Task type
            handler: Handler function
        """
        self._task_handlers[task_type] = handler

    def get_worker_statistics(self) -> Dict[str, Any]:
        """
        Get coordination statistics

        Returns:
            Statistics dictionary
        """
        return {
            "total_workers": len(self._workers),
            "available_workers": len(self.get_available_workers()),
            "busy_workers": len(self.get_busy_workers()),
            "registered_task_types": list(self._task_handlers.keys()),
            "workers": [
                {
                    "id": worker["id"],
                    "type": worker["type"],
                    "state": worker["state"].value,
                    "current_task": worker["current_task"],
                    "last_heartbeat": worker.get("last_heartbeat")
                }
                for worker in self._workers.values()
            ]
        }

    def get_worker_health(self) -> Dict[str, str]:
        """
        Get health status of all workers

        Returns:
            Worker health status
        """
        health = {}
        for worker_id, worker in self._workers.items():
            # Check if heartbeat is recent (< 30 seconds)
            last_heartbeat = datetime.fromisoformat(worker.get("last_heartbeat", datetime.utcnow().isoformat() + "Z").replace('Z', '+00:00'))
            time_since_heartbeat = (datetime.utcnow() - last_heartbeat).total_seconds()

            if time_since_heartbeat < 30:
                health[worker_id] = "healthy"
            elif time_since_heartbeat < 60:
                health[worker_id] = "degraded"
            else:
                health[worker_id] = "unhealthy"

        return health

    def heart_beat(self, worker_id: str) -> bool:
        """
        Update worker heartbeat

        Args:
            worker_id: Worker ID

        Returns:
            True if worker exists
        """
        worker = self._workers.get(worker_id)
        if not worker:
            return False

        worker["last_heartbeat"] = datetime.utcnow().isoformat() + "Z"
        return True

    def distribute_workload(
        self,
        tasks: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Distribute tasks among workers

        Args:
            tasks: List of tasks to distribute

        Returns:
            List of assigned tasks
        """
        assigned = []

        for task in tasks:
            task_type = task.get("type", "generic")
            required_capabilities = task.get("required_capabilities", [])

            # Find best worker
            best_worker = self.find_best_worker(task_type, required_capabilities)

            if best_worker:
                # Assign task
                self.assign_task(best_worker["id"], task)
                assigned.append({
                    "task": task,
                    "worker_id": best_worker["id"],
                    "status": "assigned"
                })
            else:
                assigned.append({
                    "task": task,
                    "worker_id": None,
                    "status": "no_worker_available"
                })

        return assigned