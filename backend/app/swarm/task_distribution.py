"""
Task Distributor for Swarm Intelligence

Distributes tasks among workers based on pheromone-based priority.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum

from .pheromone_system import PheromoneSystem, FindingPriority


class TaskStatus(str, Enum):
    """Task statuses"""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class TaskDistributor:
    """Distributes tasks among workers based on pheromone priority"""

    def __init__(self, pheromone_system: PheromoneSystem):
        """
        Initialize task distributor

        Args:
            pheromone_system: Pheromone system for prioritization
        """
        self.pheromone_system = pheromone_system
        self._task_queue: List[Dict[str, Any]] = []
        self._active_tasks: Dict[str, Dict[str, Any]] = {}
        self._completed_tasks: List[Dict[str, Any]] = []
        self._max_active_tasks = 10

    def enqueue_task(
        self,
        task: Dict[str, Any]
    ) -> str:
        """
        Enqueue a task for distribution

        Args:
            task: Task definition

        Returns:
            Task ID
        """
        task_id = f"task_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{len(self._task_queue)}"
        task["id"] = task_id
        task["status"] = TaskStatus.PENDING
        task["enqueued_at"] = datetime.utcnow().isoformat() + "Z"
        task["priority"] = self._calculate_task_priority(task)

        self._task_queue.append(task)

        return task_id

    def _calculate_task_priority(self, task: Dict[str, Any]) -> float:
        """
        Calculate task priority based on pheromone data

        Args:
            task: Task definition

        Returns:
            Priority score (0-1)
        """
        target_id = task.get("target_id", "")
        scanner = task.get("scanner", "")
        finding_type = task.get("finding_type", "generic")

        # Get pheromone recommendations
        recommendations = self.pheromone_system.get_target_recommendations(target_id)

        # Find matching recommendations
        matching = [
            r for r in recommendations
            if r.scanner_name == scanner or r.finding_type == finding_type
        ]

        if matching:
            avg_concentration = sum(r.get_current_concentration() for r in matching) / len(matching)
            avg_success = sum(r.success_rate for r in matching) / len(matching)
            avg_confidence = sum(r.confidence for r in matching) / len(matching)
            return (avg_concentration * 0.4 + avg_success * 0.3 + avg_confidence * 0.3)

        return 0.5  # Default medium priority

    def dequeue_task(self) -> Optional[Dict[str, Any]]:
        """
        Dequeue highest priority task

        Returns:
            Highest priority task or None
        """
        if not self._task_queue:
            return None

        # Sort by priority descending
        self._task_queue.sort(
            key=lambda x: x.get("priority", 0.5),
            reverse=True
        )

        task = self._task_queue.pop(0)
        task["status"] = TaskStatus.ASSIGNED
        task["dequeued_at"] = datetime.utcnow().isoformat() + "Z"

        self._active_tasks[task["id"]] = task

        return task

    def complete_task(
        self,
        task_id: str,
        result: Dict[str, Any]
    ) -> bool:
        """
        Mark task as completed

        Args:
            task_id: Task ID
            result: Task result

        Returns:
            True if successful
        """
        task = self._active_tasks.pop(task_id, None)
        if not task:
            return False

        task["status"] = TaskStatus.COMPLETED
        task["result"] = result
        task["completed_at"] = datetime.utcnow().isoformat() + "Z"

        self._completed_tasks.append(task)

        # Update pheromone matrix
        self.pheromone_system.update_from_finding(
            target_id=result.get("target_id", task.get("target_id", "")),
            scanner_name=result.get("scanner", task.get("scanner", "unknown")),
            finding_type=result.get("finding_type", task.get("finding_type", "generic")),
            findings=result.get("findings", [])
        )

        return True

    def fail_task(
        self,
        task_id: str,
        error: str
    ) -> bool:
        """
        Mark task as failed

        Args:
            task_id: Task ID
            error: Error message

        Returns:
            True if successful
        """
        task = self._active_tasks.pop(task_id, None)
        if not task:
            task = self._find_task_in_queue(task_id)

        if not task:
            return False

        task["status"] = TaskStatus.FAILED
        task["error"] = error
        task["failed_at"] = datetime.utcnow().isoformat() + "Z"

        return True

    def _find_task_in_queue(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Find task in queue"""
        for task in self._task_queue:
            if task.get("id") == task_id:
                return task
        return None

    def get_next_task(
        self,
        worker_type: str,
        capabilities: List[str]
    ) -> Optional[Dict[str, Any]]:
        """
        Get next task for a worker

        Args:
            worker_type: Type of worker
            capabilities: Worker capabilities

        Returns:
            Next task or None
        """
        if len(self._active_tasks) >= self._max_active_tasks:
            return None

        # Get highest priority task
        task = self.dequeue_task()
        if task:
            # Check if task is suitable for worker
            if self._is_task_suitable(task, worker_type, capabilities):
                task["worker_type"] = worker_type
                task["status"] = TaskStatus.RUNNING
                return task
            else:
                # Re-queue task
                self._task_queue.insert(0, task)

        # Try pheromone-driven task creation
        return self._create_pheromone_driven_task(worker_type, capabilities)

    def _is_task_suitable(
        self,
        task: Dict[str, Any],
        worker_type: str,
        capabilities: List[str]
    ) -> bool:
        """Check if task is suitable for worker"""
        required_caps = task.get("required_capabilities", [])
        return all(cap in capabilities for cap in required_caps)

    def _create_pheromone_driven_task(
        self,
        worker_type: str,
        capabilities: List[str]
    ) -> Optional[Dict[str, Any]]:
        """
        Create task based on pheromone data

        Args:
            worker_type: Worker type
            capabilities: Worker capabilities

        Returns:
            Task or None
        """
        recommendations = self.pheromone_system.get_priority_recommendation(limit=1)

        if not recommendations:
            return None

        top_rec = recommendations[0]

        # Check if worker has capabilities for this task
        scanner_to_capability = {
            "xss": ["web_exploitation"],
            "sqli": ["web_exploitation", "database_exploitation"],
            "lfi": ["web_exploitation"],
            "cors": ["web_exploitation"],
            "ssrf": ["web_exploitation"],
            "nmap": ["network_reconnaissance"],
            "subfinder": ["reconnaissance"],
            "nuclei": ["vulnerability_scanning"]
        }

        required_capabilities = scanner_to_capability.get(
            top_rec["scanner"],
            ["generic"]
        )

        if not all(cap in capabilities for cap in required_capabilities):
            return None

        # Create task
        task = {
            "id": f"pheromone_task_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "target_id": top_rec["target_id"],
            "scanner": top_rec["scanner"],
            "finding_type": top_rec["finding_type"],
            "url": top_rec.get("url"),
            "type": "scan",
            "required_capabilities": required_capabilities,
            "priority": top_rec["concentration"],
            "status": TaskStatus.RUNNING,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "source": "pheromone_driven"
        }

        self._active_tasks[task["id"]] = task
        return task

    def get_queue_statistics(self) -> Dict[str, Any]:
        """
        Get task queue statistics

        Returns:
            Statistics dictionary
        """
        return {
            "pending_tasks": len(self._task_queue),
            "active_tasks": len(self._active_tasks),
            "completed_tasks": len(self._completed_tasks),
            "max_active_tasks": self._max_active_tasks,
            "queue": [
                {
                    "id": task["id"],
                    "type": task.get("type", "generic"),
                    "priority": task.get("priority", 0.5),
                    "status": task["status"].value
                }
                for task in self._task_queue
            ],
            "active": [
                {
                    "id": task["id"],
                    "type": task.get("type", "generic"),
                    "worker": task.get("worker"),
                    "elapsed_seconds": (
                        datetime.utcnow() - datetime.fromisoformat(task.get("dequeued_at", datetime.utcnow().isoformat() + "Z").replace('Z', '+00:00'))
                    ).total_seconds()
                }
                for task in self._active_tasks.values()
            ]
        }

    def get_active_task_count(self) -> int:
        """Get number of active tasks"""
        return len(self._active_tasks)

    def can_accept_task(self) -> bool:
        """Check if system can accept more tasks"""
        return len(self._active_tasks) < self._max_active_tasks