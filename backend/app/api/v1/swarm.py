"""
Swarm Intelligence API routes
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Optional

from app.swarm import PheromoneSystem, CoordinationEngine, TaskDistributor, SwarmOptimizer

router = APIRouter(prefix="/swarm", tags=["swarm"])


class DepositPheromoneRequest(BaseModel):
    """Request for depositing pheromone"""
    target_id: str
    scanner_name: str
    finding_type: str
    success_rate: float = Field(default=0.5, ge=0, le=1)
    confidence: float = Field(default=0.5, ge=0, le=1)
    target_url: Optional[str] = None


class RegisterWorkerRequest(BaseModel):
    """Request for registering a worker"""
    worker_id: str
    worker_type: str
    capabilities: List[str]


class EnqueueTaskRequest(BaseModel):
    """Request for enqueuing a task"""
    target_id: str = Field(..., description="Target domain or ID")
    scanner: str = Field(..., description="Scanner name")
    finding_type: str = Field(default="generic", description="Finding type")
    required_capabilities: List[str] = Field(default_factory=list, description="Required capabilities")
    priority: float = Field(default=0.5, ge=0, le=1, description="Priority")


# Initialize swarm modules
pheromone_system = PheromoneSystem()
coordination_engine = CoordinationEngine(pheromone_system)
task_distributor = TaskDistributor(pheromone_system)
swarm_optimizer = SwarmOptimizer(pheromone_system)


@router.post("/pheromone/deposit")
async def deposit_pheromone(request: DepositPheromoneRequest):
    """Deposit pheromone for a finding"""
    entry = pheromone_system.deposit_pheromone(
        target_id=request.target_id,
        scanner_name=request.scanner_name,
        finding_type=request.finding_type,
        success_rate=request.success_rate,
        confidence=request.confidence,
        target_url=request.target_url
    )

    return {
        "key": f"{request.target_id}:{request.scanner_name}:{request.finding_type}",
        "concentration": round(entry.get_current_concentration(), 3),
        "priority": entry.get_priority().value,
        "half_life_hours": round(entry.get_half_life(), 2)
    }


@router.get("/pheromone/recommendations/{target_id}")
async def get_recommendations(target_id: str, limit: int = 10):
    """Get pheromone recommendations for a target"""
    recommendations = pheromone_system.get_priority_recommendation(
        target_id=target_id,
        limit=limit
    )

    return {
        "target_id": target_id,
        "recommendations": recommendations,
        "count": len(recommendations)
    }


@router.get("/pheromone/statistics/{target_id}")
async def get_pheromone_statistics(target_id: str):
    """Get pheromone statistics for a target"""
    stats = pheromone_system.get_target_statistics(target_id)
    return stats


@router.get("/pheromone/heatmap")
async def get_heatmap(target_id: Optional[str] = None):
    """Get pheromone heatmap"""
    heatmap = pheromone_system.get_pheromone_heatmap(target_id)
    return heatmap


@router.post("/worker/register")
async def register_worker(request: RegisterWorkerRequest):
    """Register a worker agent"""
    coordination_engine.register_worker(
        worker_id=request.worker_id,
        worker_type=request.worker_type,
        capabilities=request.capabilities
    )

    return {
        "worker_id": request.worker_id,
        "status": "registered"
    }


@router.post("/worker/{worker_id}/heartbeat")
async def worker_heartbeat(worker_id: str):
    """Update worker heartbeat"""
    success = coordination_engine.heart_beat(worker_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Worker {worker_id} not found"
        )

    return {"worker_id": worker_id, "status": "healthy"}


@router.get("/workers")
async def list_workers():
    """List all workers"""
    stats = coordination_engine.get_worker_statistics()
    return stats


@router.get("/workers/health")
async def get_worker_health():
    """Get worker health status"""
    health = coordination_engine.get_worker_health()
    return health


@router.get("/tasks/next")
async def get_next_task(worker_type: str, capabilities: str):
    """Get next task for a worker"""
    cap_list = capabilities.split(",") if capabilities else []
    task = task_distributor.get_next_task(worker_type, cap_list)

    return task or {"message": "No tasks available"}


@router.post("/tasks/enqueue")
async def enqueue_task(request: EnqueueTaskRequest):
    """Enqueue a task"""
    task = {
        "target_id": request.target_id,
        "scanner": request.scanner,
        "finding_type": request.finding_type,
        "required_capabilities": request.required_capabilities,
        "priority": request.priority,
        "type": "scan"
    }

    task_id = task_distributor.enqueue_task(task)

    return {
        "task_id": task_id,
        "status": "enqueued"
    }


@router.get("/tasks/statistics")
async def get_task_statistics():
    """Get task distribution statistics"""
    stats = task_distributor.get_queue_statistics()
    return stats


@router.get("/optimize/recommendations")
async def get_optimization_recommendations():
    """Get swarm optimization recommendations"""
    recommendations = swarm_optimizer.get_optimization_recommendations()
    return recommendations


@router.get("/metrics")
async def get_swarm_metrics():
    """Get comprehensive swarm metrics"""
    metrics = swarm_optimizer.get_swarm_metrics()
    metrics["statistics"] = pheromone_system.get_overall_statistics()
    return metrics


@router.post("/decay")
async def decay_pheromones():
    """Trigger pheromone decay"""
    count = pheromone_system.decay_all()
    return {"decayed_entries": count, "active_entries": count}


@router.post("/clear/{target_id}")
async def clear_pheromones(target_id: str):
    """Clear all pheromones for a target"""
    count = pheromone_system.clear_target(target_id)
    return {
        "target_id": target_id,
        "cleared_entries": count
    }


@router.get("/swarm-matrix")
async def get_swarm_matrix():
    """Get full swarm matrix for dashboard"""
    matrix = pheromone_system.get_swarm_matrix()
    return matrix


@router.get("/distribute")
async def distribute_workload(tasks_json: str):
    """Distribute tasks among workers"""
    import json
    try:
        tasks = json.loads(tasks_json)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid tasks JSON"
        )

    results = coordination_engine.distribute_workload(tasks)
    return {"assigned_tasks": results, "total": len(results)}


@router.post("/performance/record")
async def record_performance(request: dict):
    """Record performance metrics"""
    swarm_optimizer.record_performance(
        success_rate=request.get("success_rate", 0.5),
        completion_time_seconds=request.get("completion_time_seconds", 300),
        findings_count=request.get("findings_count", 0),
        workers_used=request.get("workers_used", 1)
    )

    return {
        "message": "Performance recorded",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }


from datetime import datetime