"""
Reasoning API routes - Pentesting Task Tree
"""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field

from app.schemas import FindingResponse
from app.models import Finding
from app.database import get_db
from app.reasoning import PTTreeManager, TaskGenerator, TaskExecutor
from app.memory import AsyncContextUpdater
from app.memory import MemoryPersistence

_memory_persistence = MemoryPersistence(context_file="matthunder_context.md")
async_updater = AsyncContextUpdater(_memory_persistence)

router = APIRouter(prefix="/reasoning", tags=["reasoning"])


class PTTreeRequest(BaseModel):
    """Request for generating PT tree"""
    target_id: str = Field(..., description="Target domain or ID")
    scan_id: str = Field(..., description="Scan session ID")
    finding_type: str = Field(..., description="Type of finding")
    reconnaissance_data: dict = Field(default_factory=dict, description="Reconnaissance data")


class TaskExecutionRequest(BaseModel):
    """Request for task execution"""
    scan_id: str = Field(..., description="Scan session ID")


# Initialize managers
pt_tree_manager = PTTreeManager()
task_generator = TaskGenerator(pt_tree_manager)
task_executor = TaskExecutor(pt_tree_manager, task_generator, async_updater)


@router.get("/ptt/{scan_id}")
async def get_pt_tree(scan_id: str):
    """Get Pentesting Task Tree for a scan"""
    tree_data = pt_tree_manager.get_tree_for_scan(scan_id)
    if not tree_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="PT Tree not found"
        )
    return tree_data


@router.post("/ptt/generate")
async def generate_pt_tree(request: PTTreeRequest):
    """Generate Pentesting Task Tree"""
    # Create appropriate tree based on finding type
    if request.finding_type == "reconnaissance":
        tree = task_generator.generate_reconnaissance_tree(
            request.target_id,
            request.scan_id,
            request.reconnaissance_data
        )
    elif request.finding_type == "web_exploitation":
        tree = task_generator.generate_web_exploitation_tree(
            request.target_id,
            request.scan_id,
            request.reconnaissance_data
        )
    elif request.finding_type == "database_exploitation":
        tree = task_generator.generate_database_exploitation_tree(
            request.target_id,
            request.scan_id,
            request.reconnaissance_data
        )
    else:
        tree = task_generator.generate_finding_specific_tree(
            request.target_id,
            request.scan_id,
            request.finding_type,
            request.reconnaissance_data
        )

    return {
        "scan_id": request.scan_id,
        "tree": tree.to_dict(),
        "message": "PT Tree generated successfully"
    }


@router.post("/ptt/execute")
async def execute_next_task(request: TaskExecutionRequest):
    """Execute the next task in PT Tree"""
    result = await task_executor.execute_next_task(request.scan_id)
    return result


@router.get("/ptt/status/{scan_id}")
async def get_pt_tree_status(scan_id: str):
    """Get current PT Tree status"""
    status = await task_executor.get_tree_status(scan_id)
    return status


@router.post("/ptt/backtrack")
async def backtrack_from_node(scan_id: str, node_id: str):
    """Backtrack from a node in PT Tree"""
    result = await task_executor.backtrack_from_node(scan_id, node_id)
    if result["status"] == "failed":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result["message"]
        )
    return result


@router.post("/ptt/stop")
async def stop_execution(scan_id: str):
    """Stop execution of PT Tree"""
    success = await task_executor.stop_execution(scan_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tree not found"
        )
    return {"message": "Execution stopped", "scan_id": scan_id}


@router.get("/ptt/visualize/{scan_id}")
async def visualize_pt_tree(scan_id: str):
    """Get tree visualization"""
    visualization = task_executor.generate_tree_visualization(scan_id)
    return {
        "scan_id": scan_id,
        "visualization": visualization
    }


@router.get("/tasks/next/{scan_id}")
async def get_next_task(scan_id: str):
    """Get next task to execute"""
    next_task = task_generator.get_next_task(scan_id)
    if not next_task:
        return {"message": "No more tasks"}
    return next_task