"""
Memory Context API routes for frontend
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional

from app.memory import MemoryPersistence, ContextManager, AsyncContextUpdater

# Initialize instances
memory_persistence = MemoryPersistence(context_file="matthunder_context.md")
context_manager = ContextManager(memory_persistence)
async_updater = AsyncContextUpdater(memory_persistence)

router = APIRouter(prefix="/memory", tags=["memory"])


@router.get("/entries")
async def get_memory_entries(
    target_id: Optional[str] = None,
    context_type: Optional[str] = None,
    limit: int = 100
):
    """Get memory context entries"""
    if target_id:
        entries = memory_persistence.get_target_context(target_id)
    elif context_type:
        entries = memory_persistence.get_context_by_type(context_type)
    else:
        entries = memory_persistence.get_recent_context(limit)

    return {
        "entries": entries,
        "count": len(entries)
    }


@router.get("/stats")
async def get_memory_stats():
    """Get memory statistics"""
    stats = memory_persistence.get_stats()
    return stats


@router.get("/insights/{target_id}")
async def get_target_insights(target_id: str):
    """Get insights for a target"""
    insights = context_manager.get_target_insights(target_id)
    return insights


@router.delete("/clear/{target_id}")
async def clear_target_context(target_id: str):
    """Clear context for a target"""
    memory_persistence.clear_target_context(target_id)
    return {"message": "Context cleared", "target_id": target_id}
