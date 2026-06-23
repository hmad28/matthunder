"""
matthunder backend package
"""
from .database import Base, get_db, init_db, close_db
from .main import app

# Import memory modules
from .memory import MemoryPersistence, ContextManager, AsyncContextUpdater

# Initialize singleton instances
memory_persistence = MemoryPersistence(context_file="matthunder_context.md")
context_manager = ContextManager(memory_persistence)
async_updater = AsyncContextUpdater(memory_persistence)

__all__ = [
    'app', 'Base', 'get_db', 'init_db', 'close_db',
    'memory_persistence', 'context_manager', 'async_updater'
]
