"""
Swarm Intelligence Module for AI Offensive AI

Implements pheromone-based coordination for decentralized agent orchestration.
"""
from .pheromone_system import PheromoneSystem, PheromoneMatrix
from .coordination_engine import CoordinationEngine
from .task_distribution import TaskDistributor
from .swarm_optimizer import SwarmOptimizer

__all__ = ['PheromoneSystem', 'PheromoneMatrix', 'CoordinationEngine', 'TaskDistributor', 'SwarmOptimizer']