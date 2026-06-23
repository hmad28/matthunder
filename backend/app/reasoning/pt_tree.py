"""
Pentesting Task Tree (PTT) Structure

Defines the task tree structure for AI-driven pentesting reasoning.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any
from enum import Enum
from datetime import datetime


class NodeType(str, Enum):
    """Types of nodes in the Pentesting Task Tree"""
    DISCOVERY = "discovery"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    RECONNAISSANCE = "reconnaissance"
    REPORTING = "reporting"


class NodeStatus(str, Enum):
    """Status of nodes in the PTT"""
    TO_DO = "to-do"
    RUNNING = "running"
    COMPLETED = "completed"
    BACKTRACKED = "backtracked"
    SKIPPED = "skipped"


@dataclass
class PTNode:
    """Node in the Pentesting Task Tree"""
    id: str
    type: NodeType
    title: str
    description: str
    scanners: Tuple[str, ...] = field(default_factory=tuple)
    dependencies: Tuple[str, ...] = field(default_factory=tuple)
    risk_level: str = "medium"  # low, medium, high, critical
    estimated_time: int = 300  # in seconds
    status: NodeStatus = NodeStatus.TO_DO
    parent_id: Optional[str] = None
    children: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def can_execute(self, existing_nodes: Dict[str, 'PTNode']) -> bool:
        """
        Check if this node can be executed

        Args:
            existing_nodes: All existing nodes

        Returns:
            True if all dependencies are completed
        """
        for dep_id in self.dependencies:
            dep_node = existing_nodes.get(dep_id)
            if not dep_node or dep_node.status != NodeStatus.COMPLETED:
                return False
        return True

    def is_critical(self) -> bool:
        """Check if this node is critical"""
        return self.risk_level in ["high", "critical"]

    def get_weight(self) -> float:
        """
        Get node weight based on risk and estimated time

        Returns:
            Weight score (0-1)
        """
        risk_weight = {"low": 0.3, "medium": 0.6, "high": 0.8, "critical": 1.0}[self.risk_level]
        time_weight = min(self.estimated_time / 3600, 1.0)  # Max 1 hour
        return (risk_weight + time_weight) / 2


@dataclass
class PTTree:
    """Pentesting Task Tree"""
    root_id: str
    scan_id: str
    target_id: str
    nodes: Dict[str, PTNode] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def get_node(self, node_id: str) -> Optional[PTNode]:
        """Get node by ID"""
        return self.nodes.get(node_id)

    def add_node(self, node: PTNode) -> None:
        """Add a node to the tree"""
        self.nodes[node.id] = node

        if node.parent_id:
            parent = self.nodes.get(node.parent_id)
            if parent:
                parent.children.append(node.id)

        self.updated_at = datetime.utcnow()

    def get_root(self) -> Optional[PTNode]:
        """Get root node"""
        return self.nodes.get(self.root_id)

    def get_children(self, node_id: str) -> List[PTNode]:
        """Get children of a node"""
        node = self.nodes.get(node_id)
        if not node:
            return []

        return [self.nodes[child_id] for child_id in node.children if child_id in self.nodes]

    def get_dependencies(self, node_id: str) -> List[PTNode]:
        """Get dependencies of a node"""
        node = self.nodes.get(node_id)
        if not node:
            return []

        return [self.nodes[dep_id] for dep_id in node.dependencies if dep_id in self.nodes]

    def get_completed_nodes(self) -> List[PTNode]:
        """Get all completed nodes"""
        return [node for node in self.nodes.values() if node.status == NodeStatus.COMPLETED]

    def get_active_nodes(self) -> List[PTNode]:
        """Get all active (running) nodes"""
        return [node for node in self.nodes.values() if node.status == NodeStatus.RUNNING]

    def get_pending_nodes(self) -> List[PTNode]:
        """Get all pending nodes"""
        return [node for node in self.nodes.values() if node.status == NodeStatus.TO_DO]

    def get_critical_path(self) -> List[PTNode]:
        """
        Get critical path (highest priority nodes)

        Returns:
            List of critical nodes sorted by priority
        """
        critical_nodes = [node for node in self.nodes.values() if node.is_critical()]
        return sorted(critical_nodes, key=lambda x: x.get_weight(), reverse=True)

    def get_progress(self) -> float:
        """
        Get overall progress percentage

        Returns:
            Progress (0-100)
        """
        if not self.nodes:
            return 0.0

        completed = sum(1 for node in self.nodes.values() if node.status == NodeStatus.COMPLETED)
        return (completed / len(self.nodes)) * 100

    def get_tree_structure(self) -> Dict[str, Any]:
        """
        Get tree structure for visualization

        Returns:
            Dictionary with tree structure
        """
        return {
            "root": self.root_id,
            "nodes": [
                {
                    "id": node.id,
                    "type": node.type.value,
                    "title": node.title,
                    "status": node.status.value,
                    "risk_level": node.risk_level,
                    "children": node.children,
                    "dependencies": node.dependencies,
                    "metadata": node.metadata
                }
                for node in self.nodes.values()
            ],
            "progress": round(self.get_progress(), 2),
            "total_nodes": len(self.nodes),
            "completed_nodes": len(self.get_completed_nodes()),
            "pending_nodes": len(self.get_pending_nodes())
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert tree to dictionary for serialization"""
        return {
            "root_id": self.root_id,
            "scan_id": self.scan_id,
            "target_id": self.target_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "nodes": [
                {
                    "id": node.id,
                    "type": node.type.value,
                    "title": node.title,
                    "description": node.description,
                    "scanners": list(node.scanners),
                    "dependencies": list(node.dependencies),
                    "risk_level": node.risk_level,
                    "estimated_time": node.estimated_time,
                    "status": node.status.value,
                    "parent_id": node.parent_id,
                    "children": node.children,
                    "metadata": node.metadata,
                    "created_at": node.created_at.isoformat(),
                    "started_at": node.started_at.isoformat() if node.started_at else None,
                    "completed_at": node.completed_at.isoformat() if node.completed_at else None
                }
                for node in self.nodes.values()
            ]
        }


class PTTreeManager:
    """Manages Pentesting Task Trees"""

    def __init__(self):
        """Initialize PT tree manager"""
        self.trees: Dict[str, PTTree] = {}

    def create_tree(
        self,
        root_id: str,
        scan_id: str,
        target_id: str,
        root_node: PTNode
    ) -> PTTree:
        """
        Create a new PT tree

        Args:
            root_id: Root node ID
            scan_id: Scan session ID
            target_id: Target domain or ID

        Returns:
            PTTree instance
        """
        tree = PTTree(
            root_id=root_id,
            scan_id=scan_id,
            target_id=target_id
        )

        tree.add_node(root_node)
        self.trees[scan_id] = tree

        return tree

    def get_tree(self, scan_id: str) -> Optional[PTTree]:
        """Get tree by scan ID"""
        return self.trees.get(scan_id)

    def update_node_status(
        self,
        scan_id: str,
        node_id: str,
        status: NodeStatus,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Update node status

        Args:
            scan_id: Scan session ID
            node_id: Node ID
            status: New status
            metadata: Optional metadata to update

        Returns:
            True if successful
        """
        tree = self.trees.get(scan_id)
        if not tree:
            return False

        node = tree.get_node(node_id)
        if not node:
            return False

        node.status = status

        if status == NodeStatus.RUNNING:
            node.started_at = datetime.utcnow()
        elif status == NodeStatus.COMPLETED:
            node.completed_at = datetime.utcnow()

        if metadata:
            node.metadata.update(metadata)

        tree.updated_at = datetime.utcnow()
        return True

    def get_tree_for_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get tree structure for a scan

        Args:
            scan_id: Scan session ID

        Returns:
            Tree structure dictionary or None
        """
        tree = self.trees.get(scan_id)
        if not tree:
            return None

        return tree.get_tree_structure()

    def delete_tree(self, scan_id: str) -> bool:
        """
        Delete a tree

        Args:
            scan_id: Scan session ID

        Returns:
            True if successful
        """
        if scan_id in self.trees:
            del self.trees[scan_id]
            return True
        return False

    def get_all_trees(self) -> List[PTTree]:
        """Get all trees"""
        return list(self.trees.values())

    def get_tree_stats(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get statistics for a tree

        Args:
            scan_id: Scan session ID

        Returns:
            Statistics dictionary or None
        """
        tree = self.trees.get(scan_id)
        if not tree:
            return None

        return {
            "scan_id": scan_id,
            "total_nodes": len(tree.nodes),
            "completed": len(tree.get_completed_nodes()),
            "running": len(tree.get_active_nodes()),
            "pending": len(tree.get_pending_nodes()),
            "progress": round(tree.get_progress(), 2),
            "critical_nodes": len(tree.get_critical_path())
        }