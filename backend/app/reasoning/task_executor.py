"""
Task Executor for Pentesting Task Tree

Executes tasks in the Pentesting Task Tree with orchestration.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum

from .pt_tree import PTNode, NodeStatus, PTTreeManager, PTTree
from .task_generator import TaskGenerator


class TaskExecutionResult(str, Enum):
    """Task execution result"""
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"
    BACKTRACKED = "backtracked"


class TaskExecutor:
    """Executes tasks in the Pentesting Task Tree"""

    def __init__(
        self,
        pt_tree_manager: PTTreeManager,
        task_generator: TaskGenerator,
        memory_updater: Any  # AsyncContextUpdater
    ):
        """
        Initialize task executor

        Args:
            pt_tree_manager: PT tree manager
            task_generator: Task generator
            memory_updater: Memory updater for context persistence
        """
        self.pt_tree_manager = pt_tree_manager
        self.task_generator = task_generator
        self.memory_updater = memory_updater

    async def execute_next_task(
        self,
        scan_id: str
    ) -> Dict[str, Any]:
        """
        Execute the next task in the tree

        Args:
            scan_id: Scan session ID

        Returns:
            Execution result
        """
        # Get next task
        next_task = self.task_generator.get_next_task(scan_id)
        if not next_task:
            return {
                "status": TaskExecutionResult.SUCCESS.value,
                "message": "All tasks completed"
            }

        # Get tree
        tree = self.pt_tree_manager.get_tree(scan_id)
        if not tree:
            return {
                "status": TaskExecutionResult.FAILED.value,
                "message": "Tree not found"
            }

        # Get node
        node = tree.get_node(next_task["node_id"])
        if not node:
            return {
                "status": TaskExecutionResult.FAILED.value,
                "message": "Node not found"
            }

        # Execute node
        result = await self._execute_node(node, tree)

        # Update node status
        if result["status"] == TaskExecutionResult.SUCCESS.value:
            await self.pt_tree_manager.update_node_status(
                scan_id,
                node.id,
                NodeStatus.COMPLETED,
                {"result": result["data"]}
            )
        elif result["status"] == TaskExecutionResult.BACKTRACKED.value:
            await self.pt_tree_manager.update_node_status(
                scan_id,
                node.id,
                NodeStatus.BACKTRACKED
            )
        elif result["status"] == TaskExecutionResult.SKIPPED.value:
            await self.pt_tree_manager.update_node_status(
                scan_id,
                node.id,
                NodeStatus.SKIPPED
            )

        # Update memory
        await self.memory_updater.update_session_state(
            target_id=tree.target_id,
            scan_id=scan_id,
            status="running",
            current_phase=node.type.value,
            progress=tree.get_progress(),
            findings_count=len(tree.get_completed_nodes())
        )

        return result

    async def _execute_node(
        self,
        node: PTNode,
        tree: PTTree
    ) -> Dict[str, Any]:
        """
        Execute a single node

        Args:
            node: Node to execute
            tree: Parent tree

        Returns:
            Execution result
        """
        # Update node status to running
        await self.pt_tree_manager.update_node_status(
            tree.scan_id,
            node.id,
            NodeStatus.RUNNING
        )

        # Check if any scanners are available
        available_scanners = [sc for sc in node.scanners if self._is_scanner_available(sc)]

        if not available_scanners:
            return {
                "status": TaskExecutionResult.FAILED.value,
                "message": f"No available scanners for node: {node.scanners}",
                "data": {}
            }

        # Execute scanners
        results = []
        for scanner in available_scanners:
            scanner_result = await self._execute_scanner(
                scanner,
                node,
                tree.target_id,
                tree.scan_id
            )
            results.append(scanner_result)

        # Check if all scanners succeeded
        if all(r["success"] for r in results):
            findings_count = sum(r.get("findings_count", 0) for r in results)
            return {
                "status": TaskExecutionResult.SUCCESS.value,
                "message": f"Node executed successfully with {findings_count} findings",
                "data": {
                    "scanners": [r["scanner"] for r in results],
                    "findings_count": findings_count,
                    "findings": [r.get("findings", []) for r in results]
                }
            }
        else:
            failed_scanners = [r["scanner"] for r in results if not r["success"]]
            return {
                "status": TaskExecutionResult.FAILED.value,
                "message": f"Scanners failed: {', '.join(failed_scanners)}",
                "data": {
                    "scanners": [r["scanner"] for r in results],
                    "failed_scanners": failed_scanners
                }
            }

    async def _execute_scanner(
        self,
        scanner: str,
        node: PTNode,
        target_id: str,
        scan_id: str
    ) -> Dict[str, Any]:
        """
        Execute a scanner for a node

        Args:
            scanner: Scanner name
            node: Parent node
            target_id: Target domain or ID
            scan_id: Scan session ID

        Returns:
            Scanner result
        """
        # This would integrate with actual scanner execution
        # For now, return mock results

        return {
            "scanner": scanner,
            "success": True,
            "findings_count": 0,
            "findings": [],
            "output": f"Scanner {scanner} executed on {target_id}"
        }

    def _is_scanner_available(self, scanner: str) -> bool:
        """
        Check if scanner is available

        Args:
            scanner: Scanner name

        Returns:
            True if available
        """
        # This would check actual scanner availability
        # For now, assume all scanners are available
        return True

    async def execute_tree(
        self,
        tree: PTTree
    ) -> Dict[str, Any]:
        """
        Execute entire tree

        Args:
            tree: PT tree to execute

        Returns:
            Execution results
        """
        results = []
        total_nodes = len(tree.nodes)

        for node_id in tree.nodes:
            node = tree.get_node(node_id)
            if not node or node.status != NodeStatus.TO_DO:
                continue

            result = await self._execute_node(node, tree)
            results.append({
                "node_id": node.id,
                "title": node.title,
                "status": result["status"],
                "message": result["message"],
                "data": result["data"]
            })

            # Check if we should stop due to backtracking
            if result["status"] == TaskExecutionResult.BACKTRACKED.value:
                break

        # Update final status
        await self.memory_updater.update_session_state(
            target_id=tree.target_id,
            scan_id=tree.scan_id,
            status="completed",
            current_phase="reporting",
            progress=tree.get_progress(),
            findings_count=len(tree.get_completed_nodes())
        )

        return {
            "total_nodes": total_nodes,
            "completed_nodes": len(tree.get_completed_nodes()),
            "results": results,
            "success": all(r["status"] == TaskExecutionResult.SUCCESS.value for r in results)
        }

    async def backtrack_from_node(
        self,
        scan_id: str,
        node_id: str
    ) -> Dict[str, Any]:
        """
        Backtrack from a node

        Args:
            scan_id: Scan session ID
            node_id: Node ID to backtrack from

        Returns:
            Backtrack result
        """
        tree = self.pt_tree_manager.get_tree(scan_id)
        if not tree:
            return {
                "status": "failed",
                "message": "Tree not found"
            }

        node = tree.get_node(node_id)
        if not node:
            return {
                "status": "failed",
                "message": "Node not found"
            }

        # Get all nodes that depend on this node
        nodes_to_backtrack = self._get_descendants(tree, node_id)

        # Backtrack all dependent nodes
        for dep_node_id in nodes_to_backtrack:
            dep_node = tree.get_node(dep_node_id)
            if dep_node:
                await self.pt_tree_manager.update_node_status(
                    scan_id,
                    dep_node_id,
                    NodeStatus.BACKTRACKED,
                    {"reason": f"Backtracked from {node.title}"}
                )

        return {
            "status": "success",
            "backtracked_nodes": len(nodes_to_backtrack),
            "node_id": node_id,
            "node_title": node.title
        }

    def _get_descendants(self, tree: PTTree, node_id: str) -> List[str]:
        """
        Get all descendants of a node

        Args:
            tree: PT tree
            node_id: Node ID

        Returns:
            List of descendant node IDs
        """
        descendants = []
        nodes_to_check = list(tree.get_node(node_id).children) if tree.get_node(node_id) else []

        while nodes_to_check:
            current_id = nodes_to_check.pop(0)
            descendants.append(current_id)
            children = tree.get_node(current_id).children if tree.get_node(current_id) else []
            nodes_to_check.extend(children)

        return descendants

    async def get_tree_status(
        self,
        scan_id: str
    ) -> Dict[str, Any]:
        """
        Get current tree status

        Args:
            scan_id: Scan session ID

        Returns:
            Status information
        """
        tree = self.pt_tree_manager.get_tree(scan_id)
        if not tree:
            return {
                "status": "not_found",
                "message": "Tree not found"
            }

        return {
            "scan_id": scan_id,
            "progress": round(tree.get_progress(), 2),
            "total_nodes": len(tree.nodes),
            "completed_nodes": len(tree.get_completed_nodes()),
            "running_nodes": len(tree.get_active_nodes()),
            "pending_nodes": len(tree.get_pending_nodes()),
            "critical_path": [
                node.id for node in tree.get_critical_path()
            ],
            "tree_structure": tree.get_tree_structure()
        }

    async def stop_execution(
        self,
        scan_id: str
    ) -> bool:
        """
        Stop execution of a tree

        Args:
            scan_id: Scan session ID

        Returns:
            True if successful
        """
        tree = self.pt_tree_manager.get_tree(scan_id)
        if not tree:
            return False

        # Stop all running nodes
        for node in tree.get_active_nodes():
            await self.pt_tree_manager.update_node_status(
                scan_id,
                node.id,
                NodeStatus.BACKTRACKED,
                {"reason": "Execution stopped by user"}
            )

        return True

    def generate_tree_visualization(self, scan_id: str) -> str:
        """
        Generate tree visualization (ASCII/Markdown)

        Args:
            scan_id: Scan session ID

        Returns:
            Visualization string
        """
        tree = self.pt_tree_manager.get_tree(scan_id)
        if not tree:
            return "Tree not found"

        # Generate simple tree visualization
        lines = []
        lines.append(f"# Pentesting Task Tree - {scan_id}")
        lines.append(f"\nProgress: {tree.get_progress()}%")
        lines.append(f"\nTotal Nodes: {len(tree.nodes)}")
        lines.append(f"\nCompleted: {len(tree.get_completed_nodes())}")
        lines.append(f"\nPending: {len(tree.get_pending_nodes())}")
        lines.append(f"\n## Tree Structure\n")

        for node_id in tree.nodes:
            node = tree.get_node(node_id)
            status_symbol = {
                "to-do": "○",
                "running": "◐",
                "completed": "●",
                "backtracked": "⏮",
                "skipped": "○"
            }.get(node.status.value, "○")

            indent = "  " * node_id.count("_")
            lines.append(f"{indent}{status_symbol} {node.title} ({node.type.value}) - {node.status.value}")

        return "\n".join(lines)