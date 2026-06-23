"""
Tool Executor for MCP Server

Executes security tools with safety guards and validation.
"""
import subprocess
import json
import shlex
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime
import asyncio

from .tool_registry import ToolRegistry, ToolDefinition


class ToolExecutor:
    """Executes security tools with safety guards"""

    def __init__(self, registry: ToolRegistry):
        """
        Initialize tool executor

        Args:
            registry: Tool registry instance
        """
        self.registry = registry

    async def execute(
        self,
        tool_name: str,
        arguments: List[str],
        timeout: Optional[int] = None,
        work_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute a security tool

        Args:
            tool_name: Tool name
            arguments: List of command-line arguments
            timeout: Execution timeout in seconds (defaults to tool's default)
            work_dir: Working directory for execution

        Returns:
            Dictionary with execution result

        Raises:
            ValueError: If tool is not available or arguments are invalid
            subprocess.TimeoutExpired: If execution times out
        """
        # Validate tool availability
        tool = self.registry.get_tool(tool_name)
        if not tool:
            raise ValueError(f"Tool '{tool_name}' is not registered")

        # Use tool's default timeout if not specified
        if timeout is None:
            timeout = tool.timeout

        # Validate arguments
        self._validate_arguments(tool_name, arguments)

        # Build command
        command = [tool.executable] + arguments

        # Execute tool
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutExpired:
                process.kill()
                stdout, stderr = await process.communicate()
                raise subprocess.TimeoutExpired(
                    ' '.join(command),
                    timeout,
                    output=stdout,
                    stderr=stderr
                )

            # Parse output
            result = self._parse_output(tool_name, stdout, stderr)

            return {
                "success": process.returncode == 0,
                "returncode": process.returncode,
                "stdout": stdout.decode('utf-8', errors='replace'),
                "stderr": stderr.decode('utf-8', errors='replace'),
                "tool": tool_name,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "duration": process.returncode if process.returncode else timeout,
                "result": result
            }

        except FileNotFoundError:
            raise ValueError(
                f"Tool '{tool_name}' executable not found. "
                f"Make sure it's installed and in PATH."
            )
        except Exception as e:
            raise ValueError(f"Tool execution failed: {str(e)}")

    def _validate_arguments(self, tool_name: str, arguments: List[str]) -> None:
        """
        Validate tool arguments for safety

        Args:
            tool_name: Tool name
            arguments: List of arguments to validate

        Raises:
            ValueError: If arguments are unsafe
        """
        tool = self.registry.get_tool(tool_name)
        if not tool:
            return

        # Check for dangerous arguments
        dangerous_patterns = [
            '--dangerous', '--exploit', '--force', '--rm', '--delete',
            '--purge', '--wipe', '--format', '--overwrite'
        ]

        args_str = ' '.join(arguments).lower()
        for pattern in dangerous_patterns:
            if pattern in args_str:
                raise ValueError(
                    f"Tool '{tool_name}' contains dangerous argument: {pattern}"
                )

        # Check for unsafe file paths
        for arg in arguments:
            if arg.startswith('/') or arg.startswith('~'):
                # Allow certain paths, reject others
                if not any(allowed in arg.lower() for allowed in ['tmp', 'temp', 'logs', 'output']):
                    raise ValueError(f"Unsafe file path in argument: {arg}")

    def _parse_output(self, tool_name: str, stdout: bytes, stderr: bytes) -> Dict[str, Any]:
        """
        Parse tool output for structured data

        Args:
            tool_name: Tool name
            stdout: Standard output
            stderr: Standard error

        Returns:
            Dictionary with parsed output
        """
        output_str = stdout.decode('utf-8', errors='replace')

        # Try to parse as JSON
        try:
            if output_str.strip().startswith('{'):
                return json.loads(output_str)
            elif output_str.strip().startswith('['):
                return json.loads(output_str)
        except json.JSONDecodeError:
            pass

        # Parse as text output
        return {
            "raw": output_str,
            "lines": output_str.split('\n'),
            "word_count": len(output_str.split()),
            "byte_count": len(output_str.encode('utf-8'))
        }

    def get_available_tools(self) -> List[Dict[str, Any]]:
        """
        Get list of available tools with basic info

        Returns:
            List of tool information dictionaries
        """
        return [
            {
                "name": tool.name,
                "category": tool.category.value,
                "description": tool.description,
                "version": tool.version,
                "capabilities": [c.value for c in tool.capabilities],
                "timeout": tool.timeout
            }
            for tool in self.registry.list_tools()
        ]

    async def batch_execute(
        self,
        tool_tasks: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Execute multiple tool tasks in parallel

        Args:
            tool_tasks: List of tasks with tool_name and arguments

        Returns:
            List of execution results
        """
        tasks = []
        for task in tool_tasks:
            tool_name = task.get("tool_name")
            arguments = task.get("arguments", [])
            timeout = task.get("timeout")

            tasks.append(self.execute(tool_name, arguments, timeout))

        return await asyncio.gather(*tasks, return_exceptions=True)

    async def get_tool_help(self, tool_name: str) -> str:
        """
        Get help text for a tool

        Args:
            tool_name: Tool name

        Returns:
            Help text
        """
        tool = self.registry.get_tool(tool_name)
        if not tool:
            return f"Tool '{tool_name}' not found"

        # Try to get tool help
        try:
            process = await asyncio.create_subprocess_exec(
                tool.executable,
                '--help',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)

            if process.returncode == 0:
                return stdout.decode('utf-8', errors='replace')
            else:
                return stderr.decode('utf-8', errors='replace')

        except Exception:
            return f"Could not retrieve help for {tool_name}"

    def validate_tool_availability(self) -> Dict[str, bool]:
        """
        Validate that all registered tools are available

        Returns:
            Dictionary mapping tool names to availability status
        """
        availability = {}
        for tool in self.registry.list_tools():
            try:
                result = self._check_tool_availability(tool.executable)
                availability[tool.name] = result["available"]
            except Exception:
                availability[tool.name] = False

        return availability

    def _check_tool_availability(self, executable: str) -> Dict[str, Any]:
        """
        Check if a tool executable is available

        Args:
            executable: Executable name or path

        Returns:
            Dictionary with availability info
        """
        try:
            result = subprocess.run(
                [executable, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return {
                "available": True,
                "version": result.stdout.strip(),
                "returncode": result.returncode
            }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return {
                "available": False,
                "version": None,
                "returncode": None
            }