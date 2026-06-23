"""
MCP Server Implementation

FastAPI server for MCP (Model Context Protocol) tool execution.
Provides RESTful API for security tools integration.
"""
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from .tool_registry import ToolRegistry, ToolDefinition
from .tool_executor import ToolExecutor


class ToolExecutionRequest(BaseModel):
    """Request for tool execution"""
    tool_name: str = Field(..., description="Tool name")
    arguments: List[str] = Field(default_factory=list, description="Command-line arguments")
    timeout: Optional[int] = Field(None, description="Execution timeout in seconds")
    work_dir: Optional[str] = Field(None, description="Working directory")


class ToolExecutionResponse(BaseModel):
    """Response for tool execution"""
    success: bool
    returncode: int
    stdout: str
    stderr: str
    tool: str
    timestamp: str
    duration: Optional[float]
    result: Dict[str, Any]


class MCPServer:
    """MCP Server providing security tool integration"""

    def __init__(self):
        """Initialize MCP server"""
        self.router = APIRouter(prefix="/api/v1/mcp", tags=["mcp"])
        self.registry = ToolRegistry()
        self.executor = ToolExecutor(self.registry)

        # Register routes
        self._register_routes()

    def _register_routes(self) -> None:
        """Register API routes"""

        @self.router.get("/tools")
        async def list_tools(category: Optional[str] = None):
            """List all available tools or tools in a category"""
            try:
                if category:
                    cat_enum = ToolExecutionRequest.__annotations__['category']
                    category_enum = ToolCategory(category)
                    tools = self.registry.list_tools(category_enum)
                else:
                    tools = self.registry.list_tools()

                return {
                    "tools": [
                        {
                            "name": tool.name,
                            "category": tool.category.value,
                            "description": tool.description,
                            "version": tool.version,
                            "capabilities": [c.value for c in tool.capabilities],
                            "timeout": tool.timeout,
                            "requires_admin": tool.requires_admin
                        }
                        for tool in tools
                    ],
                    "count": len(tools)
                }
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/tools/{tool_name}")
        async def get_tool_info(tool_name: str):
            """Get detailed information about a specific tool"""
            try:
                info = self.registry.get_execution_info(tool_name)
                if not info["available"]:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Tool '{tool_name}' not found"
                    )
                return info
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/tools/execute", response_model=ToolExecutionResponse)
        async def execute_tool(request: ToolExecutionRequest):
            """Execute a security tool"""
            try:
                result = await self.executor.execute(
                    request.tool_name,
                    request.arguments,
                    request.timeout,
                    request.work_dir
                )

                return ToolExecutionResponse(**result)

            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except subprocess.TimeoutExpired as e:
                raise HTTPException(
                    status_code=408,
                    detail=f"Tool execution timed out after {e.timeout} seconds"
                )
            except FileNotFoundError as e:
                raise HTTPException(
                    status_code=404,
                    detail="Tool executable not found. Make sure it's installed and in PATH."
                )
            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=f"Tool execution failed: {str(e)}"
                )

        @self.router.post("/tools/batch-execute")
        async def batch_execute(requests: List[ToolExecutionRequest]):
            """Execute multiple tool tasks in parallel"""
            try:
                tasks = [
                    {
                        "tool_name": req.tool_name,
                        "arguments": req.arguments,
                        "timeout": req.timeout,
                        "work_dir": req.work_dir
                    }
                    for req in requests
                ]

                results = await self.executor.batch_execute(tasks)

                return {
                    "results": [
                        {
                            "success": isinstance(r, dict) and r.get("success"),
                            "tool": r.get("tool") if isinstance(r, dict) else None,
                            "error": str(r) if not isinstance(r, dict) else None,
                            "result": r if isinstance(r, dict) else None
                        }
                        for r in results
                    ],
                    "count": len(results)
                }

            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=f"Batch execution failed: {str(e)}"
                )

        @self.router.get("/tools/{tool_name}/help")
        async def get_tool_help(tool_name: str):
            """Get help text for a tool"""
            try:
                help_text = await self.executor.get_tool_help(tool_name)
                return {"tool": tool_name, "help": help_text}
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/tools/availability")
        async def check_tool_availability():
            """Check availability of all registered tools"""
            availability = self.executor.validate_tool_availability()

            available_count = sum(1 for v in availability.values() if v)
            unavailable_count = len(availability) - available_count

            return {
                "total": len(availability),
                "available": available_count,
                "unavailable": unavailable_count,
                "availability": availability
            }

        @self.router.get("/categories")
        async def list_categories():
            """List all tool categories"""
            return {
                "categories": [cat.value for cat in self.registry.list_categories()],
                "count": len(self.registry.list_categories())
            }

    def get_router(self) -> APIRouter:
        """
        Get the router instance

        Returns:
            FastAPI router
        """
        return self.router


# ToolCategory enum needs to be imported here
from .tool_registry import ToolCategory