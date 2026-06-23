"""
Tool Registry for MCP Server

Manages registration and discovery of security tools available via MCP.
"""
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from enum import Enum


class ToolCategory(str, Enum):
    """Categories of security tools"""
    NETWORK_RECONNAISSANCE = "network_reconnaissance"
    WEB_EXPLOITATION = "web_exploitation"
    BINARY_ANALYSIS = "binary_analysis"
    CLOUD_ASSESSMENT = "cloud_assessment"
    INFRASTRUCTURE = "infrastructure"


class ToolCapability(str, Enum):
    """Capabilities of security tools"""
    PORT_SCANNING = "port_scanning"
    SUBDOMAIN_ENUMERATION = "subdomain_enumeration"
    WEB_FUZZING = "web_fuzzing"
    SQL_INJECTION = "sql_injection"
    XSS_DETECTION = "xss_detection"
    VULNERABILITY_SCANNING = "vulnerability_scanning"
    BINARY_DECOMPILATION = "binary_decompilation"
    CLOUD_AUDIT = "cloud_audit"
    CREDENTIAL_DISCOVERY = "credential_discovery"


class ToolDefinition(BaseModel):
    """Definition of a security tool"""
    name: str = Field(..., description="Tool name")
    category: ToolCategory = Field(..., description="Tool category")
    description: str = Field(..., description="Tool description")
    version: str = Field(..., description="Tool version")
    capabilities: List[ToolCapability] = Field(..., description="Tool capabilities")
    executable: str = Field(..., description="Executable name")
    config_file: Optional[str] = Field(None, description="Configuration file path")
    timeout: int = Field(300, description="Default timeout in seconds")
    requires_admin: bool = Field(False, description="Whether root/admin privileges required")
    rate_limit: Optional[int] = Field(None, description="Rate limit requests per minute")


class ToolRegistry:
    """Registry of available security tools"""

    def __init__(self):
        """Initialize tool registry"""
        self._tools: Dict[str, ToolDefinition] = {}
        self._categories: Dict[ToolCategory, List[str]] = {
            ToolCategory.NETWORK_RECONNAISSANCE: [],
            ToolCategory.WEB_EXPLOITATION: [],
            ToolCategory.BINARY_ANALYSIS: [],
            ToolCategory.CLOUD_ASSESSMENT: [],
            ToolCategory.INFRASTRUCTURE: [],
        }
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        """Register default security tools"""
        self.register_tool(
            ToolDefinition(
                name="nmap",
                category=ToolCategory.NETWORK_RECONNAISSANCE,
                description="Network mapper for port scanning and service detection",
                version="10.0",
                capabilities=[ToolCapability.PORT_SCANNING, ToolCapability.INFRASTRUCTURE],
                executable="nmap",
                timeout=600,
                rate_limit=10
            )
        )

        self.register_tool(
            ToolDefinition(
                name="rustscan",
                category=ToolCategory.NETWORK_RECONNAISSANCE,
                description="Fast port scanner using Rust for high-speed scanning",
                version="3.0",
                capabilities=[ToolCapability.PORT_SCANNING],
                executable="rustscan",
                timeout=300,
                rate_limit=5
            )
        )

        self.register_tool(
            ToolDefinition(
                name="subfinder",
                category=ToolCategory.NETWORK_RECONNAISSANCE,
                description="Subdomain enumeration tool",
                version="2.2",
                capabilities=[ToolCapability.SUBDOMAIN_ENUMERATION],
                executable="subfinder",
                timeout=300,
                rate_limit=30
            )
        )

        self.register_tool(
            ToolDefinition(
                name="nuclei",
                category=ToolCategory.WEB_EXPLOITATION,
                description="Vulnerability scanner with custom templates",
                version="3.0",
                capabilities=[ToolCapability.VULNERABILITY_SCANNING, ToolCapability.WEB_FUZZING],
                executable="nuclei",
                timeout=1200,
                rate_limit=5
            )
        )

        self.register_tool(
            ToolDefinition(
                name="sqlmap",
                category=ToolCategory.WEB_EXPLOITATION,
                description="SQL injection detection and exploitation tool",
                version="1.8",
                capabilities=[ToolCapability.SQL_INJECTION],
                executable="sqlmap",
                timeout=1800,
                rate_limit=3
            )
        )

        self.register_tool(
            ToolDefinition(
                name="dalfox",
                category=ToolCategory.WEB_EXPLOITATION,
                description="XSS vulnerability scanner",
                version="2.0",
                capabilities=[ToolCapability.XSS_DETECTION],
                executable="dalfox",
                timeout=900,
                rate_limit=10
            )
        )

        self.register_tool(
            ToolDefinition(
                name="ghidra",
                category=ToolCategory.BINARY_ANALYSIS,
                description="Binary decompiler and reverse engineering tool",
                version="10.0",
                capabilities=[ToolCapability.BINARY_DECOMPILATION],
                executable="ghidraRun",
                timeout=3600,
                rate_limit=1
            )
        )

        self.register_tool(
            ToolDefinition(
                name="radare2",
                category=ToolCategory.BINARY_ANALYSIS,
                description="Reverse engineering framework",
                version="5.0",
                capabilities=[ToolCapability.BINARY_DECOMPILATION],
                executable="r2",
                timeout=3600,
                rate_limit=1
            )
        )

        self.register_tool(
            ToolDefinition(
                name="prowler",
                category=ToolCategory.CLOUD_ASSESSMENT,
                description="AWS security assessment tool",
                version="3.4",
                capabilities=[ToolCapability.CLOUD_AUDIT],
                executable="prowler",
                timeout=1800,
                rate_limit=2
            )
        )

        self.register_tool(
            ToolDefinition(
                name="trivy",
                category=ToolCategory.CLOUD_ASSESSMENT,
                description="Container and cloud vulnerability scanner",
                version="0.45",
                capabilities=[ToolCapability.VULNERABILITY_SCANNING],
                executable="trivy",
                timeout=900,
                rate_limit=5
            )
        )

    def register_tool(self, tool: ToolDefinition) -> None:
        """
        Register a security tool

        Args:
            tool: Tool definition
        """
        self._tools[tool.name] = tool
        self._categories[tool.category].append(tool.name)

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        """
        Get tool definition by name

        Args:
            name: Tool name

        Returns:
            Tool definition or None
        """
        return self._tools.get(name)

    def list_tools(self, category: Optional[ToolCategory] = None) -> List[ToolDefinition]:
        """
        List all tools or tools in a specific category

        Args:
            category: Optional category filter

        Returns:
            List of tool definitions
        """
        if category:
            return [self._tools[name] for name in self._categories[category]]
        return list(self._tools.values())

    def list_categories(self) -> List[ToolCategory]:
        """
        List all tool categories

        Returns:
            List of tool categories
        """
        return list(self._categories.keys())

    def get_tools_by_capability(self, capability: ToolCapability) -> List[ToolDefinition]:
        """
        Get tools that support a specific capability

        Args:
            capability: Tool capability

        Returns:
            List of tool definitions
        """
        return [
            tool for tool in self._tools.values()
            if capability in tool.capabilities
        ]

    def is_available(self, name: str) -> bool:
        """
        Check if a tool is available

        Args:
            name: Tool name

        Returns:
            True if tool is available
        """
        tool = self.get_tool(name)
        return tool is not None

    def get_execution_info(self, name: str) -> Dict[str, any]:
        """
        Get execution information for a tool

        Args:
            name: Tool name

        Returns:
            Dictionary with execution info
        """
        tool = self.get_tool(name)
        if not tool:
            return {"available": False}

        return {
            "available": True,
            "name": tool.name,
            "category": tool.category.value,
            "description": tool.description,
            "version": tool.version,
            "timeout": tool.timeout,
            "requires_admin": tool.requires_admin,
            "rate_limit": tool.rate_limit
        }

    def get_all_tools_info(self) -> Dict[str, Dict[str, any]]:
        """
        Get information for all available tools

        Returns:
            Dictionary mapping tool names to their info
        """
        return {
            name: self.get_execution_info(name)
            for name in self._tools.keys()
        }