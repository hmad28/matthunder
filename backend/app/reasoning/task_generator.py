"""
Task Generator for Pentesting Task Tree

Generates PTT nodes based on reconnaissance data and finding types.
"""
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum

from .pt_tree import PTNode, PTTree, NodeType, NodeStatus, PTTreeManager


class TaskGenerator:
    """Generates tasks for Pentesting Task Tree"""

    def __init__(self, pt_tree_manager: PTTreeManager):
        """
        Initialize task generator

        Args:
            pt_tree_manager: PT tree manager
        """
        self.pt_tree_manager = pt_tree_manager

    def generate_reconnaissance_tree(
        self,
        target_id: str,
        scan_id: str,
        reconnaissance_data: Dict[str, Any]
    ) -> PTTree:
        """
        Generate reconnaissance task tree

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            reconnaissance_data: Reconnaissance data

        Returns:
            PTTree instance
        """
        # Create root node
        root_node = PTNode(
            id=f"root_{scan_id}",
            type=NodeType.RECONNAISSANCE,
            title="Reconnaissance Phase",
            description="Gather initial information about target",
            risk_level="low",
            estimated_time=1800,  # 30 minutes
            status=NodeStatus.COMPLETED
        )

        tree = self.pt_tree_manager.create_tree(
            root_id=root_node.id,
            scan_id=scan_id,
            target_id=target_id,
            root_node=root_node
        )

        # Add subdomain enumeration task
        subdomain_node = PTNode(
            id=f"subdomain_{scan_id}",
            type=NodeType.DISCOVERY,
            title="Subdomain Enumeration",
            description="Discover all subdomains of target",
            scanners=("subfinder", "amass"),
            dependencies=(root_node.id,),
            risk_level="low",
            estimated_time=600,
            status=NodeStatus.TO_DO
        )
        tree.add_node(subdomain_node)

        # Add live host detection task
        live_host_node = PTNode(
            id=f"live_host_{scan_id}",
            type=NodeType.RECONNAISSANCE,
            title="Live Host Detection",
            description="Identify live hosts and services",
            scanners=("httpx", "rustscan"),
            dependencies=(root_node.id,),
            risk_level="low",
            estimated_time=900,
            status=NodeStatus.TO_DO
        )
        tree.add_node(live_host_node)

        # Add port scanning task
        port_scan_node = PTNode(
            id=f"port_scan_{scan_id}",
            type=NodeType.DISCOVERY,
            title="Port Scanning",
            description="Scan for open ports and services",
            scanners=("nmap",),
            dependencies=(live_host_node.id,),
            risk_level="medium",
            estimated_time=1200,
            status=NodeStatus.TO_DO
        )
        tree.add_node(port_scan_node)

        # Add technology detection task
        tech_fingerprint_node = PTNode(
            id=f"tech_fingerprint_{scan_id}",
            type=NodeType.RECONNAISSANCE,
            title="Technology Fingerprinting",
            description="Identify technologies and frameworks",
            scanners=("waf", "techfingerprint"),
            dependencies=(live_host_node.id,),
            risk_level="medium",
            estimated_time=600,
            status=NodeStatus.TO_DO
        )
        tree.add_node(tech_fingerprint_node)

        return tree

    def generate_web_exploitation_tree(
        self,
        target_id: str,
        scan_id: str,
        web_data: Dict[str, Any]
    ) -> PTTree:
        """
        Generate web exploitation task tree

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            web_data: Web reconnaissance data

        Returns:
            PTTree instance
        """
        # Create root node
        root_node = PTNode(
            id=f"web_exploit_root_{scan_id}",
            type=NodeType.EXPLOITATION,
            title="Web Exploitation Phase",
            description="Exploit web vulnerabilities",
            risk_level="high",
            estimated_time=3600,
            status=NodeStatus.COMPLETED
        )

        tree = self.pt_tree_manager.create_tree(
            root_id=root_node.id,
            scan_id=scan_id,
            target_id=target_id,
            root_node=root_node
        )

        # Add endpoint discovery task
        endpoint_discovery_node = PTNode(
            id=f"endpoint_discovery_{scan_id}",
            type=NodeType.DISCOVERY,
            title="Endpoint Discovery",
            description="Discover web endpoints and API routes",
            scanners=("httpx", "gau", "katana"),
            dependencies=(root_node.id,),
            risk_level="low",
            estimated_time=900,
            status=NodeStatus.TO_DO
        )
        tree.add_node(endpoint_discovery_node)

        # Add XSS scanning task
        xss_scan_node = PTNode(
            id=f"xss_scan_{scan_id}",
            type=NodeType.EXPLOITATION,
            title="XSS Scanning",
            description="Detect Cross-Site Scripting vulnerabilities",
            scanners=("dalfox",),
            dependencies=(endpoint_discovery_node.id,),
            risk_level="high",
            estimated_time=1800,
            status=NodeStatus.TO_DO
        )
        tree.add_node(xss_scan_node)

        # Add SQL injection task
        sqli_scan_node = PTNode(
            id=f"sqli_scan_{scan_id}",
            type=NodeType.EXPLOITATION,
            title="SQL Injection Detection",
            description="Detect SQL injection vulnerabilities",
            scanners=("sqlmap",),
            dependencies=(endpoint_discovery_node.id,),
            risk_level="critical",
            estimated_time=2400,
            status=NodeStatus.TO_DO
        )
        tree.add_node(sqli_scan_node)

        # Add vulnerability scanning task
        vuln_scan_node = PTNode(
            id=f"vuln_scan_{scan_id}",
            type=NodeType.VALIDATION,
            title="Vulnerability Scanning",
            description="Scan for known vulnerabilities",
            scanners=("nuclei",),
            dependencies=(endpoint_discovery_node.id,),
            risk_level="high",
            estimated_time=1800,
            status=NodeStatus.TO_DO
        )
        tree.add_node(vuln_scan_node)

        # Add CORS scanning task
        cors_scan_node = PTNode(
            id=f"cors_scan_{scan_id}",
            type=NodeType.VALIDATION,
            title="CORS Misconfiguration",
            description="Detect CORS misconfigurations",
            scanners=("cors",),
            dependencies=(endpoint_discovery_node.id,),
            risk_level="medium",
            estimated_time=600,
            status=NodeStatus.TO_DO
        )
        tree.add_node(cors_scan_node)

        return tree

    def generate_database_exploitation_tree(
        self,
        target_id: str,
        scan_id: str,
        db_data: Dict[str, Any]
    ) -> PTTree:
        """
        Generate database exploitation task tree

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            db_data: Database reconnaissance data

        Returns:
            PTTree instance
        """
        # Create root node
        root_node = PTNode(
            id=f"db_exploit_root_{scan_id}",
            type=NodeType.EXPLOITATION,
            title="Database Exploitation Phase",
            description="Exploit database vulnerabilities",
            risk_level="critical",
            estimated_time=3600,
            status=NodeStatus.COMPLETED
        )

        tree = self.pt_tree_manager.create_tree(
            root_id=root_node.id,
            scan_id=scan_id,
            target_id=target_id,
            root_node=root_node
        )

        # Add database enumeration task
        db_enum_node = PTNode(
            id=f"db_enum_{scan_id}",
            type=NodeType.DISCOVERY,
            title="Database Enumeration",
            description="Enumerate database information",
            scanners=("sqlmap", "--dbs"),
            dependencies=(root_node.id,),
            risk_level="high",
            estimated_time=900,
            status=NodeStatus.TO_DO
        )
        tree.add_node(db_enum_node)

        # Add SQL injection task
        sqli_scan_node = PTNode(
            id=f"sqli_scan_{scan_id}",
            type=NodeType.EXPLOITATION,
            title="SQL Injection",
            description="Exploit SQL injection vulnerabilities",
            scanners=("sqlmap",),
            dependencies=(db_enum_node.id,),
            risk_level="critical",
            estimated_time=2400,
            status=NodeStatus.TO_DO
        )
        tree.add_node(sqli_scan_node)

        return tree

    def generate_finding_specific_tree(
        self,
        target_id: str,
        scan_id: str,
        finding_type: str,
        finding_evidence: Dict[str, Any]
    ) -> PTTree:
        """
        Generate finding-specific task tree

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            finding_type: Type of finding
            finding_evidence: Evidence for the finding

        Returns:
            PTTree instance
        """
        if finding_type == "xss":
            return self.generate_web_exploitation_tree(target_id, scan_id, finding_evidence)

        elif finding_type == "sqli":
            return self.generate_database_exploitation_tree(target_id, scan_id, finding_evidence)

        elif finding_type == "lfi":
            return self._generate_lfi_tree(target_id, scan_id, finding_evidence)

        elif finding_type == "cors":
            return self.generate_web_exploitation_tree(target_id, scan_id, finding_evidence)

        else:
            # Generic tree for unknown finding types
            return self.generate_web_exploitation_tree(target_id, scan_id, finding_evidence)

    def _generate_lfi_tree(
        self,
        target_id: str,
        scan_id: str,
        evidence: Dict[str, Any]
    ) -> PTTree:
        """Generate LFI-specific task tree"""
        root_node = PTNode(
            id=f"lfi_root_{scan_id}",
            type=NodeType.EXPLOITATION,
            title="Local File Inclusion Exploitation",
            description="Exploit LFI vulnerabilities",
            risk_level="high",
            estimated_time=1800,
            status=NodeStatus.COMPLETED
        )

        tree = self.pt_tree_manager.create_tree(
            root_id=root_node.id,
            scan_id=scan_id,
            target_id=target_id,
            root_node=root_node
        )

        # Add LFI scanning task
        lfi_scan_node = PTNode(
            id=f"lfi_scan_{scan_id}",
            type=NodeType.EXPLOITATION,
            title="LFI Scanning",
            description="Detect and exploit LFI vulnerabilities",
            scanners=("lfi",),
            dependencies=(root_node.id,),
            risk_level="high",
            estimated_time=1200,
            status=NodeStatus.TO_DO
        )
        tree.add_node(lfi_scan_node)

        return tree

    def generate_adaptive_tree(
        self,
        target_id: str,
        scan_id: str,
        reconnaissance_data: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> PTTree:
        """
        Generate adaptive task tree based on reconnaissance and findings

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            reconnaissance_data: Reconnaissance data
            findings: Existing findings

        Returns:
            PTTree instance
        """
        # Determine based on findings
        finding_types = set(finding.get("type") for finding in findings)

        if "sqli" in finding_types or "xss" in finding_types:
            return self.generate_web_exploitation_tree(target_id, scan_id, reconnaissance_data)
        elif "lfi" in finding_types:
            return self._generate_lfi_tree(target_id, scan_id, reconnaissance_data)
        elif "cors" in finding_types:
            return self.generate_web_exploitation_tree(target_id, scan_id, reconnaissance_data)
        else:
            return self.generate_reconnaissance_tree(target_id, scan_id, reconnaissance_data)

    def get_next_task(
        self,
        scan_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get next task to execute

        Args:
            scan_id: Scan session ID

        Returns:
            Next task information or None
        """
        tree = self.pt_tree_manager.get_tree(scan_id)
        if not tree:
            return None

        # Get pending nodes
        pending_nodes = tree.get_pending_nodes()

        # Sort by weight (priority)
        sorted_nodes = sorted(
            pending_nodes,
            key=lambda x: x.get_weight(),
            reverse=True
        )

        # Filter by dependencies
        for node in sorted_nodes:
            if node.can_execute(tree.nodes):
                return {
                    "node_id": node.id,
                    "type": node.type.value,
                    "title": node.title,
                    "description": node.description,
                    "scanners": list(node.scanners),
                    "estimated_time": node.estimated_time,
                    "risk_level": node.risk_level
                }

        return None

    def generate_report_tree(
        self,
        target_id: str,
        scan_id: str,
        findings: List[Dict[str, Any]]
    ) -> PTTree:
        """
        Generate reporting task tree

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            findings: List of findings

        Returns:
            PTTree instance
        """
        root_node = PTNode(
            id=f"report_root_{scan_id}",
            type=NodeType.REPORTING,
            title="Reporting Phase",
            description="Generate final security report",
            risk_level="low",
            estimated_time=900,
            status=NodeStatus.COMPLETED
        )

        tree = self.pt_tree_manager.create_tree(
            root_id=root_node.id,
            scan_id=scan_id,
            target_id=target_id,
            root_node=root_node
        )

        # Add findings summary task
        summary_node = PTNode(
            id=f"summary_{scan_id}",
            type=NodeType.VALIDATION,
            title="Findings Summary",
            description="Summarize all findings",
            scanners=(),
            dependencies=(root_node.id,),
            risk_level="low",
            estimated_time=300,
            status=NodeStatus.TO_DO
        )
        tree.add_node(summary_node)

        # Add report generation task
        report_node = PTNode(
            id=f"report_gen_{scan_id}",
            type=NodeType.REPORTING,
            title="Report Generation",
            description="Generate final security report",
            scanners=("report",),
            dependencies=(summary_node.id,),
            risk_level="low",
            estimated_time=600,
            status=NodeStatus.TO_DO
        )
        tree.add_node(report_node)

        return tree