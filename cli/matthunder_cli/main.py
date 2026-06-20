"""
matthunder CLI v2.0 - Modern CLI with Typer
"""
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint
import httpx
import os
import json
from pathlib import Path

app = typer.Typer(
    name="matthunder",
    help="AI-Powered Bug Hunting & Penetration Testing Platform",
    add_completion=True
)

console = Console()

# API configuration
CONFIG_DIR = Path(os.getenv("MATTHUNDER_CONFIG_DIR", Path.home() / ".matthunder"))
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_config() -> dict:
    """Load CLI config from disk."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_config(config: dict) -> None:
    """Persist CLI config."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2), encoding="utf-8")


def get_api_token() -> str:
    """Get API token from env or CLI config."""
    return os.getenv("MATTHUNDER_API_TOKEN") or load_config().get("token", "")


def get_api_url() -> str:
    """Get API URL from env, config, or default local backend."""
    return os.getenv("MATTHUNDER_API_URL") or load_config().get("api_url", "http://localhost:8000")


def get_client() -> httpx.Client:
    """Get authenticated HTTP client"""
    headers = {}
    token = get_api_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=get_api_url(), headers=headers, timeout=30.0)


@app.command()
def login(
    username: str = typer.Option(..., "--username", "-u", prompt=True, help="API username"),
    password: str = typer.Option(..., "--password", "-p", prompt=True, hide_input=True, help="API password"),
):
    """Login and save API token locally."""
    try:
        api_url = get_api_url()
        with httpx.Client(base_url=api_url, timeout=30.0) as client:
            response = client.post("/api/v1/auth/login", params={
                "username": username,
                "password": password,
            })
            response.raise_for_status()
            token = response.json()["access_token"]
    except Exception as e:
        console.print(f"[red]Login failed:[/red] {e}")
        raise typer.Exit(1)

    config = load_config()
    config.update({"api_url": api_url, "token": token})
    save_config(config)
    console.print(f"[green]✓[/green] Logged in. Token saved to {CONFIG_FILE}")


@app.command()
def logout():
    """Remove saved API token."""
    config = load_config()
    config.pop("token", None)
    save_config(config)
    console.print("[green]✓[/green] Logged out")


@app.command()
def targets(
    action: str = typer.Argument(..., help="Action: list, add, delete"),
    domain: str = typer.Option(None, "--domain", "-d", help="Target domain"),
    target_id: str = typer.Option(None, "--id", help="Target ID (for delete)")
):
    """Manage targets"""
    client = get_client()
    
    if action == "list":
        try:
            response = client.get("/api/v1/targets")
            response.raise_for_status()
            targets = response.json()
            
            table = Table(title="Targets")
            table.add_column("ID", style="cyan")
            table.add_column("Domain", style="green")
            table.add_column("Created", style="magenta")
            
            for target in targets:
                table.add_row(
                    str(target["id"])[:8] + "...",
                    target["domain"],
                    target["created_at"][:10]
                )
            
            console.print(table)
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
    
    elif action == "add":
        if not domain:
            console.print("[red]Error:[/red] --domain is required")
            raise typer.Exit(1)
        
        try:
            response = client.post("/api/v1/targets", json={"domain": domain})
            response.raise_for_status()
            target = response.json()
            console.print(f"[green]✓[/green] Target added: {target['domain']} (ID: {target['id']})")
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")
    
    elif action == "delete":
        if not target_id:
            console.print("[red]Error:[/red] --id is required")
            raise typer.Exit(1)
        
        try:
            response = client.delete(f"/api/v1/targets/{target_id}")
            response.raise_for_status()
            console.print(f"[green]✓[/green] Target deleted")
        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")


@app.command()
def scan(
    target_id: str = typer.Argument(..., help="Target ID to scan"),
    scan_type: str = typer.Option("deep", "--type", "-t", help="Scan type: light, dark, deep, pipeline"),
    speed: str = typer.Option("standard", "--speed", "-s", help="Speed: low, standard, fast")
):
    """Start a new scan"""
    client = get_client()
    
    try:
        response = client.post("/api/v1/scans", json={
            "target_id": target_id,
            "scan_type": scan_type,
            "speed": speed
        })
        response.raise_for_status()
        scan = response.json()
        
        console.print(f"[green]✓[/green] Scan started!")
        console.print(f"  Scan ID: {scan['id']}")
        console.print(f"  Type: {scan['scan_type']}")
        console.print(f"  Status: {scan['status']}")
        console.print(f"\nView logs: matthunder logs {scan['id']}")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")


@app.command()
def scans(
    limit: int = typer.Option(20, "--limit", "-l", help="Number of scans to show")
):
    """List recent scans"""
    client = get_client()
    
    try:
        response = client.get(f"/api/v1/scans?limit={limit}")
        response.raise_for_status()
        scans = response.json()
        
        table = Table(title="Recent Scans")
        table.add_column("ID", style="cyan")
        table.add_column("Type", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Speed", style="blue")
        table.add_column("Created", style="magenta")
        
        for scan in scans:
            status_color = {
                "completed": "green",
                "running": "blue",
                "failed": "red",
                "pending": "yellow"
            }.get(scan["status"], "white")
            
            table.add_row(
                str(scan["id"])[:8] + "...",
                scan["scan_type"],
                f"[{status_color}]{scan['status']}[/{status_color}]",
                scan["speed"],
                scan["created_at"][:16]
            )
        
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")


@app.command()
def findings(
    scan_id: str = typer.Option(None, "--scan", "-s", help="Filter by scan ID"),
    severity: str = typer.Option(None, "--severity", help="Filter by severity"),
    limit: int = typer.Option(50, "--limit", "-l", help="Number of findings to show")
):
    """List findings"""
    client = get_client()
    
    params = {"limit": limit}
    if scan_id:
        params["scan_id"] = scan_id
    if severity:
        params["severity"] = severity
    
    try:
        response = client.get("/api/v1/findings", params=params)
        response.raise_for_status()
        findings = response.json()
        
        table = Table(title="Findings")
        table.add_column("ID", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("Scanner", style="green")
        table.add_column("Title", style="white")
        table.add_column("URL", style="blue")
        
        for finding in findings:
            severity_colors = {
                "critical": "red",
                "high": "magenta",
                "medium": "yellow",
                "low": "blue",
                "info": "white"
            }
            color = severity_colors.get(finding.get("severity", ""), "white")
            
            table.add_row(
                str(finding["id"])[:8] + "...",
                f"[{color}]{finding.get('severity', 'N/A')}[/{color}]",
                finding.get("scanner", "N/A"),
                (finding.get("title") or "N/A")[:40],
                (finding.get("url") or "N/A")[:40]
            )
        
        console.print(table)
        console.print(f"\nTotal: {len(findings)} findings")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")


@app.command()
def scanners():
    """List available scanners"""
    client = get_client()
    
    try:
        response = client.get("/api/v1/scanners")
        response.raise_for_status()
        scanners = response.json()
        
        table = Table(title="Available Scanners")
        table.add_column("Name", style="cyan")
        table.add_column("Display Name", style="green")
        table.add_column("Category", style="yellow")
        table.add_column("Description", style="white")
        
        for scanner in scanners:
            table.add_row(
                scanner["name"],
                scanner["display_name"],
                scanner["category"],
                scanner["description"][:50] + "..." if len(scanner["description"]) > 50 else scanner["description"]
            )
        
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")


@app.command()
def run_scanner(
    scanner_name: str = typer.Argument(..., help="Scanner name"),
    target: str = typer.Argument(..., help="Target domain")
):
    """Run a specific scanner"""
    client = get_client()
    
    try:
        response = client.post(f"/api/v1/scanners/{scanner_name}/run", json={
            "target": target,
            "config": {}
        })
        response.raise_for_status()
        result = response.json()
        
        console.print(f"[green]✓[/green] Scanner started!")
        console.print(f"  Scan ID: {result['scan_id']}")
        console.print(f"  Scanner: {result['scanner']}")
        console.print(f"  Status: {result['status']}")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")


@app.command()
def ai_analyze(
    prompt: str = typer.Argument(..., help="Analysis prompt"),
    provider: str = typer.Option(None, "--provider", "-p", help="AI provider: openai, anthropic, gemini, openrouter")
):
    """Run AI analysis"""
    client = get_client()
    
    payload = {"prompt": prompt}
    if provider:
        payload["provider"] = provider
    
    try:
        with console.status("[bold green]Analyzing..."):
            response = client.post("/api/v1/ai/analyze", json=payload)
            response.raise_for_status()
            result = response.json()
        
        console.print(f"\n[green]✓[/green] Analysis complete!")
        console.print(f"Provider: {result['provider']}")
        console.print(f"Model: {result['model']}")
        console.print(f"\n[yellow]Result:[/yellow]")
        console.print(result["response"].get("content", "No content"))
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")


@app.command()
def config():
    """Show current configuration"""
    client = get_client()
    
    try:
        response = client.get("/api/v1/config")
        response.raise_for_status()
        config = response.json()
        
        table = Table(title="Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in config.items():
            if isinstance(value, dict):
                value = ", ".join([f"{k}: {v}" for k, v in value.items()])
            table.add_row(key, str(value))
        
        console.print(table)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")


@app.command()
def status():
    """Check API status"""
    client = get_client()
    
    try:
        response = client.get("/health")
        response.raise_for_status()
        
        console.print("[green]✓[/green] API is healthy")
        console.print(f"API URL: {get_api_url()}")
    except Exception as e:
        console.print(f"[red]✗[/red] API is not accessible: {e}")


if __name__ == "__main__":
    app()
