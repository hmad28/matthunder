# Matthunder API Reference

Base URL: `http://localhost:8000/api/v1`

All endpoints require authentication unless otherwise noted. Include the JWT token in the Authorization header:

```
Authorization: Bearer <access_token>
```

## Authentication

### Register User

Create a new user account.

**Endpoint:** `POST /auth/register`

**Request Body:**
```json
{
  "username": "string",
  "email": "string",
  "password": "string"
}
```

**Response:** `201 Created`
```json
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "is_active": true,
  "is_superuser": false,
  "created_at": "datetime"
}
```

**Errors:**
- `400 Bad Request` - Username or email already exists

---

### Login

Authenticate and receive access + refresh tokens.

**Endpoint:** `POST /auth/login`

**Authentication:** HTTP Basic Auth (username:password)

**Response:** `200 OK`
```json
{
  "access_token": "jwt-token",
  "refresh_token": "refresh-token",
  "token_type": "bearer",
  "expires_in": 1800,
  "user_id": "uuid"
}
```

**Errors:**
- `401 Unauthorized` - Invalid credentials

---

### Refresh Token

Exchange a valid refresh token for new access + refresh tokens.

**Endpoint:** `POST /auth/refresh`

**Query Parameters:**
- `refresh_token` (required) - Valid refresh token

**Response:** `200 OK`
```json
{
  "access_token": "new-jwt-token",
  "refresh_token": "new-refresh-token",
  "token_type": "bearer",
  "expires_in": 1800
}
```

**Errors:**
- `401 Unauthorized` - Invalid or expired refresh token

---

### Logout

Revoke refresh tokens.

**Endpoint:** `POST /auth/logout`

**Query Parameters:**
- `refresh_token` (optional) - Specific token to revoke
- `all_devices` (optional, default: false) - Revoke all tokens for user

**Response:** `200 OK`
```json
{
  "message": "Token revoked",
  "all_devices": false
}
```

---

### Get Current User

Get authenticated user information.

**Endpoint:** `GET /auth/me`

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "username": "string",
  "email": "string",
  "is_active": true,
  "is_superuser": false,
  "created_at": "datetime"
}
```

---

### Create API Key

Create a new API key for service accounts.

**Endpoint:** `POST /auth/api-keys`

**Request Body:**
```json
{
  "name": "string",
  "scopes": ["read", "write"],
  "expires_in_days": 90
}
```

**Response:** `201 Created`
```json
{
  "id": "uuid",
  "name": "string",
  "key": "mt_...",
  "scopes": ["read", "write"],
  "expires_at": "datetime",
  "last_used_at": null,
  "is_active": true,
  "created_at": "datetime"
}
```

**Note:** The `key` field is only returned once on creation. Store it securely.

---

### List API Keys

List all API keys for the current user.

**Endpoint:** `GET /auth/api-keys`

**Response:** `200 OK`
```json
[
  {
    "id": "uuid",
    "name": "string",
    "scopes": ["read", "write"],
    "expires_at": "datetime",
    "last_used_at": "datetime",
    "is_active": true,
    "created_at": "datetime"
  }
]
```

---

### Revoke API Key

Revoke an API key.

**Endpoint:** `DELETE /auth/api-keys/{key_id}`

**Response:** `200 OK`
```json
{
  "message": "API key revoked"
}
```

---

## Targets

### List Targets

Get all targets for the current user.

**Endpoint:** `GET /targets`

**Query Parameters:**
- `skip` (optional, default: 0) - Pagination offset
- `limit` (optional, default: 100) - Maximum results

**Response:** `200 OK`
```json
[
  {
    "id": "uuid",
    "domain": "example.com",
    "notes": "string",
    "scope": {},
    "created_by": "uuid",
    "created_at": "datetime",
    "updated_at": "datetime"
  }
]
```

---

### Create Target

Create a new target.

**Endpoint:** `POST /targets`

**Request Body:**
```json
{
  "domain": "example.com",
  "notes": "Optional notes",
  "scope": {
    "allowed_subdomains": ["*.example.com"],
    "blocked_paths": ["/admin"]
  }
}
```

**Response:** `201 Created`
```json
{
  "id": "uuid",
  "domain": "example.com",
  "notes": "string",
  "scope": {},
  "created_by": "uuid",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

---

### Get Target

Get a specific target by ID.

**Endpoint:** `GET /targets/{target_id}`

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "domain": "example.com",
  "notes": "string",
  "scope": {},
  "created_by": "uuid",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

**Errors:**
- `404 Not Found` - Target not found
- `403 Forbidden` - Not authorized

---

### Update Target

Update a target.

**Endpoint:** `PUT /targets/{target_id}`

**Request Body:**
```json
{
  "domain": "new-domain.com",
  "notes": "Updated notes",
  "scope": {}
}
```

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "domain": "new-domain.com",
  "notes": "Updated notes",
  "scope": {},
  "created_by": "uuid",
  "created_at": "datetime",
  "updated_at": "datetime"
}
```

---

### Delete Target

Delete a target and all associated scans/findings.

**Endpoint:** `DELETE /targets/{target_id}`

**Response:** `204 No Content`

---

## Scans

### List Scans

Get all scans for the current user.

**Endpoint:** `GET /scans`

**Query Parameters:**
- `skip` (optional, default: 0) - Pagination offset
- `limit` (optional, default: 100) - Maximum results
- `status_filter` (optional) - Filter by status (pending, running, completed, failed, cancelled)

**Response:** `200 OK`
```json
[
  {
    "id": "uuid",
    "target_id": "uuid",
    "scan_type": "deep",
    "status": "running",
    "speed": "standard",
    "celery_task_id": "task-id",
    "started_at": "datetime",
    "completed_at": null,
    "created_by": "uuid",
    "metadata": {},
    "created_at": "datetime"
  }
]
```

---

### Create Scan

Create and start a new scan.

**Endpoint:** `POST /scans`

**Request Body:**
```json
{
  "target_id": "uuid",
  "scan_type": "deep",
  "speed": "standard",
  "metadata": {
    "custom_config": "value"
  }
}
```

**Scan Types:**
- `light` - Quick reconnaissance
- `dark` - Standard scan
- `deep` - Comprehensive scan (requires approval)
- `pipeline` - Multi-phase scan

**Speed Options:**
- `low` - Conservative rate limiting
- `standard` - Normal speed
- `fast` - Aggressive scanning

**Response:** `201 Created`
```json
{
  "id": "uuid",
  "target_id": "uuid",
  "scan_type": "deep",
  "status": "pending",
  "speed": "standard",
  "celery_task_id": "task-id",
  "started_at": null,
  "completed_at": null,
  "created_by": "uuid",
  "metadata": {},
  "created_at": "datetime"
}
```

**Note:** Deep scans may require approval. Check the response status and create an approval request if needed.

---

### Get Scan

Get a specific scan by ID.

**Endpoint:** `GET /scans/{scan_id}`

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "target_id": "uuid",
  "scan_type": "deep",
  "status": "completed",
  "speed": "standard",
  "celery_task_id": "task-id",
  "started_at": "datetime",
  "completed_at": "datetime",
  "created_by": "uuid",
  "metadata": {},
  "created_at": "datetime"
}
```

---

### Get Scan Status

Get scan status with progress information.

**Endpoint:** `GET /scans/{scan_id}/status`

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "status": "running",
  "target_id": "uuid",
  "scan_type": "deep",
  "started_at": "datetime",
  "completed_at": null
}
```

---

### Stop Scan

Cancel a running scan.

**Endpoint:** `POST /scans/{scan_id}/stop`

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "target_id": "uuid",
  "scan_type": "deep",
  "status": "cancelled",
  "speed": "standard",
  "celery_task_id": "task-id",
  "started_at": "datetime",
  "completed_at": "datetime",
  "created_by": "uuid",
  "metadata": {},
  "created_at": "datetime"
}
```

**Errors:**
- `400 Bad Request` - Scan is not running

---

### Get Scan Logs

Get logs for a specific scan.

**Endpoint:** `GET /scans/{scan_id}/logs`

**Query Parameters:**
- `limit` (optional, default: 1000) - Maximum log entries

**Response:** `200 OK`
```json
[
  {
    "id": 1,
    "scan_id": "uuid",
    "level": "info",
    "message": "Scan started",
    "timestamp": "datetime"
  }
]
```

**Log Levels:**
- `info` - Informational messages
- `warn` - Warnings
- `error` - Errors
- `success` - Successful operations

---

### WebSocket: Real-Time Logs

Connect to real-time scan log stream.

**Endpoint:** `WS /scans/{scan_id}/ws`

**Query Parameters:**
- `token` (required) - JWT access token

**Connection:**
```javascript
const ws = new WebSocket(`ws://localhost:8000/api/v1/scans/${scanId}/ws?token=${accessToken}`);
```

**Messages:**
```json
{
  "type": "log",
  "data": {
    "level": "info",
    "message": "Scan started"
  }
}
```

**Message Types:**
- `log` - Scan log entry
- `status` - Scan status update
- `error` - Error message
- `complete` - Scan completed

**Close Codes:**
- `4401` - Authentication required or invalid token
- `4403` - Not authorized or origin not allowed
- `4404` - Scan not found
- `1011` - Internal error

---

## Findings

### List Findings

Get all findings for the current user.

**Endpoint:** `GET /findings`

**Query Parameters:**
- `skip` (optional, default: 0) - Pagination offset
- `limit` (optional, default: 100) - Maximum results
- `scan_id` (optional) - Filter by scan ID
- `severity` (optional) - Filter by severity (critical, high, medium, low, info)
- `scanner` (optional) - Filter by scanner name

**Response:** `200 OK`
```json
[
  {
    "id": "uuid",
    "scan_id": "uuid",
    "scanner": "xss",
    "severity": "high",
    "category": "Cross-Site Scripting",
    "title": "Reflected XSS in search parameter",
    "description": "Detailed description",
    "url": "https://example.com/search?q=<script>",
    "source_url": "https://example.com/search",
    "evidence": "<script>alert(1)</script>",
    "http_code": 200,
    "status": "new",
    "cve_id": null,
    "cvss_score": 7.5,
    "remediation": "Sanitize user input",
    "metadata": {},
    "created_at": "datetime"
  }
]
```

---

### Get Finding Stats

Get finding statistics grouped by severity.

**Endpoint:** `GET /findings/stats`

**Response:** `200 OK`
```json
{
  "total": 42,
  "critical": 2,
  "high": 8,
  "medium": 15,
  "low": 12,
  "info": 5
}
```

---

### Get Finding

Get a specific finding by ID.

**Endpoint:** `GET /findings/{finding_id}`

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "scan_id": "uuid",
  "scanner": "xss",
  "severity": "high",
  "category": "Cross-Site Scripting",
  "title": "Reflected XSS in search parameter",
  "description": "Detailed description",
  "url": "https://example.com/search?q=<script>",
  "source_url": "https://example.com/search",
  "evidence": "<script>alert(1)</script>",
  "http_code": 200,
  "status": "new",
  "cve_id": null,
  "cvss_score": 7.5,
  "remediation": "Sanitize user input",
  "metadata": {},
  "created_at": "datetime"
}
```

---

### Update Finding

Update finding status or severity.

**Endpoint:** `PUT /findings/{finding_id}`

**Request Body:**
```json
{
  "status": "confirmed",
  "severity": "critical"
}
```

**Status Options:**
- `new` - Newly discovered
- `confirmed` - Verified vulnerability
- `false_positive` - Not a real vulnerability
- `fixed` - Remediated

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "scan_id": "uuid",
  "scanner": "xss",
  "severity": "critical",
  "category": "Cross-Site Scripting",
  "title": "Reflected XSS in search parameter",
  "description": "Detailed description",
  "url": "https://example.com/search?q=<script>",
  "source_url": "https://example.com/search",
  "evidence": "<script>alert(1)</script>",
  "http_code": 200,
  "status": "confirmed",
  "cve_id": null,
  "cvss_score": 9.8,
  "remediation": "Sanitize user input",
  "metadata": {},
  "created_at": "datetime"
}
```

---

## Approvals

### Create Approval Request

Create a new approval request for a dangerous operation.

**Endpoint:** `POST /approvals`

**Request Body:**
```json
{
  "request_type": "scan",
  "target_id": "uuid",
  "scan_id": "uuid",
  "payload": {
    "scan_type": "deep",
    "speed": "standard"
  },
  "reason": "Deep scan requires approval due to resource intensity",
  "expires_in_minutes": 60
}
```

**Request Types:**
- `scan` - Scan execution
- `scanner_run` - Individual scanner execution
- `ai_hunt` - AI-powered hunting
- `bulk_scan` - Multiple target scan
- `export_raw_data` - Raw data export

**Response:** `201 Created`
```json
{
  "id": "uuid",
  "request_type": "scan",
  "requestor_id": "uuid",
  "reviewer_id": null,
  "target_id": "uuid",
  "scan_id": "uuid",
  "payload": {},
  "reason": "string",
  "status": "pending",
  "review_comment": null,
  "requested_at": "datetime",
  "reviewed_at": null,
  "expires_at": "datetime"
}
```

---

### List Approval Requests

List approval requests.

**Endpoint:** `GET /approvals`

**Query Parameters:**
- `status_filter` (optional) - Filter by status (pending, approved, rejected, expired)
- `skip` (optional, default: 0) - Pagination offset
- `limit` (optional, default: 100) - Maximum results

**Response:** `200 OK`
```json
[
  {
    "id": "uuid",
    "request_type": "scan",
    "requestor_id": "uuid",
    "reviewer_id": null,
    "target_id": "uuid",
    "scan_id": "uuid",
    "payload": {},
    "reason": "string",
    "status": "pending",
    "review_comment": null,
    "requested_at": "datetime",
    "reviewed_at": null,
    "expires_at": "datetime"
  }
]
```

---

### Get Approval Request

Get a specific approval request by ID.

**Endpoint:** `GET /approvals/{request_id}`

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "request_type": "scan",
  "requestor_id": "uuid",
  "reviewer_id": "uuid",
  "target_id": "uuid",
  "scan_id": "uuid",
  "payload": {},
  "reason": "string",
  "status": "approved",
  "review_comment": "Approved - within scope",
  "requested_at": "datetime",
  "reviewed_at": "datetime",
  "expires_at": "datetime"
}
```

---

### Review Approval Request

Approve or reject an approval request.

**Endpoint:** `POST /approvals/{request_id}/review`

**Request Body:**
```json
{
  "status": "approved",
  "comment": "Approved - within scope"
}
```

**Status Options:**
- `approved` - Approve the request
- `rejected` - Reject the request

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "request_type": "scan",
  "requestor_id": "uuid",
  "reviewer_id": "uuid",
  "target_id": "uuid",
  "scan_id": "uuid",
  "payload": {},
  "reason": "string",
  "status": "approved",
  "review_comment": "Approved - within scope",
  "requested_at": "datetime",
  "reviewed_at": "datetime",
  "expires_at": "datetime"
}
```

**Errors:**
- `400 Bad Request` - Request already reviewed or expired
- `403 Forbidden` - Cannot review your own request

---

### Cancel Approval Request

Cancel a pending approval request (by requestor).

**Endpoint:** `POST /approvals/{request_id}/cancel`

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "request_type": "scan",
  "requestor_id": "uuid",
  "reviewer_id": null,
  "target_id": "uuid",
  "scan_id": "uuid",
  "payload": {},
  "reason": "string",
  "status": "cancelled",
  "review_comment": "Cancelled by requestor",
  "requested_at": "datetime",
  "reviewed_at": "datetime",
  "expires_at": "datetime"
}
```

---

### Get Approval Stats

Get approval statistics for the current user.

**Endpoint:** `GET /approvals/stats/summary`

**Response:** `200 OK`
```json
{
  "pending": 3,
  "approved": 15,
  "rejected": 2,
  "expired": 1,
  "pending_review": 5
}
```

---

## Audit

### List Audit Logs

Get audit logs (superuser only).

**Endpoint:** `GET /audit`

**Query Parameters:**
- `user_id` (optional) - Filter by user ID
- `action` (optional) - Filter by action (supports prefix matching with *)
- `resource_type` (optional) - Filter by resource type
- `resource_id` (optional) - Filter by resource ID
- `start_date` (optional) - Filter logs after this date
- `end_date` (optional) - Filter logs before this date
- `skip` (optional, default: 0) - Pagination offset
- `limit` (optional, default: 100, max: 1000) - Maximum results

**Response:** `200 OK`
```json
[
  {
    "id": "uuid",
    "user_id": "uuid",
    "action": "scan.create",
    "resource_type": "scan",
    "resource_id": "uuid",
    "details": {
      "scan_type": "deep"
    },
    "ip_address": "192.168.1.1",
    "status": "success",
    "created_at": "datetime"
  }
]
```

---

### Get My Audit Logs

Get audit logs for the current user.

**Endpoint:** `GET /audit/me`

**Query Parameters:**
- Same as `/audit` endpoint

**Response:** `200 OK`
```json
[
  {
    "id": "uuid",
    "user_id": "uuid",
    "action": "scan.create",
    "resource_type": "scan",
    "resource_id": "uuid",
    "details": {},
    "ip_address": "192.168.1.1",
    "status": "success",
    "created_at": "datetime"
  }
]
```

---

### Get My Activity Summary

Get activity summary for the current user.

**Endpoint:** `GET /audit/me/activity`

**Query Parameters:**
- `days` (optional, default: 30, max: 365) - Number of days to look back

**Response:** `200 OK`
```json
{
  "user_id": "uuid",
  "period_days": 30,
  "total_actions": 142,
  "action_counts": {
    "scan.create": 25,
    "scan.stop": 3,
    "finding.update": 48,
    "target.create": 12
  },
  "first_activity": "datetime",
  "last_activity": "datetime"
}
```

---

### Get Resource History

Get complete audit history for a specific resource (superuser only).

**Endpoint:** `GET /audit/resource/{resource_type}/{resource_id}`

**Response:** `200 OK`
```json
[
  {
    "id": "uuid",
    "user_id": "uuid",
    "action": "scan.create",
    "resource_type": "scan",
    "resource_id": "uuid",
    "details": {},
    "ip_address": "192.168.1.1",
    "status": "success",
    "created_at": "datetime"
  }
]
```

---

## Scanners

### List Available Scanners

Get all available scanners.

**Endpoint:** `GET /scanners`

**Response:** `200 OK`
```json
[
  {
    "name": "xss",
    "display_name": "XSS Scanner",
    "description": "Cross-Site Scripting detection",
    "category": "vulnerability",
    "is_active": true
  }
]
```

---

### Run Scanner

Execute a specific scanner on a target.

**Endpoint:** `POST /scanners/{scanner_name}/run`

**Request Body:**
```json
{
  "target": "example.com",
  "config": {
    "custom_option": "value"
  }
}
```

**Response:** `200 OK`
```json
{
  "scan_id": "uuid",
  "scanner": "xss",
  "status": "running",
  "message": "Scanner started"
}
```

---

## Pipeline

### Run Pipeline

Execute a multi-phase scanning pipeline.

**Endpoint:** `POST /pipeline/run`

**Request Body:**
```json
{
  "target_id": "uuid",
  "speed": "standard",
  "phases": ["recon", "discovery", "vuln_scan"]
}
```

**Pipeline Phases:**
1. `scope-intake` - Scope normalization
2. `asset-discovery` - Subdomain enumeration
3. `live-host-probing` - HTTP probing
4. `service-discovery` - Port scanning
5. `deep-entry-mapping` - Content discovery
6. `safe-validation` - Vulnerability scanning

**Response:** `200 OK`
```json
{
  "scan_id": "uuid",
  "current_phase": "recon",
  "completed_phases": [],
  "status": "running",
  "progress": 0.0
}
```

---

### Get Pipeline Status

Get pipeline execution status.

**Endpoint:** `GET /pipeline/{scan_id}/status`

**Response:** `200 OK`
```json
{
  "scan_id": "uuid",
  "current_phase": "vuln_scan",
  "completed_phases": ["recon", "discovery"],
  "status": "running",
  "progress": 0.67
}
```

---

## AI

### List AI Providers

Get available AI providers.

**Endpoint:** `GET /ai/providers`

**Response:** `200 OK`
```json
[
  {
    "name": "openai",
    "configured": true,
    "default_model": "gpt-4o-mini",
    "available_models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"]
  },
  {
    "name": "anthropic",
    "configured": true,
    "default_model": "claude-3-5-haiku-latest",
    "available_models": ["claude-3-5-sonnet-latest", "claude-3-5-haiku-latest"]
  }
]
```

---

### Analyze with AI

Run AI analysis on a prompt.

**Endpoint:** `POST /ai/analyze`

**Request Body:**
```json
{
  "prompt": "Analyze this XSS vulnerability and suggest remediation steps",
  "provider": "openai",
  "model": "gpt-4o-mini",
  "scan_id": "uuid"
}
```

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "provider": "openai",
  "model": "gpt-4o-mini",
  "response": {
    "content": "Analysis result...",
    "tokens_used": 150
  },
  "tokens_used": 150,
  "created_at": "datetime"
}
```

---

### AI-Powered Hunting

Run AI-powered vulnerability hunting on a target.

**Endpoint:** `POST /ai/hunt`

**Request Body:**
```json
{
  "target_id": "uuid",
  "provider": "anthropic",
  "model": "claude-3-5-sonnet-latest",
  "focus": "authentication bypass"
}
```

**Response:** `200 OK`
```json
{
  "analysis": {
    "findings": [],
    "recommendations": [],
    "attack_paths": []
  }
}
```

---

## Reports

### List Reports

Get all reports for the current user.

**Endpoint:** `GET /reports`

**Query Parameters:**
- `skip` (optional, default: 0) - Pagination offset
- `limit` (optional, default: 100) - Maximum results

**Response:** `200 OK`
```json
[
  {
    "id": "uuid",
    "scan_id": "uuid",
    "report_type": "pdf",
    "file_path": "/reports/report-123.pdf",
    "file_size": 1024000,
    "generated_at": "datetime",
    "created_by": "uuid"
  }
]
```

---

### Get Report

Get a specific report by ID.

**Endpoint:** `GET /reports/{report_id}`

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "scan_id": "uuid",
  "report_type": "pdf",
  "file_path": "/reports/report-123.pdf",
  "file_size": 1024000,
  "generated_at": "datetime",
  "created_by": "uuid"
}
```

---

### Download Report

Download a report file.

**Endpoint:** `GET /reports/{report_id}/download`

**Response:** `200 OK`

**Content-Type:** `application/pdf` (or appropriate MIME type)

**Headers:**
```
Content-Disposition: attachment; filename="report-123.pdf"
Content-Length: 1024000
```

---

## Configuration

### Get Configuration

Get current system configuration.

**Endpoint:** `GET /config`

**Response:** `200 OK`
```json
{
  "app_name": "matthunder",
  "version": "2.0.0",
  "debug": false,
  "database": "postgresql",
  "redis": "connected",
  "celery": "enabled",
  "ai_providers": {
    "openai": true,
    "anthropic": true,
    "gemini": false,
    "openrouter": false
  }
}
```

---

### Get Output Directories

Get information about output directories.

**Endpoint:** `GET /config/output-dirs`

**Response:** `200 OK`
```json
{
  "upload_dir": {
    "path": "./uploads",
    "exists": true,
    "file_count": 42
  },
  "reports_dir": {
    "path": "./reports",
    "exists": true,
    "file_count": 15
  },
  "scans_dir": {
    "path": "./scans",
    "exists": true,
    "file_count": 128
  }
}
```

---

## Acunetix Integration

### Get Acunetix Status

Check Acunetix connection status.

**Endpoint:** `GET /acunetix/status`

**Response:** `200 OK`
```json
{
  "connected": true,
  "version": "14.0",
  "targets_count": 50,
  "scans_count": 120
}
```

---

### Get Acunetix Targets

Get targets from Acunetix.

**Endpoint:** `GET /acunetix/targets`

**Response:** `200 OK`
```json
[
  {
    "target_id": "acunetix-id",
    "address": "https://example.com",
    "description": "Example target"
  }
]
```

---

### Get Acunetix Scans

Get scans from Acunetix.

**Endpoint:** `GET /acunetix/scans`

**Query Parameters:**
- `limit` (optional, default: 50) - Maximum results

**Response:** `200 OK`
```json
[
  {
    "scan_id": "acunetix-scan-id",
    "target_id": "acunetix-target-id",
    "status": "completed",
    "start_date": "datetime",
    "vulnerabilities_count": 15
  }
]
```

---

### Get Acunetix Vulnerabilities

Get vulnerabilities from Acunetix.

**Endpoint:** `GET /acunetix/vulns`

**Query Parameters:**
- `limit` (optional, default: 100) - Maximum results

**Response:** `200 OK`
```json
[
  {
    "vuln_id": "acunetix-vuln-id",
    "scan_id": "acunetix-scan-id",
    "severity": "high",
    "name": "SQL Injection",
    "description": "Detailed description",
    "affects": "https://example.com/login",
    "details": {}
  }
]
```

---

### Get Acunetix Scan Vulnerabilities

Get vulnerabilities for a specific Acunetix scan.

**Endpoint:** `GET /acunetix/vulns/{scan_id}`

**Response:** `200 OK`
```json
[
  {
    "vuln_id": "acunetix-vuln-id",
    "scan_id": "acunetix-scan-id",
    "severity": "high",
    "name": "SQL Injection",
    "description": "Detailed description",
    "affects": "https://example.com/login",
    "details": {}
  }
]
```

---

## Error Responses

All error responses follow this format:

```json
{
  "detail": "Error message"
}
```

**Common HTTP Status Codes:**
- `400 Bad Request` - Invalid request data
- `401 Unauthorized` - Missing or invalid authentication
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource already exists
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

---

## Rate Limiting

Rate limits are enforced per IP address:

- **API Endpoints:** 30 requests/minute (burst: 20)
- **Login Endpoint:** 5 requests/minute (burst: 3)

When rate limited, you'll receive:

**Response:** `429 Too Many Requests`
```json
{
  "detail": "Rate limit exceeded"
}
```

**Headers:**
```
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1640000000
```

---

## WebSocket Authentication

WebSocket connections require JWT authentication via query parameter:

```javascript
const ws = new WebSocket(`ws://localhost:8000/api/v1/scans/${scanId}/ws?token=${accessToken}`);
```

**Close Codes:**
- `4401` - Authentication required or invalid token
- `4403` - Not authorized or origin not allowed
- `4404` - Scan not found
- `1000` - Normal closure
- `1011` - Internal error

---

## API Versioning

The API is versioned via URL path:
- Current version: `/api/v1/`
- Future versions: `/api/v2/`, etc.

---

## SDK Examples

### Python

```python
import httpx

# Login
response = httpx.post(
    "http://localhost:8000/api/v1/auth/login",
    auth=("username", "password")
)
tokens = response.json()
access_token = tokens["access_token"]

# Create target
headers = {"Authorization": f"Bearer {access_token}"}
response = httpx.post(
    "http://localhost:8000/api/v1/targets",
    headers=headers,
    json={"domain": "example.com"}
)
target = response.json()

# Start scan
response = httpx.post(
    "http://localhost:8000/api/v1/scans",
    headers=headers,
    json={
        "target_id": target["id"],
        "scan_type": "deep",
        "speed": "standard"
    }
)
scan = response.json()
```

### JavaScript

```javascript
// Login
const loginResponse = await fetch('http://localhost:8000/api/v1/auth/login', {
  method: 'POST',
  headers: {
    'Authorization': 'Basic ' + btoa('username:password')
  }
});
const tokens = await loginResponse.json();
const accessToken = tokens.access_token;

// Create target
const targetResponse = await fetch('http://localhost:8000/api/v1/targets', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({ domain: 'example.com' })
});
const target = await targetResponse.json();

// Start scan
const scanResponse = await fetch('http://localhost:8000/api/v1/scans', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    target_id: target.id,
    scan_type: 'deep',
    speed: 'standard'
  })
});
const scan = await scanResponse.json();

// WebSocket connection
const ws = new WebSocket(
  `ws://localhost:8000/api/v1/scans/${scan.id}/ws?token=${accessToken}`
);
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log(message);
};
```

---

## Further Reading

- [Architecture Documentation](./architecture.md)
- [Deployment Guide](./deployment.md)
- [Security Model](./security.md)
- [Scanner Development Guide](./scanner-development.md)
