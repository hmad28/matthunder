print('START', flush=True)
import sys, os
sys.path.insert(0, '.')
os.environ['PYTHONUTF8'] = '1'

print('importing acunetix...', flush=True)
from web.api.acunetix import router as acx_router
print(f'acunetix: prefix={acx_router.prefix}, routes={len(acx_router.routes)}', flush=True)

print('importing ai...', flush=True)
from web.api import ai as ai_mod
print(f'ai: prefix={ai_mod.router.prefix}, routes={len(ai_mod.router.routes)}', flush=True)

print('importing main...', flush=True)
from web.main import app
acx_found = any('acunetix' in str(getattr(r,'path','')) for r in app.routes)
ai_found = any('/api/ai' in str(getattr(r,'path','')) for r in app.routes)
print(f'in app.routes: acunetix={acx_found}, ai={ai_found}', flush=True)

from fastapi.testclient import TestClient
client = TestClient(app)
r1 = client.get('/api/acunetix/status')
print(f'GET /api/acunetix/status -> {r1.status_code}', flush=True)
r2 = client.get('/api/ai/providers')
print(f'GET /api/ai/providers -> {r2.status_code}', flush=True)

print('DONE', flush=True)
