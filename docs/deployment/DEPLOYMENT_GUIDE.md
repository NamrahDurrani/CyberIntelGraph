# Deployment guide: Fly.io (API) + Vercel (frontend)

Order matters: **API first, then frontend, then CORS, then test.** Neo4j Aura and MongoDB Atlas stay where they are.

| Part | Host | Root / files |
|---|---|---|
| FastAPI backend | Fly.io | `Dockerfile`, `fly.toml`, `.dockerignore`, `requirements-api.txt` (you generate it) |
| Next.js frontend | Vercel | Root Directory `frontend`, `frontend/vercel.json` |

## 0. Before anything: rotate secrets
Any key that was ever in a committed file, a chat, a screenshot or a zip you shared must be replaced. Replace and update your local `.env`:
- Groq API key (console.groq.com), NVD API key (nvd.nist.gov), Neo4j Aura password (console.neo4j.io), MongoDB Atlas database-user password (Atlas, Database Access)
- `JWT_SECRET` and `WEBHOOK_SECRET`: `python -c "import secrets; print(secrets.token_urlsafe(48))"`
Check whether secrets reached git history: `git log --all --oneline -S "gsk_"` and `git ls-files .env .env.example`. If history contains keys, rotating them is what protects you.

## 1. Backend on Fly.io

### 1.1 Confirm three things in your code
```powershell
cd C:\CyberIntelGraph
# a) the FastAPI app (expected: backend/main.py with app = FastAPI(...), so APP_MODULE = backend.main:app)
Select-String -Path backend -Pattern 'FastAPI\(' -Recurse -Include *.py
# b) the health route (expected /api/health). Open http://127.0.0.1:8000/docs locally and look for it.
Select-String -Path backend -Pattern 'health' -Recurse -Include *.py
# c) does the API embed text at request time, and which model?
Select-String -Path backend,agent,graphrag_engine -Pattern 'SentenceTransformer|EMBEDDING_MODEL' -Recurse -Include *.py
```
- If (a) differs, edit `APP_MODULE` in `fly.toml`.
- If (b) differs, edit `path` under `[[http_service.checks]]` in `fly.toml`.
- (c): `BAAI/bge-m3` needs roughly 2.5 GB RAM, which is why `fly.toml` asks for `4gb`. To bake the model into the image set `PREFETCH_MODEL = "BAAI/bge-m3"` in `fly.toml`. If the API does not embed anything at request time, set `USE_TORCH_CPU=0`, leave `PREFETCH_MODEL` empty and use `memory = "1gb"`.

### 1.2 CORS and streaming (backend code, two small checks)
The frontend calls the API directly from the browser and streams live events, so:
```powershell
Select-String -Path backend -Pattern 'CORSMiddleware|allow_origins' -Recurse -Include *.py
```
- The allowed origins must include your Vercel URL. Read them from an environment variable (for example `CORS_ORIGINS`, comma separated) if your code does not already, so you can change them without redeploying code. No cookies are used (the token is sent in the `Authorization` header), so credentials are not required.
- Streaming routes (`/events`, `/graph/watch`) should send `Cache-Control: no-cache` and `X-Accel-Buffering: no`, avoid gzip middleware, and send a small heartbeat every 15 to 30 seconds so proxies do not close an idle stream.

### 1.3 Build the API requirements
```powershell
.\.venv\Scripts\Activate.ps1      # the environment you run uvicorn in
python scripts\make_requirements_api.py backend agent database neo4j_engine graphrag_engine canonical config
notepad requirements-api.txt      # read it: remove dev-only packages, keep pinned versions
```
`torch` is excluded on purpose; the Dockerfile installs the CPU build.

### 1.4 Allow Fly to reach MongoDB Atlas
Atlas, Network Access: Fly machines do not have a fixed address by default. Either allow `0.0.0.0/0` (simplest; the database user and a strong password are then your protection) or give the app a fixed outbound IP (`fly ips allocate-egress`) and allow only that. Neo4j Aura works with the `neo4j+ssc://` address already in your `.env`.

### 1.5 Deploy
```powershell
iwr https://fly.io/install.ps1 -useb | iex        # installs flyctl, then reopen PowerShell
fly auth login
fly apps create cyberintel-api                    # pick another name if taken, and update `app` in fly.toml
Get-Content .env | fly secrets import             # stores your .env values as encrypted secrets on Fly
fly secrets set CORS_ORIGINS="http://localhost:3000"      # only if your code reads this variable; updated in step 3
fly deploy
fly status
curl https://cyberintel-api.fly.dev/api/health
fly logs
```
If startup fails on a missing file, the API reads local data that `.dockerignore` excluded (`data`, `outputs`, `logs`). Remove the needed folder from `.dockerignore`, or move that data to Atlas/Neo4j, and deploy again. Fly needs a payment method on file; check current pricing at fly.io/docs/about/pricing before leaving `min_machines_running = 1`.

## 2. Frontend on Vercel
In the Vercel dashboard: **Add New, Project, import the GitHub repository**, then set:
- **Root Directory:** `frontend`
- **Framework Preset:** Next.js (detected automatically)
- **Environment Variables** (Production and Preview): `NEXT_PUBLIC_API_URL = https://cyberintel-api.fly.dev`
Deploy. Every push to `main` redeploys. `NEXT_PUBLIC_API_URL` is baked into the build, so **after changing it you must redeploy**. It is visible in the browser: never put a secret in a `NEXT_PUBLIC_` variable.

CLI alternative:
```powershell
npm i -g vercel
cd frontend
vercel login
vercel link
vercel env add NEXT_PUBLIC_API_URL production      # value: https://cyberintel-api.fly.dev
vercel env add NEXT_PUBLIC_API_URL preview
vercel --prod
```

## 3. Close the loop (CORS)
```powershell
fly secrets set CORS_ORIGINS="http://localhost:3000,https://<your-app>.vercel.app"
```
This restarts the API. Vercel preview deployments use different addresses, so test on the production address or add an origin pattern for `https://<project>-*.vercel.app` in your CORS code.

## 4. Acceptance checklist
- [ ] `https://<fly-app>.fly.dev/api/health` returns 200, `/docs` loads (or is disabled on purpose)
- [ ] Register and sign in from the Vercel address, no CORS errors in the browser console
- [ ] One question end to end: the Pipeline panel streams, the answer has claims and evidence
- [ ] A second question in the same chat; the composer is docked at the bottom
- [ ] Knowledge graph page draws data from Aura; Dashboard shows Neo4j and MongoDB as connected
- [ ] `fly logs` shows no secrets and no stack traces during the test
- [ ] `python evaluation\run_eval.py --base-url https://<fly-app>.fly.dev ... --origin https://<your-app>.vercel.app` passes the gates
- [ ] Decide who may register on a public site (the register page is open to anyone) and add rate limiting if needed
- [ ] Every key that ever appeared in a file, chat or screenshot has been rotated

## 5. Operations
```powershell
fly logs                      # live logs
fly status; fly releases      # current and past releases
fly deploy --image <image>    # roll back to a previous release image (see fly releases)
fly secrets list              # names only, never values
fly scale memory 4096         # change memory
```
Vercel: Deployments, open a previous deployment, **Promote to Production** to roll back.

## 6. Troubleshooting
| Symptom | Likely cause |
|---|---|
| Browser console: blocked by CORS | Vercel address missing from the API's allowed origins, or a typo (no trailing slash) |
| Frontend says "Cannot reach the API" | `NEXT_PUBLIC_API_URL` wrong or not redeployed after changing it |
| Pipeline panel stays empty or stops | Streaming buffered or closed by a proxy: check the headers and heartbeat in 1.2 |
| API crashes at start, out of memory | Machine too small for the embedding model (1.1c) |
| `fly deploy` fails at pip install | `requirements-api.txt` pins a package that is not on PyPI for Linux; edit it |
| Neo4j or MongoDB not connected on the Dashboard | Secrets not imported, Atlas network access (1.4), or wrong password after rotation |
