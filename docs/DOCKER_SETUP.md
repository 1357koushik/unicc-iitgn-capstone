# UNICC Cyber AI: setup guide (Docker)

This guide installs the whole system on one machine with Docker: the web application
(dashboard, login, audit log, AI gateway, network sensor) and the Team 2 threat retrieval
service, plus, if wanted, an on-premise AI model (Ollama). It takes about 30 minutes, most
of it spent downloading and copying.

Contents

1. [What runs where](#1-what-runs-where)
2. [What you need](#2-what-you-need)
3. [Quick start](#3-quick-start)
4. [The retrieval data](#4-the-retrieval-data)
5. [Settings (.env)](#5-settings-env)
6. [First login and user accounts](#6-first-login-and-user-accounts)
7. [The AI model: Gemini or Ollama](#7-the-ai-model-gemini-or-ollama)
8. [Check that everything works](#8-check-that-everything-works)
9. [Network sensor](#9-network-sensor)
10. [Day-to-day operation](#10-day-to-day-operation)
11. [Before real use: security checklist](#11-before-real-use-security-checklist)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. What runs where

`docker-compose.yml` in the project folder starts these containers:

| Container | What it is | Address | Stores its files in |
|---|---|---|---|
| `backend` | Web app: dashboard, login, roles, audit log, AI summaries (Gemini or Ollama), PoC discovery, network sensor | http://localhost:8080 (open to the network) | Docker volume `app-data` (accounts, audit log, saved settings, sensor models) |
| `retrieval` | Team 2 threat retrieval and matching (v2 pipeline): CVE store, keyword index, vector index, MITRE ATT&CK graph, technique ranking. CPU only | http://127.0.0.1:8000 (this computer only) | reads the **retrieval data** folder (read-only); PoC cache in volume `retrieval-state` |
| `ollama` (optional) | On-premise AI model server, started only with `--profile ollama` | http://127.0.0.1:11434 (this computer only) | volume `ollama-models` |

People use only the web app (port 8080). The web app calls the retrieval service inside
Docker, so port 8000 is open only to the computer itself, for API use and checks.

```
 browser ──► backend :8080 ──► retrieval :8000 ──► /data (retrieval data, read-only)
                │
                ├──► Google Gemini API (internet), or
                └──► Ollama :11434 (on-premise)
```

## 2. What you need

| | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores, x86-64 | 8 cores or more |
| Memory (RAM) for Docker | 8 GB with the technique ranking off (`TRE_TECHNIQUES=0`), 12 GB with it on | **16 GB**, plus 8 GB more for the bundled Ollama |
| Free disk | 25 GB | 40 GB (more for Ollama models) |
| Software | Docker Engine 24+ with the Compose plugin (`docker compose version`), or Docker Desktop 4.x | |
| Internet | to build the images (Docker Hub, GitHub container registry, PyPI, download.pytorch.org) | at run time only for Gemini, the PoC sources (GitHub, Mastodon, Bluesky) and the network-sensor dataset download |

No GPU is needed: the retrieval service runs on the CPU, the configuration it was benchmarked in.
Measured memory of the retrieval service: 5.2 GB just after start with everything on, 2.5 GB with
`TRE_TECHNIQUES=0`; the long-running service on the IITGN server grew to 7.8 GB. The web app
needs about 0.5 GB.

**Windows and macOS (Docker Desktop):** Docker Desktop gives its Linux machine only part of the
computer's memory. Check *Settings → Resources* (macOS) or the WSL memory limit (Windows:
`%UserProfile%\.wslconfig`, `[wsl2]` section, `memory=16GB`, then `wsl --shutdown`) and give it
at least the memory in the table. Too little memory shows up as the retrieval container being
restarted while it loads (see [Troubleshooting](#12-troubleshooting)).

## 3. Quick start

Commands are for a Linux or macOS terminal. On Windows use PowerShell; where a command
differs, the PowerShell form is given too.

**Step 1: get the code** (the `main` branch holds every team's code):

```bash
git clone https://github.com/1357koushik/unicc-iitgn-capstone.git
cd unicc-iitgn-capstone
```

**Step 2: put the retrieval data in place.** You receive it from the project team as a folder
or a `retrieval-data.tar` file of about 8 GB (section 4 explains what is inside and how to make
it). Put it in the project folder so that `retrieval-data/BUNDLE.json` exists:

```bash
tar -xf /path/to/retrieval-data.tar          # creates ./retrieval-data
python3 scripts/docker/retrieval_data.py check retrieval-data --full
```

The check must end with `OK: retrieval data in retrieval-data (checksums verified)`. It needs
only Python 3.9+ (no packages). To keep the data somewhere else, set `RETRIEVAL_DATA_DIR` in
`.env` (step 3) to that folder.

**Step 3: create the settings file** from the example and fill it in:

```bash
cp .env.example .env                    # PowerShell: Copy-Item .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Open `.env` in a text editor and paste the printed value after `JWT_SECRET=`. That is the only
value you must set now; the AI key can be added later in the dashboard (section 7). Section 5
lists every setting.

**Step 4: build and start:**

```bash
docker compose up -d --build
```

The first build downloads the Python packages (installed, they take about 1.3 GB for the retrieval
image and 0.3 GB for the web app), so it takes several minutes; later builds reuse them. Add
`--profile ollama` to also start the on-premise AI model (section 7).

**Step 5: wait until both containers are healthy** (the retrieval service needs 1 to 3 minutes
to load its 8 GB of indexes and models into memory):

```bash
docker compose ps
```

Both `backend` and `retrieval` must show `(healthy)`. While loading, `retrieval` shows
`(health: starting)`. To watch it: `docker compose logs -f retrieval` (Ctrl+C stops watching,
not the service). It loads the indexes and models (`v2 pipeline ready`), then answers three
warm-up questions, because the very first questions after a start are slow, and only then
reports `ready for requests` and turns healthy. In the test of this setup that took 69 seconds.

**Step 6: note the login passwords.** On the very first start the web app creates three accounts
with random passwords and prints them **once**:

```bash
docker compose logs backend | grep -A4 "No user accounts existed"
# PowerShell: docker compose logs backend | Select-String -Context 0,4 "No user accounts existed"
```

**Step 7: open http://localhost:8080** (from another computer: `http://<server address>:8080`)
and log in as `admin_user`. Then go to **System Config → Google Gemini**, paste your Gemini API
key and press **Check and save** (section 7).

Done. Section 8 shows how to check each part.

## 4. The retrieval data

The retrieval service does not build anything when it starts: it reads finished builds. They are
kept out of the image (too large, and they change on their own schedule) and mounted read-only
into the container at `/data`. The folder:

```
retrieval-data/
  BUNDLE.json                                   build IDs; size and sha256 of every file
  store/LATEST       store/<build>/             CVE store: store.sqlite (3.2 GB, 424,176 CVEs, 405,013 searchable)
  lexical/LATEST     lexical/<build>/           keyword index: SQLite FTS5 + BM25 score matrix (0.5 GB)
  dense/LATEST       dense/<build>/             vector index: 406,840 x 1,024 vectors, bge-large-en-v1.5 (1.6 GB)
  attack/LATEST      attack/<build>/            MITRE ATT&CK 20.1 graph and names (24 MB)
  techniques/LATEST  techniques/<build>/        ATT&CK technique ranking (255 MB, optional)
  models/bge-large-en-v1.5/                     query encoder of the vector index (1.3 GB)
  models/Qwen3-Embedding-0.6B/                  second encoder of the technique ranking (1.2 GB, optional)
```

Each `LATEST` file names the build folder next to it. These are exactly the builds of the
evaluated, served configuration (`docs/RETRIEVAL_V2_PLAN.md`, C3b to C7):

| Part | Build |
|---|---|
| store | `20261115T091739Z-f7f744ffa8` |
| lexical | `20261115T203653Z-bfacb4bb1c` |
| dense | `20261118T022104Z-ac852d4454` |
| attack | `20261115T190948Z-917121fbde` |
| techniques | `20261118T074915Z-9ee875f803` |

**Checking it.** `python3 scripts/docker/retrieval_data.py check <folder>` checks the structure,
that the builds belong together (each one was made from the others) and every file's size, in a
few seconds; add `--full` to also compare every file's sha256 (about a minute). The retrieval
container runs the quick check at every start and, if something is wrong, stops with a list of
what is missing instead of a long error later.

**Less memory: without the technique ranking.** Set `TRE_TECHNIQUES=0` in `.env`. The service then
skips the technique ranking (the `attack_techniques` part of each answer) and its Qwen3 model,
saving about 2.5 GB of memory; `techniques/` and `models/Qwen3-Embedding-0.6B/` may then be left
out of the folder.

**Making the bundle (project team).** From folders that hold the builds (the PC's `data/` folder or
the server's `~/team2`), one command copies exactly the needed builds and models and writes
`BUNDLE.json`; it refuses builds that do not belong together and checks the vector index and its
model against the checksums recorded when the index was built:

```bash
python scripts/docker/retrieval_data.py pack --out retrieval-data \
    --store data/store --lexical data/lexical/20261115T203653Z-bfacb4bb1c \
    --dense data/dense/20261118T022104Z-ac852d4454 --attack data/attack \
    --techniques data/techniques --models data/models
tar -cf retrieval-data.tar retrieval-data     # about 8 GB; hand it over on a drive or file share
```

Each `--<part>` takes a build folder or a folder whose `LATEST` names one. `--link` hard-links
instead of copying (same disk only). On the server the folders are `~/team2/store/builds`,
`~/team2/lexical/builds/<id>`, `~/team2/dense/builds`, `~/team2/attack/builds`,
`~/team2/techniques/builds` and `~/team2/models`.

**Rebuilding the data from the public sources (advanced).** Only needed for newer data. The order,
with the commands' own `--help` for details: collect the sources
(`python scripts/collect/collect_all.py`) and the Team 1 CVE feeds (`knowledge_foundation/feeds`),
then build the store (`python -m threat_retrieval_engine.store.build`), the ATT&CK store
(`python -m threat_retrieval_engine.attack.build`), the keyword index
(`python -m threat_retrieval_engine.lexical.build --attack ...`), the vector index
(`python -m threat_retrieval_engine.dense.build documents|encode|assemble`, about 15 hours on a
CPU server, minutes on a GPU) and the technique ranking (`python scripts/v2/build_techniques.py`).
Each build checks its own inputs and refuses unexplained records. After a rebuild the quality
figures in `docs/BENCHMARKS.md` no longer apply until the evaluation is run again.

## 5. Settings (.env)

All settings live in `.env` in the project folder (copied from `.env.example`, which explains
each one). `.env` holds secrets: it is never uploaded by git and never copied into an image;
the containers read it through a read-only mount. **After editing `.env`**, apply it with

```bash
docker compose up -d --force-recreate backend      # web-app settings (most of them)
docker compose up -d --force-recreate retrieval    # TRE_*, RETRIEVAL_*, PoC source logins (reloads 1-3 min)
```

(Many editors save a file as a new copy, which a running container does not see until it is
recreated. Your data is in volumes and is kept.) The Gemini key and model can instead be
changed in the dashboard (section 7), which needs no restart at all.

| Setting | Default | What it does |
|---|---|---|
| `JWT_SECRET` | random at each start | Signs logins. **Set it** (step 3), or everyone is logged out at every restart |
| `COOKIE_SECURE` | `false` | `true` once the app is served over HTTPS (section 11) |
| `SESSION_MINUTES` | `60` | How long a login lasts |
| `DEFAULT_LLM_BACKEND` | `gemini` | AI backend on the very first start; afterwards an admin switches it in System Config |
| `GEMINI_API_KEY`, `GEMINI_MODEL` | empty, `gemma-4-26b-a4b-it` | Gemini key and model (also settable in System Config, which wins) |
| `OLLAMA_HOST`, `OLLAMA_MODEL` | `http://ollama:11434`, `llama3.2:3b` | Ollama server and model. `http://ollama:11434` = the bundled container. **Note:** `.env.example` holds the IITGN lab address; change it, or empty it to use the bundled one |
| `GITHUB_TOKEN`, `MASTODON_*`, `BLUESKY_*` | empty | Logins of the PoC discovery sources (optional; without them those sources report "not configured") |
| `APP_PORT` | `8080` | Port of the web app on this computer |
| `RETRIEVAL_PORT` | `8000` | Port of the retrieval API (this computer only) |
| `RETRIEVAL_DATA_DIR` | `./retrieval-data` | Where the retrieval data folder is |
| `TRE_TECHNIQUES` | `1` | `0` turns the technique ranking off (section 4, less memory) |
| `TRE_NUM_THREADS` | number of CPUs, at most 8 | CPU threads of the retrieval service |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Address of your HTTPS reverse proxy (section 11) |
| `LOGIN_MAX_FAILURES_PER_USER`, `LOGIN_MAX_FAILURES_PER_IP`, `LOGIN_BLOCK_MINUTES` | 5, 20, 15 | Password-guessing limits |

## 6. First login and user accounts

The first start creates `admin_user` (admin), `investigator_1` (investigator) and `auditor_1`
(auditor), each with a random password printed once in the backend log (step 6). The roles:
admins configure the system and manage users, investigators analyse reports, auditors read the
audit log.

Set a new password (also if the first-start passwords were missed):

```bash
docker compose exec backend python -m backend.manage_users reset-password investigator_1
```

Other account commands: `docker compose exec backend python -m backend.manage_users --help`.
Accounts, the audit log and saved settings are in the `app-data` volume: they survive
`docker compose down`, rebuilds and updates (but see `down -v` in section 10).

## 7. The AI model: Gemini or Ollama

The AI writes report summaries, extracts entities and writes the investigation assessment.
Choose the backend in **System Config → LLM Backend** (admin only).

**Google Gemini (cloud).** Get a key at https://aistudio.google.com/apikey. In **System Config →
Google Gemini**, paste it and press **Check and save**: the app asks Google whether the key and
model work (no text is generated, nothing is charged) and saves the key only if Google accepts
it. It is used at once, no restart. Afterwards the page shows only the key's last 4 characters;
**Test connection** checks again at any time, **Remove saved key** goes back to the key in
`.env`. The model can be changed in the same panel (current names:
https://ai.google.dev/gemini-api/docs/models). Gemini needs internet access from the server.

Alternatively put `GEMINI_API_KEY=...` in `.env` (no spaces or quotes needed) and apply it with
`docker compose up -d --force-recreate backend`. A key saved in the dashboard wins over `.env`.

**Ollama (on-premise, no internet needed at run time).** Either use your own Ollama server (set
`OLLAMA_HOST` in `.env` to its address) or start the bundled one and download a model once:

```bash
docker compose --profile ollama up -d
docker compose exec ollama ollama pull llama3.2:3b      # the model named in OLLAMA_MODEL
```

Leave `OLLAMA_HOST` empty in `.env` to use the bundled container. Then choose **Ollama
(On-Premise)** in System Config. Bigger models give better answers but need more memory and
are slower on a CPU.

## 8. Check that everything works

```bash
docker compose ps                                        # backend and retrieval: (healthy)
curl -s http://127.0.0.1:8000/api/v1/health              # retrieval components and build IDs
curl -s -X POST http://127.0.0.1:8000/api/v1/threats/match \
     -H "Content-Type: application/json" \
     -d '{"query": "EternalBlue SMB remote code execution", "top_k": 3}'
```

PowerShell: `Invoke-RestMethod http://127.0.0.1:8000/api/v1/health`, and for the match
`Invoke-RestMethod -Method Post http://127.0.0.1:8000/api/v1/threats/match -ContentType "application/json" -Body '{"query": "EternalBlue SMB remote code execution", "top_k": 3}'`.

Expected: `/health` lists the five builds of section 4 and `"confidence_model": "calibrated"`;
the match returns `CVE-2017-0144` first. Other good checks: a CVE ID (`CVE-2021-44228`, rank 1,
tier `EXACT`) and a group (`Lazarus Group spear phishing`: `attack:G0032` first, with ATT&CK
techniques such as `T1566.003` in `attack_techniques`).

In the web app: log in as `investigator_1`, paste a short report on **Investigate** (for example
*"Attackers used EternalBlue (MS17-010) against our SMB file servers"*) and run the analysis;
with an AI backend configured you get the summary, the entities and the matched threats. As
admin, **Audit Logs** shows each step.

## 9. Network sensor

The sensor (Team 4, Task 5.0) needs a trained model; set it up once, inside the backend container
(it stores everything in the `app-data` volume):

```bash
docker compose exec backend python -m network_sensor.download_data     # NSL-KDD (needs internet)
docker compose exec backend python -m network_sensor.train
docker compose exec backend python -m network_sensor.evaluate
```

Without internet, copy the two dataset files in first, then run `download_data` (it keeps files
whose fingerprints match):

```bash
docker compose exec backend mkdir -p /data/network_sensor/nsl_kdd
docker compose cp KDDTrain+.txt backend:/data/network_sensor/nsl_kdd/
docker compose cp KDDTest+.txt backend:/data/network_sensor/nsl_kdd/
```

Other datasets (CIC-IDS2017, your own traffic) and what the reports mean:
`network_sensor/README.md`.

## 10. Day-to-day operation

| Task | Command |
|---|---|
| Status | `docker compose ps` |
| Logs (follow) | `docker compose logs -f backend` / `retrieval` |
| Stop / start | `docker compose stop` / `docker compose start` |
| Apply a change to `.env` | `docker compose up -d --force-recreate backend` (and/or `retrieval`) |
| Update to new code | `git pull`, then `docker compose up -d --build` |
| New retrieval data | replace the folder (or point `RETRIEVAL_DATA_DIR` at the new one), run the `check --full`, then `docker compose restart retrieval` |
| Remove the containers (data kept) | `docker compose down` |
| Remove everything, **including accounts and audit log** | `docker compose down -v` (cannot be undone) |

**Backup** of accounts, audit log, settings and sensor models (the `app-data` volume):

```bash
docker compose stop backend
docker run --rm -v unicc-cyber-ai_app-data:/data -v "$PWD":/backup alpine tar -czf /backup/app-data-backup.tgz -C /data .
docker compose start backend
```

Restore: the same with `tar -xzf /backup/app-data-backup.tgz -C /data` into a stopped backend.
The retrieval data needs no backup beyond the original bundle.

**Moving from the earlier compose files.** Earlier versions kept the database in the project's
`data/app.db` (top-level `docker-compose.yml`) or used `deployment/api` / `deployment/onprem`.
To keep the old accounts and audit log, copy the old file in once, before the first login:
`docker compose cp data/app.db backend:/data/app.db`, then `docker compose restart backend`.

## 11. Before real use: security checklist

1. `JWT_SECRET` is set to a long random value (step 3), and `.env` is readable only by the
   administrators (Linux: `chmod 600 .env`).
2. **HTTPS.** Serve the web app through a reverse proxy with a certificate (nginx, Caddy, Traefik,
   or your organisation's gateway) and then set `COOKIE_SECURE=true` and
   `FORWARDED_ALLOW_IPS=<the proxy's address>`. Never `*`: anyone could then fake their address
   and get around the login limits. Do not publish port 8080 beyond the proxy (`APP_PORT` can be
   set to `127.0.0.1:8080` when the proxy runs on the same machine).
3. Ports 8000 (retrieval) and 11434 (Ollama) are bound to `127.0.0.1` by `docker-compose.yml`; keep
   it that way: they have no logins of their own.
4. Change the three first-start passwords if they were shared, and remove accounts that are not
   needed.
5. The containers run as an ordinary user (not root); the retrieval data is mounted read-only.
6. Gemini sends report text to Google. For reports that must not leave the organisation, use
   Ollama (section 7).
7. Back up the `app-data` volume regularly (section 10): it holds the audit log.

## 12. Troubleshooting

| What you see | Cause and fix |
|---|---|
| `docker compose up` stops at once: *bind source path does not exist: .../.env* | `.env` is missing: step 3 (`cp .env.example .env`) |
| *... does not exist: .../retrieval-data* | The data folder is not where `RETRIEVAL_DATA_DIR` says (default: `retrieval-data` in the project folder): step 2 |
| `retrieval` restarts again and again; its log ends with *The retrieval data in /data is not usable* | The log lists what is missing or incomplete. Run `python3 scripts/docker/retrieval_data.py check <folder> --full` on the host and replace damaged parts |
| `retrieval` restarts while loading, with no error, or `docker compose ps` shows exit code 137 | Not enough memory for Docker (section 2). Give Docker more memory, or set `TRE_TECHNIQUES=0` in `.env` and run `docker compose up -d` |
| `retrieval` stays `(health: starting)` for more than 5 minutes | Slow disk, or the data folder is on a network share. `docker compose logs retrieval` shows progress; the data should be on a local disk |
| Threat matching says *Threat matching is not available right now: the threat retrieval service cannot be reached or is still starting* | `retrieval` is still loading or not healthy: `docker compose ps`, then `docker compose logs retrieval`; wait for `(healthy)`. Admins see the exact cause in the message and in the audit log (stage `retrieval`) |
| AI summary fails: *Google says the Gemini API key is not valid* | Paste a new key in System Config → Google Gemini (**Check and save**) |
| AI summary fails: *Google has no model called ...* | The model name was retired or mistyped: change it in System Config (current names: https://ai.google.dev/gemini-api/docs/models) |
| AI summary fails: *Cannot connect to Gemini* / *Could not reach Google* | The server has no internet access (or a proxy blocks it): use Ollama |
| AI summary fails with Ollama: connection refused | `OLLAMA_HOST` is wrong, or the bundled container is not started (`--profile ollama`), or the model is not pulled (`docker compose exec ollama ollama list`) |
| Login passwords were missed | `docker compose exec backend python -m backend.manage_users reset-password admin_user` |
| Everyone is logged out after each restart | `JWT_SECRET` is empty in `.env` |
| Port 8080 already in use | Set `APP_PORT=8090` (any free port) in `.env`, `docker compose up -d` |
| Building fails while downloading packages | The build needs internet (section 2). Behind a company proxy, configure Docker's proxy settings (Docker Desktop: *Settings → Resources → Proxies*) |

Details for each part: the root `README.md`, `docs/API_REFERENCE.md` (retrieval API),
`docs/V2_API_CHANGES.md`, `network_sensor/README.md`, and `TEAM2_REPORT.md`.
