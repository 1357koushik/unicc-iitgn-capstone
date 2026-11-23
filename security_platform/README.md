# Security Platform (Team 4)

The application people use: dashboard, login and roles, audit log, AI gateway API and network sensor.

| Folder | What it holds |
|---|---|
| `backend/` | FastAPI web app: authentication, audit log, investigation and admin APIs |
| `frontend/` | Analyst and investigator dashboard |
| `network_sensor/` | Network intrusion detection (see `network_sensor/README.md`) |
| `tests/` | Automatic checks for the network sensor |

**In Docker** nothing extra is needed: see `docs/DOCKER_SETUP.md`.

**Without Docker**, run from the project folder with both folders on the Python path:

```powershell
$env:PYTHONPATH = ".;security_platform"
python -m uvicorn backend.api.main:app --port 8080
python -m unittest discover -s security_platform/tests
```

On Linux or macOS use `export PYTHONPATH=.:security_platform`.
