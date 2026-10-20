# Network Security AI Sensor (Task 5.0, Team 4)

Flags network connections that look like attacks, using three machine-learning models
that check each other, and measures how precise it is on two public labelled datasets:
**NSL-KDD** (the classic benchmark) and **CIC-IDS2017** (modern traffic from 2017).

| Model | Learns from | Good at |
|---|---|---|
| Isolation Forest | normal traffic only | spotting anything unusual |
| One-Class SVM | normal traffic only | the same, built differently, so it makes different mistakes |
| Random Forest | labelled normal **and** attack traffic | attack types it has seen before |

**Decision rule:** a connection is an attack if the Random Forest says so, **or** if both
normal-only models agree it is abnormal. The second part is there to catch new kinds of
attack; how well it does that differs a lot between attack types (see the reports).

**Every alert explains itself** in plain English: which models raised it, and up to three
measurements that are rare in normal traffic, for example

> Matches known attack patterns (Random Forest score 92%), and both anomaly models found it abnormal.
> - Network service on the destination: eco_i (normal: usually http). Only 0.7% of normal connections have this.
> - Protocol: icmp (normal: usually tcp). Only 1.9% of normal connections have this.

The evaluation report checks that these reasons are true: resetting the named measurements
to normal values must clear far more alerts than resetting random other measurements.
The Random Forest score is the share of its trees voting "attack" - good for ranking
alerts, but not a guaranteed probability (false alarms can score 99%).

The idea (several anomaly models working together) follows
[SentinelAI](https://github.com/ayaan-cs/SentinelAI), named in the UNICC task sheet.
SentinelAI trains on made-up traffic; this sensor is trained and scored on public
labelled data, as the evaluation sheet asks for public ground truth:

| Dataset | Traffic | Measurements per connection | Test |
|---|---|---|---|
| NSL-KDD | 1998, a simulated military network (DARPA / MIT Lincoln Laboratory) | 41 (connection summary) | the official test file, with 17 attack types not in the training file |
| CIC-IDS2017 | 2017, five working days, modern attacks | 65 (CICFlowMeter flow measurements) | 30% of the flows, plus a retraining check for each attack family it has never seen |

| Dataset | Precision (Task 5.0 target: 90%) | Attacks caught | False alarms on normal traffic |
|---|---|---|---|
| NSL-KDD | 96.7% | 72.3% | 3.2% |
| CIC-IDS2017 | 96.1% | 99.4% | 0.9% |

(From `python -m network_sensor.evaluate`, October 2026; the reports explain every number.)

The same models and decision rule are used for both, fixed on NSL-KDD before CIC-IDS2017
was used. One setting, the anomaly models' false-alarm budget, was re-chosen for CIC-IDS2017
(5% to 2%) on its training data after the first test run gave 89.1% precision; its report
says so. `python -m network_sensor.calibrate --dataset cicids2017` repeats that choice.

## Run it (Windows PowerShell, in the project folder)

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements-network-sensor.txt   # once (already installed in most setups)

python -m network_sensor.download_data   # downloads NSL-KDD (~22 MB), checks fingerprints
python -m network_sensor.train           # trains the three models (under a minute)
python -m network_sensor.evaluate        # precision / recall report on the official test file

python -m unittest test_network_sensor test_network_sensor_api test_network_sensor_live test_network_sensor_cicids2017 -v   # automatic checks
```

**CIC-IDS2017** (optional, larger): download `MachineLearningCSV.zip` from the
[CIC-IDS2017 page](https://www.unb.ca/cic/datasets/ids-2017.html) ("Download this dataset";
only that file, not the PCAPs), then:

```powershell
python -m network_sensor.cicids2017 "C:\path\to\MachineLearningCSV.zip"   # checks it, keeps a copy
python -m network_sensor.train --dataset cicids2017      # a few minutes
python -m network_sensor.evaluate --dataset cicids2017   # longer: also retrains once per attack family
python -m network_sensor.calibrate --dataset cicids2017  # optional: how the anomaly share was chosen
```

Everything the commands create goes into `data/network_sensor/` (ignored by git):
the datasets, the trained models, and the reports (`reports/evaluation_report.md` / `.json`,
and `reports/cicids2017/` for CIC-IDS2017).

## Use it from the app (API)

Train the sensor first (above), then start the app as usual. Investigators and admins can use:

| Endpoint | What it does |
|---|---|
| `GET /api/v1/network/status` | Is the sensor trained? When? Latest evaluation score. |
| `POST /api/v1/network/scan` | Upload a file of connections (form field `file`); get back the alerts, most serious first, each with its explanation. |
| `POST /api/v1/network/live/start?speed=100` | Start a live replay of an uploaded file at 10, 100 or 1,000 connections per second. |
| `POST /api/v1/network/live/{id}/next` | Check what has "arrived" since the last call (the dashboard calls this once a second). |
| `POST /api/v1/network/live/{id}/stop` | Stop a live replay early. |

- **File formats:** `.csv` with a header row naming the 41 NSL-KDD columns, a raw NSL-KDD
  file with no header (41 values per row, optionally followed by the label and difficulty,
  like `KDDTest+.txt`), or a CIC-IDS2017 CSV file (the format the CICFlowMeter tool writes).
  Each format is checked by the sensor trained on that dataset; the answer says which one.
  If a label column is present, the answer also says how precise the sensor was on that
  file. Labels are never used to decide.
- **Limits:** 5 MB and 25,000 connections per file; one scan at a time (others get "try again").
  The 300 most serious alerts of each kind are returned (known attack patterns, and possible
  new attacks raised only by the anomaly models); the totals are always given.
- **Audit log:** every scan, including refused files, is recorded with the file's name,
  size and SHA-256 fingerprint and the number of alerts. The file itself is not kept.
- If scikit-learn is not installed on the server, the rest of the app still works and
  these endpoints say how to install the sensor.
- Retraining is picked up automatically, without restarting the app.

## Live mode (real-time)

The dashboard's **Live Mode** panel replays a recorded file as if its connections were
arriving now. Once a second it checks everything that has arrived since the last second,
as one batch ("micro-batching", the way network sensors usually work: checking 1,000
connections together takes about as long as checking 5 one by one). New alerts appear
at the top of a live feed, with counters and the time each second of traffic took to
check. `python -m network_sensor.evaluate` measures these times on your computer and
writes them in the report's "Speed" section.

- It is a **replay of recorded traffic**, not a capture of this computer's own network:
  working out the measurements from live packets needs extra tools (for the CIC-IDS2017
  format, CICFlowMeter does exactly this).
- Only the user who started a replay can see or stop it. One replay per user; at most
  3 on the whole server. A replay nobody has checked on for 10 minutes is dropped.
- The start and the end of every replay (completed, stopped, or logged out) go in the
  audit log, with the file's fingerprint, the speed and the number of alerts.
- Replays are kept in the server's memory, so they assume one server process (the
  normal `uvicorn backend.api.main:app`).

## Run it in Docker

The backend image (`deployment/docker/Dockerfile.backend`) includes the sensor. It uses
Python 3.13 because the sensor's pinned packages need Python 3.12 or newer.

- **`docker-compose.yml`** in the project folder: the backend uses the project's `data/`
  folder, so a sensor trained on the host (`python -m network_sensor.train`) is used as it is.
- **`deployment/api`** and **`deployment/onprem`**: the sensor keeps its files on the
  `app-data` volume (`NETWORK_SENSOR_DATA_DIR=/data/network_sensor`), so they survive
  rebuilds. Set it up once, from the project folder (for on-premise, use
  `deployment/onprem/docker-compose.yml`):

```bash
docker compose -f deployment/api/docker-compose.yml build backend
docker compose -f deployment/api/docker-compose.yml up -d backend
docker compose -f deployment/api/docker-compose.yml logs backend    # first start: the login passwords, shown once
docker compose -f deployment/api/docker-compose.yml exec backend python -m network_sensor.download_data
docker compose -f deployment/api/docker-compose.yml exec backend python -m network_sensor.train
docker compose -f deployment/api/docker-compose.yml exec backend python -m network_sensor.evaluate
```

Then open **http://localhost:8080** (the `0.0.0.0` address in the log is not a browser address).
The app shows the login passwords only on its very first start; if they were missed, set a
new one with
`docker compose -f deployment/api/docker-compose.yml exec backend python -m backend.manage_users reset-password investigator_1`.

If the container cannot reach GitHub, copy the two dataset files in first, then run the
`download_data` command above: it keeps files whose fingerprints match.

```bash
docker compose -f deployment/onprem/docker-compose.yml exec backend mkdir -p /data/network_sensor/nsl_kdd
docker compose -f deployment/onprem/docker-compose.yml cp data/network_sensor/nsl_kdd/KDDTrain+.txt backend:/data/network_sensor/nsl_kdd/
docker compose -f deployment/onprem/docker-compose.yml cp data/network_sensor/nsl_kdd/KDDTest+.txt backend:/data/network_sensor/nsl_kdd/
```

For CIC-IDS2017, copy the downloaded zip in (give its path), prepare it inside the
container, then train and evaluate:

```bash
docker compose -f deployment/api/docker-compose.yml cp MachineLearningCSV.zip backend:/tmp/MachineLearningCSV.zip
docker compose -f deployment/api/docker-compose.yml exec backend python -m network_sensor.cicids2017 /tmp/MachineLearningCSV.zip
docker compose -f deployment/api/docker-compose.yml exec backend python -m network_sensor.train --dataset cicids2017
docker compose -f deployment/api/docker-compose.yml exec backend python -m network_sensor.evaluate --dataset cicids2017
```

How this was checked: with Docker Desktop 4.96 on Windows (October 2026), the `build`
command built the image in about 4 minutes, and inside the container the commands above set
up both sensors with the same results as outside Docker (NSL-KDD 96.7%, CIC-IDS2017 96.1%);
the dashboard at http://localhost:8080 showed both sensors ready. `JWT_SECRET` and
`GEMINI_API_KEY` were left unset for this check (the app then uses a temporary login key and
AI summaries are off); set them for real use.

## Files

| File | What it does |
|---|---|
| `spec.py` | what differs between datasets (columns, wording, attack families), in one description per dataset |
| `download_data.py` | downloads NSL-KDD and refuses files whose SHA-256 fingerprint does not match |
| `datasets.py` | NSL-KDD: reads the files, adds `is_attack` and the attack family (DoS, Probe, R2L, U2R), plain-English wording |
| `cicids2017.py` | CIC-IDS2017: checks the zip's fingerprints, reads and splits it, plain-English wording |
| `features.py` | checks input (no missing columns, text in number columns, impossible values) and converts it to model inputs |
| `models.py` | the three models, the decision rule, saving and loading |
| `explain.py` | the normal-traffic profile and the plain-English reason for each alert |
| `train.py` | trains on a dataset's training part and saves the model |
| `evaluate.py` | scores the model on the test part, checks the explanations, writes the report |
| `calibrate.py` | chooses the anomaly models' false-alarm budget on validation data from the training part |
| `service.py` | used by the web app: reads uploaded files, picks the matching sensor, runs scans, reports status |
| `live.py` | live replays: speed, micro-batches, who may use them, limits |
| `errors.py` | the error type the web app turns into an answer |
| `paths.py` | where files are kept |

## Security notes

- Trained model files are Python pickles: **opening one can run code hidden inside it**.
  Only load model files you trained yourself; never commit them or accept them from others.
- Downloaded data is checked against fixed SHA-256 fingerprints before it is used.

## Known limitations

- NSL-KDD comes from 1998 traffic; CIC-IDS2017 from a 2017 test network. Real UNICC traffic
  will look different from both.
- The measurements come with the datasets; the sensor does not yet compute them from
  live traffic (live mode replays recorded traffic). For CIC-IDS2017-format files, the
  CICFlowMeter tool can produce them from captured packets.
- On NSL-KDD, remote-access attacks (R2L, e.g. password guessing) are mostly missed, because
  its training file has very few examples of them. The evaluation reports show results per family.
- CIC-IDS2017 has no official training/test split, and researchers have found some wrong
  labels in it; its report explains how the split was made and what that means.
