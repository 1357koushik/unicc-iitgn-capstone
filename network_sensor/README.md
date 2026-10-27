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

**Every alert also says what to do** (see "Actionable alerts" below): its likely attack type,
a priority (High / Medium / Low), how sure the sensor is, and a suggested first step.

The sensor is trained and scored on public labelled data, as the evaluation sheet asks for
public ground truth (see "How this compares with SentinelAI" for the tool the sheet names):

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

## Actionable alerts

Task 5.0 asks for "clear, actionable insights into why activities were flagged". Besides the
reasons above, every alert says:

| | What it is | Where it comes from |
|---|---|---|
| **Likely attack type** | the known attack family the connection most resembles, e.g. "Likely: Web Attack" | a fourth model (another Random Forest) trained on the labelled **attacks** only. It never decides whether a connection is flagged, so the detection results above are unchanged |
| **Priority** | High, Medium or Low: how much is at stake | a fixed rule (below), not learned |
| **Certainty** | how sure the sensor is: all three models, the Random Forest alone, or only the two anomaly models | the models' votes |
| **Next step** | one suggested first action for that type of attack | written per attack family in `datasets.py` and `cicids2017.py` |
| **Where** | addresses and ports, if the file has those columns (CICFlowMeter's full output does) | the uploaded file; never used by the models |

**Priority rule.** A known-pattern alert gets what its likely attack type could do if it succeeds:

- **High** - could give an attacker control of a machine, an account or data
  (NSL-KDD: R2L, U2R; CIC-IDS2017: Brute Force, Web Attack, Botnet, Infiltration, Heartbleed)
- **Medium** - could make a service unavailable (DoS, DDoS)
- **Low** - information gathering only (Probe, PortScan)

A possible new attack (raised only by the two anomaly models) is **Medium**: its type is
unknown, so it shows the *closest* known type with low certainty. Certainty is shown next to
the priority, not mixed into it: the Random Forest is rarely sure about rare attack types (on a
validation slice of the NSL-KDD training data, 1 of 11 U2R attacks scored 90% or more, against
99.8% of DoS attacks), so lowering the priority of unsure alerts would push the rarest, most
damaging types down the list. Alerts are listed High first.

Measured on the test parts (the reports' "Actionable alerts" section has the details per family):

| | NSL-KDD | CIC-IDS2017 |
|---|---|---|
| Likely attack type right (known-pattern alerts on real attacks) | 97.1% (7,658 of 7,885) | 100.0% (156,033 of 156,061) |
| High-priority alerts that were real attacks | 99.5% of 182 | 94.2% of 6,212 |
| Medium-priority alerts that were real attacks | 98.4% of 7,525 | 94.7% of 108,718 |
| Low-priority alerts that were real attacks | 89.8% of 1,888 | 99.4% of 47,498 |

On NSL-KDD, even for caught attacks of the 17 types never seen in training, the family was named correctly for 71.2% (1,568 of 2,202). On CIC-IDS2017 the type is almost always right, but as with detection that number is optimistic: its test flows come from the same recording, and the same attacks, as its training flows.

Example (CIC-IDS2017):

> **High** - Known pattern - Likely: Heartbleed. Matches known attack patterns (Random Forest score 100%), and both anomaly models found it abnormal.
> - Average data per packet from the destination: 3,808 bytes (normal: usually 0 bytes to 718 bytes). Higher than any normal connection seen in training.
> - Certainty: High: all three models flagged it (Random Forest score 100%). Where: Destination Port 444
> - **Next step:** Someone may be exploiting the Heartbleed bug. Update OpenSSL on the target server now, then replace its certificates and keys and make users log in again, because secrets may have leaked.

The dashboard shows the priority, type and next step on every alert, can show only one
priority level, and draws two charts: alerts by priority and alerts by likely type (and, in
live mode, alerts per second).

## Run it (Windows PowerShell, in the project folder)

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements-network-sensor.txt   # once (already installed in most setups)

python -m network_sensor.download_data   # downloads NSL-KDD (~22 MB), checks fingerprints
python -m network_sensor.train           # trains the three models and the attack-type classifier (under a minute)
python -m network_sensor.evaluate        # precision / recall report on the official test file

python -m unittest test_network_sensor test_network_sensor_api test_network_sensor_live test_network_sensor_cicids2017 test_network_sensor_actions -v   # automatic checks
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

**Updating from an earlier version?** Train both sensors again once (`train`, then
`evaluate`). Sensors trained before attack types existed still work, but their alerts have no
likely type, priority or next step, and the dashboard says so.

Everything the commands create goes into `data/network_sensor/` (ignored by git):
the datasets, the trained models, and the reports (`reports/evaluation_report.md` / `.json`,
and `reports/cicids2017/` for CIC-IDS2017).

## Use it from the app (API)

Train the sensor first (above), then start the app as usual. Investigators and admins can use:

| Endpoint | What it does |
|---|---|
| `GET /api/v1/network/status` | Is the sensor trained? When? Latest evaluation score. |
| `POST /api/v1/network/scan` | Upload a file of connections (form field `file`); get back the alerts, highest priority first, each with its explanation, likely attack type, priority, certainty and next step, plus counts of all alerts by priority and by type. |
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
  The dashboard can show all alerts, only known attack patterns, only possible new attacks
  (raised only by the anomaly models), or one priority; each of these shows its 300 most
  serious alerts, and says how many the whole file has. The totals are always given.
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

- It is a **replay of recorded traffic**, not a capture of this computer's own network
  (see "Not done: capturing live traffic" below).
- Each alert in the feed shows its priority, likely type and next step; the counters
  include the number of High-priority alerts, and a chart shows the alerts found each second.
- Only the user who started a replay can see or stop it. One replay per user; at most
  3 on the whole server. A replay nobody has checked on for 10 minutes is dropped.
- The start and the end of every replay (completed, stopped, or logged out) go in the
  audit log, with the file's fingerprint, the speed and the number of alerts.
- Replays are kept in the server's memory, so they assume one server process (the
  normal `uvicorn backend.api.main:app`).

### Not done: capturing live traffic

To watch a real network, a flow meter would sit where it can see the traffic (for example a
copy of a switch's traffic), turn packets into connection records, and pass them to the sensor
in batches, the way live mode does with a file. For the CIC-IDS2017 format that tool is
CICFlowMeter, which wrote that dataset's measurements. This is not done here because:

- capturing packets needs administrator rights and permission to watch the network (privacy);
- the measurements must be computed exactly as in the training data, or the models see
  something different (the 2017 CICFlowMeter output already has quirks, such as the
  mislabelled TCP flag columns described in the CIC-IDS2017 report);
- it is a deployment step on UNICC's own network rather than part of the sensor.

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
| `models.py` | the three models, the decision rule, the attack-type classifier, saving and loading |
| `actions.py` | makes alerts actionable: priority rule, certainty, next step, where, counts for the charts |
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

## How this compares with SentinelAI

The UNICC task sheet names [SentinelAI](https://github.com/ayaan-cs/SentinelAI) as an example
tool. This sensor follows its idea (several anomaly models working together, with explanations)
but not its code:

| | SentinelAI (from its README) | This sensor | Why the difference |
|---|---|---|---|
| Models | Isolation Forest, One-Class SVM, DBSCAN | Isolation Forest, One-Class SVM, Random Forest, plus a Random Forest for the attack type | a model trained on labelled attacks recognises known attacks directly |
| Training and test data | synthetic traffic it generates itself (with the Faker library) | public labelled datasets: NSL-KDD and CIC-IDS2017 | the evaluation sheet asks for public ground truth, not synthetic benchmarks |
| Measured precision | none published | 96.7% (NSL-KDD), 96.1% (CIC-IDS2017) | Task 5.0 is scored on precision |
| Explanations | "feature importance" and human-readable insights | up to 3 plain-English reasons per alert, checked to be true | an analyst must be able to trust the reasons |
| Attack type and severity | lists 4 attack types it detects; High / Medium / Low from anomaly-score thresholds | likely type with measured accuracy; High / Medium / Low from what the type can do; certainty shown separately; a next step | priority means "what is at stake" |
| Real time | analyses the flows it generates "as they happen" | replays recorded files at up to 1,000 connections per second | neither captures live traffic (SentinelAI lists it as a future extension) |
| Where it runs | a separate Streamlit dashboard | inside this app, with login, roles and an audit log | |

Both use only free, open-source libraries, so neither has a licence cost.

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
- The likely attack type can only be one of the families in the training data. For a
  possible new attack it is just the closest known family, shown with low certainty.
- The priority rule and the next steps are general first steps written for each attack
  family, not a replacement for UNICC's own incident-response procedures.
