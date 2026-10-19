# Network Security AI Sensor (Task 5.0, Team 4)

Flags network connections that look like attacks, using three machine-learning models
that check each other, and measures how precise it is on a public labelled dataset.

| Model | Learns from | Good at |
|---|---|---|
| Isolation Forest | normal traffic only | spotting anything unusual |
| One-Class SVM | normal traffic only | the same, built differently, so it makes different mistakes |
| Random Forest | labelled normal **and** attack traffic | attack types it has seen before |

**Decision rule:** a connection is an attack if the Random Forest says so, **or** if both
normal-only models agree it is abnormal. The second part catches new kinds of attack.

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
SentinelAI trains on made-up traffic; this sensor is trained and scored on the public
**NSL-KDD** benchmark, as the evaluation sheet asks for public ground truth.

## Run it (Windows PowerShell, in the project folder)

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements-network-sensor.txt   # once (already installed in most setups)

python -m network_sensor.download_data   # downloads NSL-KDD (~22 MB), checks fingerprints
python -m network_sensor.train           # trains the three models (under a minute)
python -m network_sensor.evaluate        # precision / recall report on the official test file

python -m unittest test_network_sensor test_network_sensor_api -v   # automatic checks
```

Everything the commands create goes into `data/network_sensor/` (ignored by git):
the dataset, the trained model, and `reports/evaluation_report.md` / `.json`.

## Use it from the app (API)

Train the sensor first (above), then start the app as usual. Investigators and admins can use:

| Endpoint | What it does |
|---|---|
| `GET /api/v1/network/status` | Is the sensor trained? When? Latest evaluation score. |
| `POST /api/v1/network/scan` | Upload a file of connections (form field `file`); get back the alerts, most serious first, each with its explanation. |

- **File formats:** `.csv` with a header row naming the 41 NSL-KDD columns, or a raw NSL-KDD
  file with no header (41 values per row, optionally followed by the label and difficulty,
  like `KDDTest+.txt`). If a `label` column is present, the answer also says how precise the
  sensor was on that file. Labels are never used to decide.
- **Limits:** 5 MB and 25,000 connections per file; one scan at a time (others get "try again").
  The 300 most serious alerts of each kind are returned (known attack patterns, and possible
  new attacks raised only by the anomaly models); the totals are always given.
- **Audit log:** every scan, including refused files, is recorded with the file's name,
  size and SHA-256 fingerprint and the number of alerts. The file itself is not kept.
- If scikit-learn is not installed on the server, the rest of the app still works and
  these endpoints say how to install the sensor.
- Retraining is picked up automatically, without restarting the app.

## Files

| File | What it does |
|---|---|
| `download_data.py` | downloads NSL-KDD and refuses files whose SHA-256 fingerprint does not match |
| `datasets.py` | reads the files; adds `is_attack` and the attack family (DoS, Probe, R2L, U2R) |
| `features.py` | checks input (no missing columns, text in number columns, or negative values) and converts it to model inputs |
| `models.py` | the three models, the decision rule, saving and loading |
| `explain.py` | the normal-traffic profile and the plain-English reason for each alert |
| `train.py` | trains on `KDDTrain+.txt` and saves the model |
| `evaluate.py` | scores the model on `KDDTest+.txt`, checks the explanations, writes the report |
| `service.py` | used by the web app: reads uploaded files, runs scans, reports status |
| `paths.py` | where files are kept |

## Security notes

- Trained model files are Python pickles: **opening one can run code hidden inside it**.
  Only load model files you trained yourself; never commit them or accept them from others.
- Downloaded data is checked against fixed SHA-256 fingerprints before it is used.

## Known limitations

- NSL-KDD comes from 1998 traffic. A newer dataset (CIC-IDS2017) is planned.
- The 41 measurements come with the dataset; the sensor does not yet compute them from
  live traffic.
- Remote-access attacks (R2L, e.g. password guessing) are mostly missed, because the
  training file has very few examples of them. The evaluation report shows this per family.
