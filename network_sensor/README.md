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
| CSE-CIC-IDS2018: **another network**, checked by the CIC-IDS2017 sensor without retraining | 57.0% | **2.5%** | 0.9% |
| CSE-CIC-IDS2018, after **retraining on its own labelled traffic** (`--own-data`, its 30% test part) | 87.7% | **97.5%** | 5.5% |

(From `python -m network_sensor.evaluate`, `python -m network_sensor.cicids2018` and
`python -m network_sensor.train --own-data`, October 2026; the reports explain every number.)

**Read the last two rows before relying on the first two.** The first two test each sensor on
traffic like its training data. On a network it was not trained on, the CIC-IDS2017 sensor stays
quiet but misses almost every attack (see "On another network" below). Retrained on that
network's own labelled traffic, it catches almost every attack; its precision there is held back
by one unreliable label in that dataset (see "Training on your own traffic" below).

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

## On another network: CSE-CIC-IDS2018

The CIC-IDS2017 test part comes from the same recording as its training part (the same
machines, week and attack tools), so 96.1% is optimistic. To see what happens elsewhere, the
CIC-IDS2017 sensor - **not retrained or adjusted** - checked
[CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html): the same lab's next dataset,
recorded a year later on another network, written by the next version of the same flow tool
(CICFlowMeter 4.0, which uses shorter column names; `cicids2018.py` renames them).

Seven of its days (6,622,549 flows: FTP and SSH password guessing, four DoS attacks, two DDoS
attacks, web attacks, infiltration, a botnet) were used. A random sample of 399,117 flows was
checked - 5% of the normal flows and up to 20,000 flows of each attack type per day - and each
sampled flow counted for the flows it stands for, so the numbers estimate checking every flow.

| | CIC-IDS2017 test part (same recording) | CSE-CIC-IDS2018 (another network) |
|---|---|---|
| Precision | 96.1% | 57.0% |
| Attacks caught | 99.4% | 2.5% |
| False alarms on normal traffic | 0.9% | 0.9% |

| Family (2018) | Caught |
|---|---|
| DoS | 7.3% (Slowloris 98.9%, GoldenEye 29.2%, Hulk 5.4%, SlowHTTPTest 0.0%) |
| DDoS (HOIC, LOIC-UDP) | 0.0% |
| Password guessing (FTP 0.0%, SSH 1.1%) | 0.6% |
| Web attacks | 9.7% (362 flows only) |
| Infiltration | 3.5% |
| Botnet | 0.0% |

What the checks show:

- **The column mapping is right.** For Slowloris, which was caught, the 2017 and 2018 flows
  have practically the same measurements (packet counts, sizes, durations).
- **Some 2018 "attacks" never happened on the wire.** Every FTP-BruteForce and DoS-SlowHTTPTest
  flow in these files carries no data in either direction, and the SlowHTTPTest flows went to
  port 21 (FTP), not to a web server. No flow-based sensor can recognise those as the attack.
  Researchers have documented other errors in both datasets (Liu, Engelen et al., *Error
  Prevalence in NIDS datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018*, IEEE CNS 2022).
- **The real attacks look different on another network** (other machines, operating systems
  and tool versions), and the Random Forest only recognises what it was shown: its own alerts
  were still right 98.7% of the time, but it caught 2.4% of the attacks. Published studies that
  train on CIC-IDS2017 and test on CSE-CIC-IDS2018 also find poor results.
- **The normal traffic looks different too:** the One-Class SVM finds 46.6% of the 2018 normal
  flows unusual. The decision rule (both anomaly models must agree) keeps false alarms at 0.9%,
  but those false alarms are why precision falls to 57%.

So the benchmark scores are not what to expect on UNICC's network. The sensor, the explanations
and the dashboard carry over; the trained models do not. Before real use, the sensor must be
retrained (and re-scored) on labelled traffic from the network it watches - one command does
both (see "Training on your own traffic").

Run the check yourself (the CIC-IDS2017 sensor must be trained first): download the
"Processed Traffic Data for ML Algorithms" CSV files you want from the dataset's page into one
folder, then

```powershell
python -m network_sensor.cicids2018 "C:\path\to\folder"
```

The report (`reports/cicids2017/cross_dataset_cicids2018.md` / `.json`) lists every file, the
sample, each attack type, the alerts' likely types and priorities, and which measurements of the
2018 normal traffic differ most from 2017. It takes about two minutes for the seven days.

## Run it (Windows PowerShell, in the project folder)

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements-network-sensor.txt   # once (already installed in most setups)

python -m network_sensor.download_data   # downloads NSL-KDD (~22 MB), checks fingerprints
python -m network_sensor.train           # trains the three models and the attack-type classifier (under a minute)
python -m network_sensor.evaluate        # precision / recall report on the official test file

python -m unittest test_network_sensor test_network_sensor_api test_network_sensor_live test_network_sensor_cicids2017 test_network_sensor_actions test_network_sensor_cicids2018 test_network_sensor_own_data -v   # automatic checks
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
| `POST /api/v1/network/scan/alerts.csv` | The same upload, but the answer is **every** alert as a CSV table for Excel (the dashboard's "Download all alerts (CSV)" button). Text from the file that could act as a spreadsheet formula is made harmless. |
| `POST /api/v1/network/live/start?speed=100` | Start a live replay of an uploaded file at 10, 100 or 1,000 connections per second. |
| `POST /api/v1/network/live/{id}/next` | Check what has "arrived" since the last call (the dashboard calls this once a second). |
| `POST /api/v1/network/live/{id}/stop` | Stop a live replay early. |

- **File formats:** `.csv` with a header row naming the 41 NSL-KDD columns, a raw NSL-KDD
  file with no header (41 values per row, optionally followed by the label and difficulty,
  like `KDDTest+.txt`), a CIC-IDS2017 CSV file, or a CSV file written by CICFlowMeter 4.0
  (as in CSE-CIC-IDS2018: "Dst Port", "Tot Fwd Pkts", ...; renamed to the CIC-IDS2017 names
  and checked by that sensor; its placeholder label, "No Label" or "NeedManualLabel", counts
  as no label).
  Each format is checked by the sensor trained on that dataset; the answer says which one.
  If a label column is present, the answer also says how precise the sensor was on that
  file. Labels are never used to decide.
- **Limits:** 5 MB and 25,000 connections per file; one scan at a time (others get "try again").
  The dashboard can show all alerts, only known attack patterns, only possible new attacks
  (raised only by the anomaly models), or one priority; each of these shows its 300 most
  serious alerts, and says how many the whole file has. The totals are always given, and
  "Download all alerts (CSV)" gives every alert.
- **Audit log:** every scan and every alerts download, including refused files, is recorded
  with the file's name, size and SHA-256 fingerprint and the number of alerts. The file itself
  is not kept (for the download, the browser sends it again).
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
  (see "Scanning your own traffic" below).
- Each alert in the feed shows its priority, likely type and next step; the counters
  include the number of High-priority alerts, and a chart shows the alerts found each second.
- Only the user who started a replay can see or stop it. One replay per user; at most
  3 on the whole server. A replay nobody has checked on for 10 minutes is dropped.
- The start and the end of every replay (completed, stopped, or logged out) go in the
  audit log, with the file's fingerprint, the speed and the number of alerts.
- Replays are kept in the server's memory, so they assume one server process (the
  normal `uvicorn backend.api.main:app`).

### Scanning your own traffic

The sensor does not capture packets itself. To check traffic from a real network:

1. Capture it, for example with Wireshark (this needs administrator rights and permission to
   watch that network), and save it as a `.pcap` file.
2. Turn the capture into flow records with the official
   [CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter) (version 4.0, a Java program),
   which writes a CSV file.
3. Upload that CSV file in the dashboard (scan or live mode).

Two warnings, both measured:

- **Use the official CICFlowMeter.** The Python package of the same name (`pip install
  cicflowmeter`, version 0.5.0) was tried and is not compatible: it gives durations in seconds
  instead of microseconds, counts the first packet of every flow twice, and measures packet
  sizes including their headers. The models would get the wrong numbers.
- **Expect the CIC-IDS2017 sensor to miss most attacks on another network** (see "On another
  network" above) until it is retrained on that network's labelled traffic (next section).

Watching a network continuously would put a flow meter where it sees the traffic (for example
a copy of a switch's traffic) and send its flows to the sensor in batches, as live mode does
with a file. That is a deployment step on UNICC's own network, not part of the sensor.

### Training on your own traffic

The sensor for CICFlowMeter files can learn your own network instead of CIC-IDS2017. The format
stays the same (CICFlowMeter's measurements, under the CIC-IDS2017 names); what changes is what
it has learned normal traffic and attacks look like. It needs **labelled** flows from that
network: CICFlowMeter writes `No Label` in the `Label` column, so replace it for every flow -
`Benign` (or `Normal`) for normal traffic, an attack name for attacks, for example from the times
and machines of a penetration test. Attack names it knows, so alerts get a likely type, priority
and next step: the CIC-IDS2017 and CSE-CIC-IDS2018 names (`SSH-Patator`, `DoS attacks-Hulk`, ...)
or a family (`DoS`, `DDoS`, `PortScan`, `Brute Force`, `Web Attack`, `Botnet`, `Infiltration`,
`Heartbleed`). Put the CSV files in one folder, then on the server:

```powershell
python -m network_sensor.train --own-data "C:\path\to\folder"
```

It refuses flows without a label, and files without normal traffic or without any attack name it
knows. It splits the flows 70% / 30% like CIC-IDS2017, trains the same four models on the 70%,
and scores them on the 30%. **Only if precision reaches the 90% target** does the new sensor
replace the one the app uses (the app picks it up by itself); the old one is kept as
`models/sensor_model_cicids2017.previous.joblib`. Below the target nothing changes, unless you
add `--accept-below-target`. The report (`reports/cicids2017/own_data_training.md` / `.json`)
gives the results per attack name and lists the files with their SHA-256 fingerprints, which are
also stored in the model. The dashboard then says the sensor was trained "from your own labelled
files" and shows the result on their test part. To go back to the public sensor:
`python -m network_sensor.train --dataset cicids2017`.

There is deliberately no training button in the web app: whoever picks the training files
decides what the sensor learns (see "Security notes").

**Checked on real data** (October 2026), treating the seven CSE-CIC-IDS2018 days above
(6,622,549 flows) as "your own network": `--own-data` on that folder trained on 671,452 sampled
flows of the 70% and checked 223,729 flows of the 30% test part (about 12 minutes on a 2-core
machine, at most 3.4 GB of memory). It caught **97.5%** of the attacks (2.5% without retraining),
with false alarms on 5.5% of the normal traffic, so precision was **87.7% - below the target, and
the command did not install it**. Almost all of its false alarms (99.7%) were taken for
Infiltration, and 4,203 normal flows in the sample have exactly the same measurements as flows
labelled Infiltration: in these files that label also covers ordinary-looking traffic. Trained
and tested the same way without the Infiltration flows, it reaches 97.3% precision, catching
99.9% of the attacks with false alarms on 1.0%. This is what the 90% check is for: when labels
do not match the traffic, the old sensor stays in place until the labels are fixed.

In Docker with `docker-compose.yml`, run the command on the host as above (the app uses the
project's `data/` folder). With `deployment/api` or `deployment/onprem`, copy the folder into the
container first, for example
`docker compose -f deployment/api/docker-compose.yml cp own-flows backend:/tmp/own-flows`, then
`docker compose -f deployment/api/docker-compose.yml exec backend python -m network_sensor.train --own-data /tmp/own-flows`.

## Run it in Docker

The backend image (`deployment/docker/Dockerfile.backend`) includes the sensor. It uses
Python 3.13 because the sensor's pinned packages need Python 3.12 or newer.

- **`docker-compose.yml`** in the project folder: the backend uses the project's `data/`
  folder, so a sensor trained on the host (`python -m network_sensor.train`) is used as it is.
  The login accounts and the audit log are kept there too (`data/app.db`), so they survive
  `docker compose down` and rebuilds; the passwords are shown only on the very first start.
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
| `cicids2018.py` | CICFlowMeter 4.0 / CSE-CIC-IDS2018 files: renames their columns and attack names; the check on another network |
| `features.py` | checks input (no missing columns, text in number columns, impossible values) and converts it to model inputs |
| `models.py` | the three models, the decision rule, the attack-type classifier, saving and loading |
| `actions.py` | makes alerts actionable: priority rule, certainty, next step, where, counts for the charts |
| `explain.py` | the normal-traffic profile and the plain-English reason for each alert |
| `train.py` | trains on a dataset's training part and saves the model; with `--own-data`, on your own labelled files |
| `own_data.py` | training on your own labelled CICFlowMeter files: checks the labels, splits, trains, tests, installs only above the target |
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
- Whoever chooses the training files decides what the sensor learns: wrongly labelled flows
  (by mistake or on purpose, "data poisoning") teach it to ignore those attacks. So training is
  only a command on the server, never a button in the web app; a sensor trained on your own
  files replaces the current one only if it reaches the 90% precision target on their test part;
  and the files' fingerprints are recorded in the model and the report.

## How this compares with SentinelAI

The UNICC task sheet names [SentinelAI](https://github.com/ayaan-cs/SentinelAI) as an example
tool. This sensor follows its idea (several anomaly models working together, with explanations)
but not its code:

| | SentinelAI (from its README) | This sensor | Why the difference |
|---|---|---|---|
| Models | Isolation Forest, One-Class SVM, DBSCAN | Isolation Forest, One-Class SVM, Random Forest, plus a Random Forest for the attack type | a model trained on labelled attacks recognises known attacks directly |
| Training and test data | synthetic traffic it generates itself (with the Faker library) | public labelled datasets: NSL-KDD and CIC-IDS2017 | the evaluation sheet asks for public ground truth, not synthetic benchmarks |
| Measured precision | none published | 96.7% (NSL-KDD), 96.1% (CIC-IDS2017); on another network (CSE-CIC-IDS2018) 57.0%, catching 2.5% of attacks | Task 5.0 is scored on precision; the last number shows the models must be retrained for a new network |
| Explanations | "feature importance" and human-readable insights | up to 3 plain-English reasons per alert, checked to be true | an analyst must be able to trust the reasons |
| Attack type and severity | lists 4 attack types it detects; High / Medium / Low from anomaly-score thresholds | likely type with measured accuracy; High / Medium / Low from what the type can do; certainty shown separately; a next step | priority means "what is at stake" |
| Real time | analyses the flows it generates "as they happen" | replays recorded files at up to 1,000 connections per second | neither captures live traffic (SentinelAI lists it as a future extension) |
| Where it runs | a separate Streamlit dashboard | inside this app, with login, roles and an audit log | |

Both use only free, open-source libraries, so neither has a licence cost.

## Known limitations

- NSL-KDD comes from 1998 traffic; CIC-IDS2017 from a 2017 test network. On another network
  (CSE-CIC-IDS2018) the CIC-IDS2017 sensor caught only 2.5% of the attacks: the trained models
  do not carry over, and must be retrained on the network the sensor watches (`--own-data`).
  That needs labelled traffic from that network - in practice, normal traffic plus the attacks
  of a penetration test whose times and machines are known.
- The sensor does not capture packets itself: flow records come from files (live mode replays
  them). The official CICFlowMeter can make them from a packet capture (see "Scanning your
  own traffic").
- On NSL-KDD, remote-access attacks (R2L, e.g. password guessing) are mostly missed, because
  its training file has very few examples of them. The evaluation reports show results per family.
- CIC-IDS2017 has no official training/test split, and researchers have found some wrong
  labels in it; its report explains how the split was made and what that means.
- The likely attack type can only be one of the families in the training data. For a
  possible new attack it is just the closest known family, shown with low certainty.
- The priority rule and the next steps are general first steps written for each attack
  family, not a replacement for UNICC's own incident-response procedures.
