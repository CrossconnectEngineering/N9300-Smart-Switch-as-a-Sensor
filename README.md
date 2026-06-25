# N9300-Smart-Switch-as-a-Sensor
# Hypershield Flow Capture & Policy Import Toolchain

Capture live flow data from a Nexus Smart Switch, distill it into a declarative intent table, and push the result into Hypershield as a draft policy group.

```text
┌──────────────┐    ┌──────────────────┐    ┌─────────────────────┐    ┌────────────────────────┐
│ Nexus Switch │ →  │ flow_collector.py│ →  │ flow_to_hs.py       │ →  │ import_hs_policy_csv.py│ →  HS draft policy
└──────────────┘    └──────────────────┘    └─────────────────────┘    └────────────────────────┘
                          (over SSH)         (intent.xlsx + CSVs)            (gRPC to HS)
```

## Setup

Cross-platform (Windows, Linux, macOS). Python 3.9+.

```bash
python -m pip install paramiko openpyxl
```

The third script (`import_hs_policy_csv.py`) uses only the Python standard
library — no extra installs.

---

## 1. `flow_collector.py` — capture flow data

Logs into a Nexus switch over SSH and runs `slot 1 dpu N dpctl show flow`
for N=1..4 every X seconds. Writes one timestamped text file per cycle.
Handles absent DPUs silently. Auto-reconnects on SSH drop. Ctrl-C finishes
the in-flight cycle and exits cleanly.

### Usage

```bash
python flow_collector.py --host 10.3.7.206 --user admin --interval 60 --output-dir .\captures
```

Prompts for the password, or set `NXOS_PASSWORD` env var to skip the prompt.

### Useful flags

- `--interval 60` — seconds between cycle starts (default 60)
- `--duration 1800` — auto-stop after N seconds (default: run until Ctrl-C)
- `--max-dpus 4` — highest DPU number to query (default 4)

### Output

`.\captures\flowcap_2026-05-13T18-45-00Z.txt` per cycle. Feed the whole
directory to `flow_to_hs.py`.

---

## 2. `flow_to_hs.py` — build the policy intent

Reads a directory of capture files and applies bidirectional confirmation:
a flow is a policy candidate only if it was observed completing in at least
one snapshot (initiator + matching responder). Flows that stay one-sided
across the entire capture window are evidence of blocked or unanswered
traffic and are *not* written into policy.

Identical source-sets and identical port-sets collapse into single rows.

### Usage

```bash
python flow_to_hs.py .\captures -o intent.xlsx --hs-csv-dir .\hs_import
```

The `--hs-csv-dir` flag is optional. Omit it if you only want the xlsx review
artifact. When supplied, that directory is **cleared and rebuilt on every
run** — each run is a fresh draft.

### Output

- `intent.xlsx` — human-readable intent table (Source, Destination,
  PROTOCOL [PORTS]) plus an "Unconfirmed Flows" sheet listing flows seen
  attempting but never completing (policy candidates to investigate, not
  to write).
- `hs_import\network_objects.csv` — one row per unique IP-set
- `hs_import\policies.csv` — one row per (intent_row × port_tag)
- `hs_import\policy_group.csv` — timestamped draft group name

---

## 3. `import_hs_policy_csv.py` — upload to Hypershield

Creates the network objects, creates a draft policy group, and stages every
policy into that group. **Does not deploy** — you review and push in the
Hypershield UI when ready.

### Dry run first

```bash
python import_hs_policy_csv.py --objects-csv .\hs_import\network_objects.csv --policies-csv .\hs_import\policies.csv --policy-group-csv .\hs_import\policy_group.csv --dry-run --output-json plan.json
```

Logs every API call it *would* make to `plan.json` without sending anything.
Inspect `plan.json` and `intent.xlsx`; both should make sense before you go live.

### Live run

Set the Hypershield MP API URL and access token, then run the same command without `--dry-run`:

```powershell
$env:HS_MP_API_URL = "https://<your-hs-mp-host>/api"
$env:HS_ACCESS_TOKEN = "<your-token>"

python import_hs_policy_csv.py --objects-csv .\hs_import\network_objects.csv --policies-csv .\hs_import\policies.csv --policy-group-csv .\hs_import\policy_group.csv --output-json result.json
```

`HS_MP_API_URL` ends in `/api`.
`HS_ACCESS_TOKEN` is an API token with permission to edit Hypershield policy.

---

## End-to-end example

```powershell
# 1. Capture for 30 minutes
python flow_collector.py --host 10.3.7.206 --user admin --interval 60 --duration 1800 --output-dir .\captures

# 2. Build intent table + HS CSVs
python flow_to_hs.py .\captures -o intent.xlsx --hs-csv-dir .\hs_import

# 3. Dry-run the upload
python import_hs_policy_csv.py --objects-csv .\hs_import\network_objects.csv --policies-csv .\hs_import\policies.csv --policy-group-csv .\hs_import\policy_group.csv --dry-run --output-json plan.json

# 4. Inspect intent.xlsx and plan.json. Look for surprises.

# 5. Live push to Hypershield creates draft, does NOT deploy
$env:HS_MP_API_URL = "https://<your-hs-mp-host>/api"
$env:HS_ACCESS_TOKEN = "<your-token>"

python import_hs_policy_csv.py --objects-csv .\hs_import\network_objects.csv --policies-csv .\hs_import\policies.csv --policy-group-csv .\hs_import\policy_group.csv --output-json result.json

# 6. Review and deploy the draft in the Hypershield UI.
```
