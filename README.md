# N9300-Smart-Switch-as-a-Sensor
# Hypershield Flow Capture & Policy Import Toolchain

Capture live flow data from a Nexus Smart Switch, distill it into a declarative intent table, and create the corresponding resources in Hypershield.

```text
+--------------+    +-------------------+    +---------------+    +---------------------+
| Nexus Switch | -> | flow_collector.py | -> | flow_to_hs.py | -> | import_hs_policy.py |
+--------------+    +-------------------+    +---------------+    +---------------------+
                         (over SSH)          (xlsx + CSVs)          (gRPC to HS)
```

## Setup

Cross-platform (Windows, Linux, macOS). Python 3.10 or later — the tools use `X | None` type syntax, which raises a `TypeError` on import under 3.9.

Dependencies are per tool, so install only what the step needs:

```bash
python -m pip install paramiko    # flow_collector.py, for SSH
python -m pip install openpyxl    # flow_to_hs.py, for the xlsx workbook
```

`import_hs_policy.py` uses only the Python standard library, but it shells out to [`grpcurl`](https://github.com/fullstorydev/grpcurl). Install `grpcurl` and put it on `PATH` before a live import.

### Reaching the gRPC service

`grpcurl` speaks native gRPC and addresses a method at the root of a host and port. It cannot reach a service published under a path prefix. Pass `--srv` the address and port where the intent service itself listens — commonly a NodePort such as `32000` — rather than the management UI address.

If `grpcurl -insecure <host>:<port> list` returns

```text
Failed to list services: rpc error: code = Unavailable desc = upstream connect error
or disconnect/reset before headers. reset reason: protocol error
```

then something is answering on that port but it is not the gRPC service — usually the management ingress. Find the address and port where the service is exposed directly and use that.

---

## 1. `flow_collector.py` — capture flow data

Logs into a Nexus switch over SSH and runs `slot 1 dpu N dpctl show flow` for N=1..4 every X seconds. Writes one timestamped text file per cycle. Handles absent DPUs silently. Auto-reconnects on SSH drop. Ctrl-C finishes the in-flight cycle and exits cleanly.

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

`.\captures\flowcap_2026-05-13T18-45-00Z.txt` per cycle. Feed the whole directory to `flow_to_hs.py`.

---

## 2. `flow_to_hs.py` — build the policy intent

Reads a directory of capture files and applies bidirectional confirmation: a flow is a policy candidate only if it was observed completing in at least one snapshot (initiator + matching responder). Flows that stay one-sided across the entire capture window are evidence of blocked or unanswered traffic and are *not* written into policy.

Identical source-sets and identical port-sets collapse into single rows.

### Usage

```bash
python flow_to_hs.py .\captures -o intent.xlsx --hs-csv-dir .\hs_import
```

The `--hs-csv-dir` flag is optional. Omit it if you only want the xlsx review artifact. When supplied, that directory is **cleared and rebuilt on every run** — each run is a fresh export.

### Output

- `intent.xlsx` — human-readable intent table (Source, Destination, PROTOCOL [PORTS]) plus an "Unconfirmed Flows" sheet listing flows seen attempting but never completing (policy candidates to investigate, not to write).
- `hs_import\network_objects.csv` — one row per unique IP-set
- `hs_import\policies.csv` — one row per (intent_row × port_tag)
- `hs_import\policy_group.csv` — timestamped group metadata emitted by `flow_to_hs.py`; the current gRPC importer does not read this file

---


## Microsoft Entra / OIDC authentication

GA Hypershield / Timescape requires bearer-token authentication for API access.
`import_hs_policy.py` now includes an integrated Microsoft Entra ID login flow
through `hypershield_oauth.py`; a separate token-generator workflow is not
required.

Configure the Entra App Registration with this **Web** redirect URI:

```text
http://localhost:5678/oauth2/callback
```

The deployment documented for this project uses:

- Public client flows enabled.
- Implicit Access Token and ID Token grants disabled.
- A client secret.
- Microsoft Graph delegated `email` and `User.Read` permissions.
- Optional `email` and `groups` claims where required by Hypershield RBAC.
- `groupMembershipClaims` set to `ApplicationGroup` when application-assigned
  groups are used for authorization.

Create a `.env` file in the repository root:

```text
HYPERSHIELD_ISSUER=<tenant-id-or-tenant-domain>
HYPERSHIELD_CLIENT_ID=<application-client-id>
HYPERSHIELD_CLIENT_SECRET=<client-secret>
HYPERSHIELD_REDIRECT_URI=http://localhost:5678/oauth2/callback
HYPERSHIELD_SCOPES=openid profile email
```

Optional settings:

```text
HS_OIDC_PROMPT=select_account
HS_OIDC_EXPECTED_ACCOUNT=user@example.com
HYPERSHIELD_TOKEN_FILE=hs_token.txt
```

On the first live operation, or whenever the cached token is expired, the
importer:

1. Performs OIDC discovery against Microsoft Entra ID.
2. Starts a temporary callback listener on localhost.
3. Opens the Entra sign-in page in the default browser.
4. Uses Authorization Code flow with PKCE.
5. Exchanges the returned authorization code for tokens.
6. Writes the Hypershield bearer token to `hs_token.txt`.
7. Adds `Authorization: Bearer <token>` to subsequent `grpcurl` calls.

Force a fresh login with:

```bash
python import_hs_policy.py --reauth ...
```

For older lab deployments that do not require authentication:

```bash
python import_hs_policy.py --no-auth ...
```

You can also acquire or refresh only the token:

```bash
python hypershield_oauth.py
```

Do not commit `.env`, client secrets, or `hs_token.txt`.

## 3. `import_hs_policy.py` — import resources over gRPC

Reads the network-object and policy CSVs, validates them, and uses `grpcurl` to call `timescape.intent.v1.IntentService/CreateResource`. It creates `isovalent.com/v1alpha1` `NetworkObjectGroup` resources followed by `isovalent.com/v1alpha1` `SmartSwitchNetworkPolicy` resources in the `hypershield` namespace by default.

The importer now acquires a Microsoft Entra/OIDC bearer token through `hypershield_oauth.py` and passes it to `grpcurl` as `Authorization: Bearer <token>`. The token is cached locally and reused while valid. `grpcurl` is still invoked with `-insecure`, matching the existing behavior.

### Validate and dry-run first

Validation alone does not invoke `grpcurl`:

```powershell
python import_hs_policy.py --network-objects .\hs_import\network_objects.csv --policies .\hs_import\policies.csv --validate-only
```

A dry run performs the same validation, prints each `grpcurl` command and its JSON payload, but does not run `grpcurl` or create resources. `--srv` is required, because the rendered command line contains it:

```powershell
python import_hs_policy.py --srv <hypershield-grpc-host:port> --network-objects .\hs_import\network_objects.csv --policies .\hs_import\policies.csv --dry-run
```

### Live run

Pass the gRPC server as `host:port` with `--srv`:

```powershell
python import_hs_policy.py --srv <hypershield-grpc-host:port> --network-objects .\hs_import\network_objects.csv --policies .\hs_import\policies.csv
```

The importer validates all inputs before creating anything. On a successful live create, it records each created resource in a change-list JSON file. By default that file is written under `revert_files` with a timestamped name; use `--change-list <path>` to choose it explicitly.

### Importer options

- `--token-file <path>` — bearer-token cache (default: `hs_token.txt`)
- `--reauth` — force a fresh interactive Entra login
- `--no-auth` — disable Authorization metadata for unauthenticated legacy/lab deployments

- `--srv <host:port>` — gRPC server passed directly to `grpcurl`; required for dry-run commands that render gRPC calls and for live, list, or revert calls
- `--namespace <name>` — resource namespace (default: `hypershield`)
- `--network-objects <path>` — network-object CSV (default: `network_objects.csv`)
- `--policies <path>` — policy CSV; policies are not imported when omitted
- `--change-list <path>` — rollback log. A live import writes one whether or not the flag is given; without it, the file is a timestamped JSON under `revert_files`. A revert reads the same flag, and without it uses the newest file in `revert_files`
- `--dry-run` — print gRPC commands and payloads without invoking `grpcurl`
- `--validate-only` — validate CSV inputs and create no resources
- `--allow-missing-refs` — allow policies whose object references are absent from the loaded network-object CSV; other validation errors still stop the run
- `--limit N` — limit network objects created (and the object set used when validating policy references)
- `--policy-limit N` — limit grouped policies created
- `--skip-network-objects` — validate but do not create network objects
- `--skip-policies` — do not load, validate, or create policies
- `--list` — list `NetworkObjectGroup` resources through `timescape.intent.v1.IntentService/ListResources`
- `--revert` — delete resources from a change-list in reverse order through `timescape.intent.v1.IntentService/DeleteResource`; without `--change-list`, uses the newest JSON file in `revert_files`
- `--stop-on-revert-error` — stop a revert at its first non-not-found error

No output-plan or result JSON option exists. Dry-run output is written to the terminal; the change-list is the live run's local record of created resources.

---

## End-to-end example

```powershell
# 1. Capture for 30 minutes
python flow_collector.py --host 10.3.7.206 --user admin --interval 60 --duration 1800 --output-dir .\captures

# 2. Build the intent workbook and importer CSVs
python flow_to_hs.py .\captures -o intent.xlsx --hs-csv-dir .\hs_import

# 3. Validate locally; no gRPC call is made
python import_hs_policy.py --network-objects .\hs_import\network_objects.csv --policies .\hs_import\policies.csv --validate-only

# 4. Inspect intent.xlsx and the validation output, then preview every gRPC call
python import_hs_policy.py --srv <hypershield-grpc-host:port> --network-objects .\hs_import\network_objects.csv --policies .\hs_import\policies.csv --dry-run

# 5. Create the resources and save an explicit rollback change-list
python import_hs_policy.py --srv <hypershield-grpc-host:port> --network-objects .\hs_import\network_objects.csv --policies .\hs_import\policies.csv --change-list .\revert_files\import.json
```
