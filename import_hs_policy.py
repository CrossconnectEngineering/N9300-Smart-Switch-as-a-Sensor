#!/usr/bin/env python3

import argparse
import csv
import json
import re
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Any


DEFAULT_NAMESPACE = "hypershield"
DEFAULT_SRV = None
DEFAULT_REVERT_DIR = "revert_files"

NETWORK_OBJECT_GVK = {
    "group": "isovalent.com",
    "version": "v1alpha1",
    "kind": "NetworkObjectGroup",
}

POLICY_GVK = {
    "group": "isovalent.com",
    "version": "v1alpha1",
    "kind": "SmartSwitchNetworkPolicy",
}

CREATE_RESOURCE_METHOD = "timescape.intent.v1.IntentService/CreateResource"
DELETE_RESOURCE_METHOD = "timescape.intent.v1.IntentService/DeleteResource"
LIST_RESOURCES_METHOD = "timescape.intent.v1.IntentService/ListResources"

SUPPORTED_POLICY_PROTOCOLS = {"tcp", "udp", "icmp"}
DENY_EFFECTS = {"deny", "drop", "block", "forbid"}
ALLOW_EFFECTS = {"permit", "allow"}
PORT_RANGE_RE = re.compile(r"^(\d+)(?:-(\d+))?$")

NETWORK_OBJECT_YAML_TEMPLATE = Template("""apiVersion: isovalent.com/v1alpha1
kind: NetworkObjectGroup
metadata:
  name: $name
  namespace: $namespace
spec:
  cidrs:
$cidrs_yaml
  description: "$description"
  virtualNetwork:
    vrfs:
$vrfs_yaml
""")


POLICY_YAML_TEMPLATE = Template("""apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: $name
  namespace: $namespace
spec:
  rules:
    - action: $action
      source:
        networkRef:
$source_network_ref_yaml
      destination:
        networkRef:
$destination_network_ref_yaml$proto_ports_block
""")


def grpcurl_call(
    srv: str,
    method: str,
    payload: dict[str, Any],
    dry_run: bool = False,
) -> dict[str, Any]:
    payload_json = json.dumps(payload)

    cmd = [
        "grpcurl",
        "-insecure",
        "-d",
        "@",
        srv,
        method,
    ]

    if dry_run:
        print("\n# DRY RUN grpcurl command:")
        print(" ".join(cmd))
        print(f"# Payload bytes: {len(payload_json.encode('utf-8'))}")
        if len(payload_json) <= 20000:
            print(json.dumps(payload, indent=2))
        else:
            print("# Payload omitted because it is very large.")
        return {}

    result = subprocess.run(
        cmd,
        input=payload_json,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"grpcurl failed\n"
            f"method: {method}\n"
            f"payload:\n{json.dumps(payload, indent=2)}\n\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    if not result.stdout.strip():
        return {}

    return json.loads(result.stdout)


def split_values(value: str) -> list[str]:
    """
    Allows addresses/vrfs to be represented as:
      10.1.1.0/24
      10.1.1.0/24;10.1.2.0/24
      10.1.1.0/24|10.1.2.0/24
    """
    value = (value or "").strip()

    if not value:
        return []

    for separator in (";", "|"):
        if separator in value:
            return [item.strip() for item in value.split(separator) if item.strip()]

    return [value]


def yaml_list(items: list[str], indent: int = 4) -> str:
    spaces = " " * indent
    return "\n".join(f"{spaces}- {item}" for item in items)


def yaml_name_refs(names: list[str], indent: int = 10) -> str:
    spaces = " " * indent
    return "\n".join(f"{spaces}- name: {name}" for name in names)


def yaml_proto_ports(proto_ports: list[dict[str, Any]], indent: int = 10) -> str:
    spaces = " " * indent
    lines: list[str] = []

    for proto_port in proto_ports:
        lines.append(f"{spaces}- protocol: {proto_port['protocol']}")
        if proto_port.get("port") is not None:
            lines.append(f"{spaces}  port: {proto_port['port']}")

    return "\n".join(lines)


def k8s_name(value: str) -> str:
    """
    Convert source names like:
      OBJ_default_10_10_33_0_29
    into RFC 1123-compatible Kubernetes names:
      obj-default-10-10-33-0-29
    """
    name = value.strip().lower()
    name = re.sub(r"[^a-z0-9.-]+", "-", name)
    name = re.sub(r"-+", "-", name)
    name = re.sub(r"\.+", ".", name)
    name = name.strip("-.")

    if not name:
        raise ValueError(f"Could not normalize invalid Kubernetes name from {value!r}")

    if len(name) > 253:
        name = name[:253].rstrip("-.")

    return name


def sanitize_description(value: str) -> str:
    """
    Keep the simple YAML template safe from unescaped quotes.
    """
    return (value or "").replace('"', '\\"')


def parse_destination_ports(value: str) -> list[int] | None:
    """
    Return validated destination port integers.

    Blank means protocol-wide/all ports, so the protoPort entry should omit port.
    Accepted examples:
      443 -> [443]
      6400-6403 -> [6400, 6401, 6402, 6403]
    """
    value = (value or "").strip()

    if not value:
        return None

    match = PORT_RANGE_RE.match(value)
    if not match:
        raise ValueError(f"Invalid destination_port {value!r}")

    start = int(match.group(1))
    end = int(match.group(2) or match.group(1))

    if start < 1 or end > 65535 or start > end:
        raise ValueError(f"Invalid destination_port range {value!r}")

    return list(range(start, end + 1))


def is_valid_destination_port(value: str) -> bool:
    try:
        parse_destination_ports(value)
    except ValueError:
        return False
    return True


def effect_to_action(effect: str) -> str | None:
    normalized = (effect or "").strip().lower()

    if normalized in ALLOW_EFFECTS:
        return "allow"

    if normalized in DENY_EFFECTS:
        return "deny"

    return None


def load_change_list(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Change-list file does not exist: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"Change-list must be a JSON list: {path}")

    return data


def default_timestamped_change_list() -> Path:
    revert_dir = Path(DEFAULT_REVERT_DIR)
    revert_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now()
    timestamp = f"{now.month}_{now.day}_{now.strftime('%y')}_{now.strftime('%H%M')}"
    return revert_dir / f"{timestamp}.json"


def save_change_list(path: Path, changes: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")

    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(changes, f, indent=2)

    tmp_path.replace(path)


def append_change(path: Path, change: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        changes = load_change_list(path)
    else:
        changes = []

    changes.append(change)
    save_change_list(path, changes)


def record_created_resource(
    change_list_path: Path,
    gvk: dict[str, str],
    name: str,
    namespace: str,
    source_name: str | None = None,
) -> None:
    append_change(
        change_list_path,
        {
            "action": "created",
            "gvk": gvk,
            "namespace": namespace,
            "name": name,
            "source_name": source_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


def build_network_object_yaml(
    name: str,
    addresses: list[str],
    vrfs: list[str],
    description: str = "",
    namespace: str = DEFAULT_NAMESPACE,
) -> str:
    if not name:
        raise ValueError("Network object missing name")

    if not addresses:
        raise ValueError(f"Network object {name} has no addresses")

    if not vrfs:
        vrfs = ["default"]

    return NETWORK_OBJECT_YAML_TEMPLATE.substitute(
        name=name,
        namespace=namespace,
        cidrs_yaml=yaml_list(addresses, indent=4),
        description=sanitize_description(description),
        vrfs_yaml=yaml_list(vrfs, indent=6),
    )


def build_policy_yaml(
    name: str,
    action: str,
    source_refs: list[str],
    destination_refs: list[str],
    proto_ports: list[dict[str, Any]],
    namespace: str = DEFAULT_NAMESPACE,
) -> str:
    if not name:
        raise ValueError("Policy missing name")

    if not source_refs:
        raise ValueError(f"Policy {name} has no source network refs")

    if not destination_refs:
        raise ValueError(f"Policy {name} has no destination network refs")

    proto_ports_block = ""
    if proto_ports:
        proto_ports_block = "\n        protoPorts:\n" + yaml_proto_ports(proto_ports, indent=10)

    return POLICY_YAML_TEMPLATE.substitute(
        name=name,
        namespace=namespace,
        action=action,
        source_network_ref_yaml=yaml_name_refs(source_refs, indent=10),
        destination_network_ref_yaml=yaml_name_refs(destination_refs, indent=10),
        proto_ports_block=proto_ports_block,
    )


def create_yaml_resource(
    srv: str,
    object_yaml: str,
    dry_run: bool = False,
) -> dict[str, Any]:
    payload = {
        "object": {
            "yaml": object_yaml,
        }
    }

    return grpcurl_call(
        srv=srv,
        method=CREATE_RESOURCE_METHOD,
        payload=payload,
        dry_run=dry_run,
    )


def create_network_object(
    srv: str,
    name: str,
    addresses: list[str],
    vrfs: list[str],
    description: str = "",
    namespace: str = DEFAULT_NAMESPACE,
    dry_run: bool = False,
) -> dict[str, Any]:
    object_yaml = build_network_object_yaml(
        name=name,
        addresses=addresses,
        vrfs=vrfs,
        description=description,
        namespace=namespace,
    )

    return create_yaml_resource(
        srv=srv,
        object_yaml=object_yaml,
        dry_run=dry_run,
    )


def create_policy(
    srv: str,
    name: str,
    action: str,
    source_refs: list[str],
    destination_refs: list[str],
    proto_ports: list[dict[str, Any]],
    namespace: str = DEFAULT_NAMESPACE,
    dry_run: bool = False,
) -> dict[str, Any]:
    object_yaml = build_policy_yaml(
        name=name,
        action=action,
        source_refs=source_refs,
        destination_refs=destination_refs,
        proto_ports=proto_ports,
        namespace=namespace,
    )

    return create_yaml_resource(
        srv=srv,
        object_yaml=object_yaml,
        dry_run=dry_run,
    )


def delete_resource(
    srv: str,
    gvk: dict[str, str],
    name: str,
    namespace: str = DEFAULT_NAMESPACE,
    dry_run: bool = False,
) -> dict[str, Any]:
    payload = {
        "gvk": gvk,
        "namespace": namespace,
        "name": name,
    }

    return grpcurl_call(
        srv=srv,
        method=DELETE_RESOURCE_METHOD,
        payload=payload,
        dry_run=dry_run,
    )


def list_resources(
    srv: str,
    gvk: dict[str, str],
    namespace: str = DEFAULT_NAMESPACE,
    page_size: int = 500,
    dry_run: bool = False,
) -> dict[str, Any]:
    payload = {
        "gvk": gvk,
        "namespace": namespace,
        "pageSize": page_size,
    }

    return grpcurl_call(
        srv=srv,
        method=LIST_RESOURCES_METHOD,
        payload=payload,
        dry_run=dry_run,
    )


def list_network_objects(
    srv: str,
    namespace: str = DEFAULT_NAMESPACE,
    page_size: int = 500,
    dry_run: bool = False,
) -> dict[str, Any]:
    return list_resources(
        srv=srv,
        gvk=NETWORK_OBJECT_GVK,
        namespace=namespace,
        page_size=page_size,
        dry_run=dry_run,
    )


def load_network_objects_csv(path: Path) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []

    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)

        required = {"name", "addresses", "vrf"}
        missing = required - set(reader.fieldnames or [])

        if missing:
            raise ValueError(f"{path} missing required columns: {sorted(missing)}")

        for line_number, row in enumerate(reader, start=2):
            source_name = (row.get("name") or "").strip()
            name = k8s_name(source_name)
            description = row.get("description") or ""
            addresses = split_values(row.get("addresses") or "")
            vrfs = split_values(row.get("vrf") or "default")
            object_type = (row.get("object_type") or "").strip().upper()

            if object_type and object_type != "NETWORK":
                print(f"Skipping line {line_number}: unsupported object_type={object_type!r}")
                continue

            objects.append(
                {
                    "line_number": line_number,
                    "source_name": source_name,
                    "name": name,
                    "description": description,
                    "addresses": addresses,
                    "vrfs": vrfs,
                }
            )

    return objects


def load_policies_csv(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)

        required = {
            "policy_key",
            "name",
            "effect",
            "source_object",
            "destination_object",
            "protocol",
            "destination_port",
        }
        missing = required - set(reader.fieldnames or [])

        if missing:
            raise ValueError(f"{path} missing required columns: {sorted(missing)}")

        for line_number, row in enumerate(reader, start=2):
            policy_key = (row.get("policy_key") or "").strip()
            source_name = (row.get("name") or policy_key).strip()
            group_key = policy_key or source_name
            protocol = (row.get("protocol") or "").strip().lower()
            destination_port = (row.get("destination_port") or "").strip()
            source_object = (row.get("source_object") or "").strip()
            destination_object = (row.get("destination_object") or "").strip()

            rows.append(
                {
                    "line_number": line_number,
                    "policy_key": policy_key,
                    "source_name": source_name,
                    "group_key": group_key,
                    "name": k8s_name(source_name),
                    "description": row.get("description") or "",
                    "effect": (row.get("effect") or "").strip(),
                    "action": effect_to_action(row.get("effect") or ""),
                    "source_object": source_object,
                    "source_ref": k8s_name(source_object),
                    "destination_object": destination_object,
                    "destination_ref": k8s_name(destination_object),
                    "protocol": protocol,
                    "destination_port": destination_port,
                }
            )

    return rows


def group_policy_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped_rows[row["group_key"]].append(row)

    policies: list[dict[str, Any]] = []

    for group_key, group in grouped_rows.items():
        first = group[0]
        source_refs = sorted({row["source_ref"] for row in group})
        destination_refs = sorted({row["destination_ref"] for row in group})
        proto_port_keys: set[tuple[str, int | None]] = set()
        proto_ports: list[dict[str, Any]] = []

        for row in group:
            protocol_upper = row["protocol"].upper()

            if row["protocol"] == "icmp":
                ports: list[int] | None = None
            else:
                ports = parse_destination_ports(row["destination_port"])

            if ports is None:
                key = (protocol_upper, None)
                if key not in proto_port_keys:
                    proto_port_keys.add(key)
                    proto_ports.append({"protocol": protocol_upper})
                continue

            for port in ports:
                key = (protocol_upper, port)
                if key in proto_port_keys:
                    continue

                proto_port_keys.add(key)
                proto_ports.append(
                    {
                        "protocol": protocol_upper,
                        "port": port,
                    }
                )

        policies.append(
            {
                "line_numbers": [row["line_number"] for row in group],
                "first_line_number": first["line_number"],
                "group_key": group_key,
                "source_name": first["source_name"],
                "name": first["name"],
                "description": first["description"],
                "action": first["action"],
                "source_refs": source_refs,
                "destination_refs": destination_refs,
                "proto_ports": proto_ports,
                "row_count": len(group),
                "deduped_proto_port_count": len(proto_ports),
            }
        )

    return policies


def find_duplicate_names(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for item in items:
        by_name[item["name"]].append(item)

    return {name: grouped for name, grouped in by_name.items() if len(grouped) > 1}


def validate_import_inputs(
    network_objects: list[dict[str, Any]],
    policy_rows: list[dict[str, Any]],
    grouped_policies: list[dict[str, Any]],
    network_objects_path: Path,
    policies_path: Path | None,
) -> list[str]:
    errors: list[str] = []

    print(f"Loaded {len(network_objects)} network objects from {network_objects_path}")
    if policies_path is not None:
        print(f"Loaded {len(grouped_policies)} grouped policies from {policies_path}")

    duplicate_objects = find_duplicate_names(network_objects)
    if duplicate_objects:
        errors.append(f"Found {len(duplicate_objects)} duplicate normalized network object names")
        print("\nDuplicate normalized network object names:")
        for name, objects in duplicate_objects.items():
            lines = ", ".join(str(obj["line_number"]) for obj in objects)
            print(f"  {name}: CSV lines {lines}")

    duplicate_policies = find_duplicate_names(grouped_policies)
    if duplicate_policies:
        errors.append(f"Found {len(duplicate_policies)} duplicate normalized policy names")
        print("\nDuplicate normalized policy names:")
        for name, policies in duplicate_policies.items():
            lines = ", ".join(str(policy["first_line_number"]) for policy in policies)
            print(f"  {name}: grouped policy first CSV lines {lines}")

    network_object_names = {obj["name"] for obj in network_objects}
    missing_source_refs = [
        row for row in policy_rows if row["source_ref"] not in network_object_names
    ]
    missing_destination_refs = [
        row for row in policy_rows if row["destination_ref"] not in network_object_names
    ]

    invalid_port_rows: list[dict[str, Any]] = []
    blank_port_rows: list[dict[str, Any]] = []
    invalid_protocol_rows: list[dict[str, Any]] = []
    invalid_effect_rows: list[dict[str, Any]] = []
    inconsistent_group_rows: list[tuple[str, str, list[Any]]] = []

    for row in policy_rows:
        protocol = row["protocol"]
        destination_port = row["destination_port"]

        if row["action"] is None:
            invalid_effect_rows.append(row)

        if protocol not in SUPPORTED_POLICY_PROTOCOLS:
            invalid_protocol_rows.append(row)

        if protocol != "icmp":
            if not destination_port:
                blank_port_rows.append(row)
            elif not is_valid_destination_port(destination_port):
                invalid_port_rows.append(row)

    rows_by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in policy_rows:
        rows_by_group[row["group_key"]].append(row)

    for group_key, rows in rows_by_group.items():
        for field in ("name", "action", "source_ref", "destination_ref"):
            values = sorted({row[field] for row in rows})
            if len(values) > 1:
                inconsistent_group_rows.append((group_key, field, values))

    print(f"Missing source objects: {len(missing_source_refs)}")
    print(f"Missing destination objects: {len(missing_destination_refs)}")

    if missing_source_refs:
        errors.append(f"Found {len(missing_source_refs)} missing policy source object references")
        print("\nMissing source references:")
        for row in missing_source_refs:
            print(
                f"  CSV policy line {row['line_number']}: "
                f"{row['source_object']} -> {row['source_ref']}"
            )

    if missing_destination_refs:
        errors.append(f"Found {len(missing_destination_refs)} missing policy destination object references")
        print("\nMissing destination references:")
        for row in missing_destination_refs:
            print(
                f"  CSV policy line {row['line_number']}: "
                f"{row['destination_object']} -> {row['destination_ref']}"
            )

    if blank_port_rows:
        print("\nNon-ICMP rows with blank destination_port will be treated as all ports:")
        for row in blank_port_rows:
            print(f"  CSV policy line {row['line_number']}: protocol={row['protocol']!r}")

    if invalid_port_rows:
        errors.append(f"Found {len(invalid_port_rows)} policy rows with invalid destination_port")
        print("\nRows with invalid destination_port:")
        for row in invalid_port_rows:
            print(
                f"  CSV policy line {row['line_number']}: "
                f"protocol={row['protocol']!r}, destination_port={row['destination_port']!r}"
            )

    if invalid_protocol_rows:
        errors.append(f"Found {len(invalid_protocol_rows)} policy rows with unsupported protocol")
        print("\nRows with unsupported protocol:")
        for row in invalid_protocol_rows:
            print(
                f"  CSV policy line {row['line_number']}: "
                f"protocol={row['protocol']!r}; supported={sorted(SUPPORTED_POLICY_PROTOCOLS)}"
            )

    if invalid_effect_rows:
        errors.append(f"Found {len(invalid_effect_rows)} policy rows with unsupported effect")
        print("\nRows with unsupported effect:")
        for row in invalid_effect_rows:
            print(
                f"  CSV policy line {row['line_number']}: "
                f"effect={row['effect']!r}; supported={sorted(ALLOW_EFFECTS | DENY_EFFECTS)}"
            )

    if inconsistent_group_rows:
        errors.append(f"Found {len(inconsistent_group_rows)} inconsistent grouped policy fields")
        print("\nInconsistent grouped policy fields:")
        for group_key, field, values in inconsistent_group_rows:
            print(f"  {group_key}: {field} has multiple values: {values}")

    total_proto_ports = sum(policy["deduped_proto_port_count"] for policy in grouped_policies)
    raw_policy_rows = len(policy_rows)
    print(f"Policy rows: {raw_policy_rows}")
    print(f"Deduped grouped protoPorts: {total_proto_ports}")

    return errors


def import_network_objects(
    srv: str,
    objects: list[dict[str, Any]],
    csv_path: Path,
    namespace: str = DEFAULT_NAMESPACE,
    dry_run: bool = False,
    limit: int | None = None,
    change_list_path: Path | None = None,
) -> None:
    if limit is not None:
        objects = objects[:limit]

    print(f"Loaded {len(objects)} network objects from {csv_path}")

    for obj in objects:
        print(
            f"Creating NetworkObjectGroup {obj['name']} "
            f"from CSV line {obj['line_number']} "
            f"(source name: {obj['source_name']})"
        )

        create_network_object(
            srv=srv,
            name=obj["name"],
            addresses=obj["addresses"],
            vrfs=obj["vrfs"],
            description=obj["description"],
            namespace=namespace,
            dry_run=dry_run,
        )

        if not dry_run and change_list_path is not None:
            record_created_resource(
                change_list_path=change_list_path,
                gvk=NETWORK_OBJECT_GVK,
                name=obj["name"],
                namespace=namespace,
                source_name=obj["source_name"],
            )


def import_policies(
    srv: str,
    policies: list[dict[str, Any]],
    csv_path: Path,
    namespace: str = DEFAULT_NAMESPACE,
    dry_run: bool = False,
    limit: int | None = None,
    change_list_path: Path | None = None,
) -> None:
    if limit is not None:
        policies = policies[:limit]

    print(f"Loaded {len(policies)} grouped policies from {csv_path}")

    for policy in policies:
        print(
            f"Creating SmartSwitchNetworkPolicy {policy['name']} "
            f"from grouped CSV lines {policy['line_numbers']} "
            f"(source name: {policy['source_name']})"
        )

        create_policy(
            srv=srv,
            name=policy["name"],
            action=policy["action"],
            source_refs=policy["source_refs"],
            destination_refs=policy["destination_refs"],
            proto_ports=policy["proto_ports"],
            namespace=namespace,
            dry_run=dry_run,
        )

        if not dry_run and change_list_path is not None:
            record_created_resource(
                change_list_path=change_list_path,
                gvk=POLICY_GVK,
                name=policy["name"],
                namespace=namespace,
                source_name=policy["source_name"],
            )


def is_not_found_error(exc: RuntimeError) -> bool:
    text = str(exc).lower()
    return "code: notfound" in text or "resource does not exist" in text


def revert_changes(
    srv: str,
    change_list_path: Path,
    dry_run: bool = False,
    continue_on_error: bool = True,
) -> None:
    changes = load_change_list(change_list_path)

    print(f"Loaded {len(changes)} changes from {change_list_path}")
    print("Reverting in reverse order...")

    failed = 0
    reverted = 0

    for change in reversed(changes):
        if change.get("action") != "created":
            print(f"Skipping unsupported change action: {change}")
            continue

        gvk = change["gvk"]
        namespace = change["namespace"]
        name = change["name"]
        kind = gvk["kind"]

        print(f"Deleting {kind} {namespace}/{name}")

        try:
            delete_resource(
                srv=srv,
                gvk=gvk,
                name=name,
                namespace=namespace,
                dry_run=dry_run,
            )
            reverted += 1
        except RuntimeError as exc:
            if is_not_found_error(exc):
                print(f"Already absent: {kind} {namespace}/{name}")
                reverted += 1
                continue

            failed += 1
            print(f"WARNING: failed to delete {kind} {namespace}/{name}")
            print(exc)

            if not continue_on_error:
                raise

    print(f"Revert complete. Deleted: {reverted}. Failed: {failed}.")

    if not dry_run and failed == 0:
        reverted_path = change_list_path.with_suffix(change_list_path.suffix + ".reverted")
        change_list_path.rename(reverted_path)
        print(f"Renamed change-list to {reverted_path}")


def latest_change_list() -> Path:
    revert_dir = Path(DEFAULT_REVERT_DIR)
    candidates = sorted(
        (path for path in revert_dir.glob("*.json") if path.is_file()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    if not candidates:
        raise FileNotFoundError(f"No change-list JSON files found in {revert_dir}/")

    return candidates[0]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import Hypershield network objects and SmartSwitch policies from CSV."
    )
    parser.add_argument("--srv", default=DEFAULT_SRV)
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    parser.add_argument("--network-objects", default="network_objects.csv")
    parser.add_argument("--policies", default=None)
    parser.add_argument(
        "--change-list",
        default=None,
        help=(
            "Change-list JSON path. Imports default to "
            "revert_files/<month>_<day>_<yy>_<HHMM>.json. "
            "Reverts require an explicit path."
        ),
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--allow-missing-refs", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--policy-limit", type=int, default=None)
    parser.add_argument("--skip-network-objects", action="store_true")
    parser.add_argument("--skip-policies", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--revert", action="store_true")
    parser.add_argument("--stop-on-revert-error", action="store_true")
    args = parser.parse_args()

    if args.change_list:
        change_list_path = Path(args.change_list)
    elif args.revert:
        try:
            change_list_path = latest_change_list()
        except FileNotFoundError as exc:
            raise SystemExit(str(exc)) from exc
    else:
        change_list_path = default_timestamped_change_list()

    print(f"Using change-list: {change_list_path}")

    network_objects_path = Path(args.network_objects)
    policies_path = Path(args.policies) if args.policies else None

    if args.revert:
        revert_changes(
            srv=args.srv,
            change_list_path=change_list_path,
            dry_run=args.dry_run,
            continue_on_error=not args.stop_on_revert_error,
        )
        return

    if args.list:
        result = list_network_objects(
            srv=args.srv,
            namespace=args.namespace,
            dry_run=args.dry_run,
        )
        print(json.dumps(result, indent=2))
        return

    network_objects = load_network_objects_csv(network_objects_path)
    policy_rows: list[dict[str, Any]] = []
    grouped_policies: list[dict[str, Any]] = []

    if policies_path is not None and not args.skip_policies:
        policy_rows = load_policies_csv(policies_path)
        grouped_policies = group_policy_rows(policy_rows)

    if args.limit is not None and not args.skip_network_objects:
        validation_network_objects = network_objects[: args.limit]
    else:
        validation_network_objects = network_objects

    validation_errors = validate_import_inputs(
        network_objects=validation_network_objects,
        policy_rows=policy_rows,
        grouped_policies=grouped_policies,
        network_objects_path=network_objects_path,
        policies_path=policies_path if policy_rows else None,
    )

    missing_ref_errors = [
        error for error in validation_errors if "missing policy" in error.lower()
    ]
    non_missing_ref_errors = [
        error for error in validation_errors if error not in missing_ref_errors
    ]

    if validation_errors:
        print("\nValidation errors:")
        for error in validation_errors:
            print(f"  - {error}")

    if non_missing_ref_errors or (missing_ref_errors and not args.allow_missing_refs):
        raise SystemExit("Validation failed. No resources were created.")

    if missing_ref_errors and args.allow_missing_refs:
        print("\nWARNING: missing policy references were found, but --allow-missing-refs was set.")

    if args.validate_only:
        print("\nValidation-only mode complete. No resources were created.")
        return

    if not args.skip_network_objects:
        import_network_objects(
            srv=args.srv,
            objects=network_objects,
            csv_path=network_objects_path,
            namespace=args.namespace,
            dry_run=args.dry_run,
            limit=args.limit,
            change_list_path=change_list_path,
        )

    if policies_path is not None and not args.skip_policies:
        import_policies(
            srv=args.srv,
            policies=grouped_policies,
            csv_path=policies_path,
            namespace=args.namespace,
            dry_run=args.dry_run,
            limit=args.policy_limit,
            change_list_path=change_list_path,
        )


if __name__ == "__main__":
    main()
