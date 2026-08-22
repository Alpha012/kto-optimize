#!/usr/bin/env python3
"""Preflight and filter DPI Detector TCP targets without changing upstream code."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import math
import os
import re
import socket
import sys
import time
from pathlib import Path
from typing import Any


DPI_PREFLIGHT_BUILD = "v337"
SCHEMA_VERSION = 1


class PreflightError(RuntimeError):
    pass


def _safe_text(value: Any) -> str:
    return str(value or "").replace("\t", " ").replace("\r", " ").replace("\n", " ").strip()


def _load_json(path: str) -> Any:
    try:
        if path == "-":
            return json.loads(sys.stdin.read().lstrip("\ufeff"))
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise PreflightError(f"cannot read {path}: {exc}") from exc


def load_targets(path: str) -> list[dict[str, Any]]:
    raw = _load_json(path)
    if not isinstance(raw, list) or not raw:
        raise PreflightError("tcp16.json must contain a non-empty list")

    targets: list[dict[str, Any]] = []
    seen_indexes: set[int] = set()
    for position, raw_item in enumerate(raw):
        if not isinstance(raw_item, dict):
            raise PreflightError(f"target #{position + 1} is not an object")

        item = dict(raw_item)
        raw_index = item.pop("_kto_index", position)
        try:
            index = int(raw_index)
        except (TypeError, ValueError) as exc:
            raise PreflightError(f"target #{position + 1} has an invalid index") from exc
        if index < 0 or index in seen_indexes:
            raise PreflightError(f"target #{position + 1} has a duplicate or negative index")
        seen_indexes.add(index)

        ip = _safe_text(item.get("ip"))
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise PreflightError(f"target #{position + 1} has an invalid IP: {ip or '-'}") from exc
        if parsed_ip.version != 4:
            raise PreflightError(f"target #{position + 1} is not IPv4: {ip}")

        raw_port = item.get("port", item.get(",port", 443))
        try:
            port = int(raw_port)
        except (TypeError, ValueError) as exc:
            raise PreflightError(f"target #{position + 1} has an invalid port") from exc
        if not 1 <= port <= 65535:
            raise PreflightError(f"target #{position + 1} has an out-of-range port: {port}")

        item["ip"] = ip
        item["port"] = port
        item.pop(",port", None)
        targets.append({"index": index, "item": item})

    return targets


async def _probe_once(ip: str, port: int, timeout: float) -> tuple[bool, str, float | None]:
    started = time.monotonic()
    writer: asyncio.StreamWriter | None = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, family=socket.AF_INET),
            timeout=timeout,
        )
        latency_ms = round((time.monotonic() - started) * 1000.0, 1)
        return True, "open", latency_ms
    except (asyncio.TimeoutError, TimeoutError):
        return False, "timeout", None
    except ConnectionRefusedError:
        return False, "refused", None
    except OSError as exc:
        code = exc.errno if exc.errno is not None else "unknown"
        detail = os.strerror(exc.errno) if exc.errno is not None else exc.__class__.__name__
        return False, f"oserror:{code}:{detail}", None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def _probe_target(
    target: dict[str, Any],
    semaphore: asyncio.Semaphore,
    timeout: float,
    attempts: int,
) -> dict[str, Any]:
    item = target["item"]
    reasons: list[str] = []
    async with semaphore:
        for attempt in range(attempts):
            ok, reason, latency_ms = await _probe_once(item["ip"], item["port"], timeout)
            if ok:
                return {
                    "index": target["index"],
                    "ip": item["ip"],
                    "port": item["port"],
                    "ok": True,
                    "reason": reason,
                    "latency_ms": latency_ms,
                }
            reasons.append(reason)
            if attempt + 1 < attempts:
                await asyncio.sleep(0.15)

    return {
        "index": target["index"],
        "ip": item["ip"],
        "port": item["port"],
        "ok": False,
        "reason": ",".join(reasons),
        "latency_ms": None,
    }


async def probe_targets(
    targets: list[dict[str, Any]], timeout: float, concurrency: int, attempts: int
) -> dict[str, Any]:
    semaphore = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(
        *(_probe_target(target, semaphore, timeout, attempts) for target in targets)
    )
    results.sort(key=lambda result: result["index"])
    alive = sum(1 for result in results if result["ok"])
    return {
        "schema": SCHEMA_VERSION,
        "build": DPI_PREFLIGHT_BUILD,
        "total": len(results),
        "alive": alive,
        "failed": len(results) - alive,
        "results": results,
    }


def load_report(path: str, label: str) -> dict[int, dict[str, Any]]:
    report = _load_json(path)
    if not isinstance(report, dict) or report.get("schema") != SCHEMA_VERSION:
        raise PreflightError(f"{label} report has an unsupported schema")
    raw_results = report.get("results")
    if not isinstance(raw_results, list):
        raise PreflightError(f"{label} report has no results")

    results: dict[int, dict[str, Any]] = {}
    for raw_result in raw_results:
        if not isinstance(raw_result, dict):
            raise PreflightError(f"{label} report contains an invalid result")
        try:
            index = int(raw_result["index"])
        except (KeyError, TypeError, ValueError) as exc:
            raise PreflightError(f"{label} report contains an invalid index") from exc
        if index in results:
            raise PreflightError(f"{label} report contains duplicate index {index}")
        results[index] = raw_result
    return results


def _validate_result(target: dict[str, Any], result: dict[str, Any], label: str) -> None:
    item = target["item"]
    if result.get("ip") != item["ip"] or result.get("port") != item["port"]:
        raise PreflightError(f"{label} report does not match target index {target['index']}")
    if not isinstance(result.get("ok"), bool):
        raise PreflightError(f"{label} report has invalid status for index {target['index']}")


def _target_group(item: dict[str, Any]) -> str:
    asn_numbers = re.findall(r"\d+", _safe_text(item.get("asn")))
    if asn_numbers:
        return "asn:" + "/".join(asn_numbers)
    provider = _safe_text(item.get("provider")).casefold()
    provider_root = re.sub(r"[^a-z0-9_.-]+", " ", provider).split()
    if provider_root:
        return "provider:" + provider_root[0]
    return "target:" + _safe_text(item.get("id"))


def combine_reports(args: argparse.Namespace) -> int:
    targets = load_targets(args.input)
    selected = load_report(args.selected, "selected")
    reference = load_report(args.reference, "reference")

    kept: list[dict[str, Any]] = []
    skipped: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    selected_alive = 0
    reference_alive = 0
    differential = 0
    unverified: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
    records: list[
        tuple[dict[str, Any], dict[str, Any], dict[str, Any], str, bool]
    ] = []
    group_sizes: dict[str, int] = {}
    group_alive: dict[str, int] = {}

    for target in targets:
        index = target["index"]
        if index not in selected or index not in reference:
            raise PreflightError(f"missing probe result for target index {index}")
        selected_result = selected[index]
        reference_result = reference[index]
        _validate_result(target, selected_result, "selected")
        _validate_result(target, reference_result, "reference")

        selected_ok = selected_result["ok"]
        reference_ok = reference_result["ok"]
        selected_alive += int(selected_ok)
        reference_alive += int(reference_ok)
        differential += int(not selected_ok and reference_ok)
        group = _target_group(target["item"])
        reachable = selected_ok or reference_ok
        group_sizes[group] = group_sizes.get(group, 0) + 1
        group_alive[group] = group_alive.get(group, 0) + int(reachable)
        records.append((target, selected_result, reference_result, group, reachable))

    for target, selected_result, reference_result, group, reachable in records:
        if reachable:
            kept.append(target["item"])
        elif group_sizes[group] > 1 and group_alive[group] > 0:
            skipped.append((target, selected_result, reference_result))
        else:
            # A whole ASN/provider group can be filtered by the tested network.
            # Keep it in the real detector instead of laundering a block as downtime.
            kept.append(target["item"])
            unverified.append((target, selected_result, reference_result))

    minimum = max(args.min_kept, math.ceil(len(targets) * args.min_kept_ratio))
    if len(kept) < minimum:
        print(f"TOTAL\t{len(targets)}")
        print(f"KEPT\t{len(kept)}")
        print(f"MINIMUM\t{minimum}")
        print("ABORT\ttoo_few_reachable_targets")
        return 3

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f".{output_path.name}.tmp")
    with open(temporary, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(kept, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    os.replace(temporary, output_path)

    print(f"TOTAL\t{len(targets)}")
    print(f"KEPT\t{len(kept)}")
    print(f"SKIPPED\t{len(skipped)}")
    print(f"SELECTED_ALIVE\t{selected_alive}")
    print(f"REFERENCE_ALIVE\t{reference_alive}")
    print(f"DIFFERENTIAL\t{differential}")
    print(f"UNVERIFIED\t{len(unverified)}")
    for target, selected_result, reference_result in skipped:
        item = target["item"]
        print(
            "\t".join(
                (
                    "SKIP",
                    _safe_text(item.get("id")) or str(target["index"] + 1),
                    _safe_text(item.get("provider")) or "-",
                    item["ip"],
                    str(item["port"]),
                    _safe_text(selected_result.get("reason")) or "unknown",
                    _safe_text(reference_result.get("reason")) or "unknown",
                )
            )
        )
    for target, selected_result, reference_result in unverified:
        item = target["item"]
        print(
            "\t".join(
                (
                    "UNVERIFIED_TARGET",
                    _safe_text(item.get("id")) or str(target["index"] + 1),
                    _safe_text(item.get("provider")) or "-",
                    item["ip"],
                    str(item["port"]),
                    _safe_text(selected_result.get("reason")) or "unknown",
                    _safe_text(reference_result.get("reason")) or "unknown",
                )
            )
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    probe = subparsers.add_parser("probe")
    probe.add_argument("--input", required=True)
    probe.add_argument("--timeout", type=float, default=2.0)
    probe.add_argument("--concurrency", type=int, default=48)
    probe.add_argument("--attempts", type=int, default=1)

    combine = subparsers.add_parser("combine")
    combine.add_argument("--input", required=True)
    combine.add_argument("--selected", required=True)
    combine.add_argument("--reference", required=True)
    combine.add_argument("--output", required=True)
    combine.add_argument("--min-kept", type=int, default=10)
    combine.add_argument("--min-kept-ratio", type=float, default=0.35)
    return parser


def validate_args(args: argparse.Namespace) -> None:
    if args.command == "probe":
        if not 0.2 <= args.timeout <= 30.0:
            raise PreflightError("timeout must be between 0.2 and 30 seconds")
        if not 1 <= args.concurrency <= 256:
            raise PreflightError("concurrency must be between 1 and 256")
        if not 1 <= args.attempts <= 5:
            raise PreflightError("attempts must be between 1 and 5")
    elif args.command == "combine":
        if not 1 <= args.min_kept <= 10000:
            raise PreflightError("min-kept must be between 1 and 10000")
        if not 0.05 <= args.min_kept_ratio <= 1.0:
            raise PreflightError("min-kept-ratio must be between 0.05 and 1.0")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        validate_args(args)
        if args.command == "probe":
            targets = load_targets(args.input)
            report = asyncio.run(
                probe_targets(targets, args.timeout, args.concurrency, args.attempts)
            )
            json.dump(report, sys.stdout, ensure_ascii=False, separators=(",", ":"))
            sys.stdout.write("\n")
            return 0
        return combine_reports(args)
    except PreflightError as exc:
        print(f"preflight error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
