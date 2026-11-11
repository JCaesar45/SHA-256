#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

API = os.environ.get("AURUM_API", "http://localhost:8787").rstrip("/")
CHUNK = 1 << 20


def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def folder_leaves(folder: Path) -> list[tuple[str, str]]:
    files = sorted(
        (p for p in folder.rglob("*") if p.is_file()),
        key=lambda p: p.relative_to(folder).as_posix(),
    )
    return [(p.relative_to(folder).as_posix(), file_digest(p)) for p in files]


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        raise ValueError("A Merkle root needs at least one file.")
    level = [bytes.fromhex(x) for x in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[i] + level[i + 1]).digest()
            for i in range(0, len(level), 2)
        ]
    return level[0].hex()


def call(method: str, route: str, payload: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        API + route,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as err:
        try:
            body = json.load(err)
        except ValueError:
            body = {"error": str(err.reason)}
        return err.code, body
    except urllib.error.URLError as err:
        sys.exit(f"Cannot reach {API}: {err.reason}")


def need_file(raw: str) -> Path:
    path = Path(raw)
    if not path.is_file():
        sys.exit(f"Not a file: {raw}")
    return path


def cmd_hash(args: argparse.Namespace) -> int:
    print(file_digest(need_file(args.file)))
    return 0


def cmd_seal(args: argparse.Namespace) -> int:
    path = need_file(args.file)
    status, body = call("POST", "/api/seal", {"digest": file_digest(path), "label": args.label or path.name})
    print(json.dumps(body, indent=2))
    return 0 if status == 201 else 1


def cmd_verify(args: argparse.Namespace) -> int:
    digest = file_digest(need_file(args.file))
    status, body = call("GET", f"/api/verify/{digest}")
    print(json.dumps(body, indent=2))
    return 0 if status == 200 else 1


def cmd_merkle(args: argparse.Namespace) -> int:
    folder = Path(args.folder)
    if not folder.is_dir():
        sys.exit(f"Not a folder: {args.folder}")
    pairs = folder_leaves(folder)
    if not pairs:
        sys.exit("The folder has no files.")
    root = merkle_root([digest for _, digest in pairs])
    for name, digest in pairs:
        print(f"{digest}  {name}")
    print(f"\nmerkle root  {root}")
    if args.seal:
        status, body = call("POST", "/api/seal", {"digest": root, "label": args.label or f"{folder.name} ({len(pairs)} files)"})
        print(json.dumps(body, indent=2))
        return 0 if status == 201 else 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aurum", description="Hash, seal and verify files with Aurum Seal.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_hash = sub.add_parser("hash", help="print the SHA-256 of a file")
    p_hash.add_argument("file")
    p_hash.set_defaults(run=cmd_hash)

    p_seal = sub.add_parser("seal", help="seal a file")
    p_seal.add_argument("file")
    p_seal.add_argument("--label")
    p_seal.set_defaults(run=cmd_seal)

    p_verify = sub.add_parser("verify", help="check whether a file was sealed")
    p_verify.add_argument("file")
    p_verify.set_defaults(run=cmd_verify)

    p_merkle = sub.add_parser("merkle", help="compute the Merkle root of a folder")
    p_merkle.add_argument("folder")
    p_merkle.add_argument("--seal", action="store_true", help="seal the root")
    p_merkle.add_argument("--label")
    p_merkle.set_defaults(run=cmd_merkle)
    return parser


if __name__ == "__main__":
    ns = build_parser().parse_args()
    sys.exit(ns.run(ns))
