"""Restore an authenticated ThreatFusion local-data backup. Requires cryptography."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
import zipfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"TFBACKUP1\n"
BLOCK = 1024 * 1024


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(BLOCK), b""):
            h.update(block)
    return h.hexdigest()


def safe_name(name):
    p = PurePosixPath(name)
    if p.is_absolute() or ".." in p.parts or "\\" in name or ":" in name:
        raise ValueError("Unsafe archive path")
    return p


def git(*args):
    result = subprocess.run(["git", *map(str, args)], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("Git recovery command failed: " + result.stderr.strip())
    return result.stdout.strip()


def recover(backup_dir, key_path, destination=None):
    backup_dir = Path(backup_dir).resolve()
    index = json.loads((backup_dir / "backup.json").read_text(encoding="utf-8"))
    key_data = json.loads(Path(key_path).read_text(encoding="utf-8"))
    if key_data["key_id"] != index["key_id"]:
        raise ValueError("Recovery key belongs to a different backup")
    key = base64.b64decode(key_data["key_base64"], validate=True)
    if len(key) != 32:
        raise ValueError("Invalid recovery key")
    if destination is not None and Path(destination).exists():
        raise ValueError("Destination must not exist; use a new folder")
    with tempfile.TemporaryDirectory(prefix="threatfusion-restore-") as temp:
        temp = Path(temp)
        encrypted = temp / "backup.encrypted"
        with encrypted.open("wb") as joined:
            for part in index["parts"]:
                name = safe_name(part["name"])
                if len(name.parts) != 1:
                    raise ValueError("Invalid part name")
                part_path = backup_dir / name.name
                if part_path.stat().st_size != part["bytes"] or digest(part_path) != part["sha256"]:
                    raise ValueError("Encrypted part checksum failed")
                with part_path.open("rb") as source:
                    shutil.copyfileobj(source, joined, BLOCK)
        if digest(encrypted) != index["encrypted_sha256"]:
            raise ValueError("Complete encrypted backup checksum failed")
        size = encrypted.stat().st_size
        with encrypted.open("rb") as source:
            if source.read(len(MAGIC)) != MAGIC:
                raise ValueError("Unknown backup format")
            nonce = source.read(12)
            source.seek(-16, os.SEEK_END)
            tag = source.read(16)
            source.seek(len(MAGIC) + 12)
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            decryptor.authenticate_additional_data(MAGIC)
            remaining = size - len(MAGIC) - 12 - 16
            decrypted = temp / "backup.zip"
            with decrypted.open("wb") as output:
                while remaining:
                    chunk = source.read(min(BLOCK, remaining))
                    if not chunk:
                        raise ValueError("Truncated encrypted backup")
                    output.write(decryptor.update(chunk))
                    remaining -= len(chunk)
                output.write(decryptor.finalize())
        with zipfile.ZipFile(decrypted) as archive:
            manifest = json.loads(archive.read("recovery/manifest.json"))
            expected_names = {e["path"] for e in manifest["entries"]} | {"recovery/manifest.json"}
            if len(archive.namelist()) != len(expected_names) or set(archive.namelist()) != expected_names:
                raise ValueError("Archive file inventory does not match its manifest")
            for entry in manifest["entries"]:
                safe_name(entry["path"])
                h = hashlib.sha256()
                count = 0
                with archive.open(entry["path"]) as source:
                    for block in iter(lambda: source.read(BLOCK), b""):
                        h.update(block)
                        count += len(block)
                if count != entry["bytes"] or h.hexdigest() != entry["sha256"]:
                    raise ValueError("Decrypted file checksum failed")
            if destination is not None:
                bundle = temp / "repository.bundle"
                with archive.open("recovery/repository.bundle") as source, bundle.open("wb") as output:
                    shutil.copyfileobj(source, output, BLOCK)
                destination = Path(destination).resolve()
                git("clone", "--no-hardlinks", "--branch", manifest["source_branch"], bundle, destination)
                git("-C", destination, "remote", "set-url", "origin", manifest["repository_url"])
                if git("-C", destination, "rev-parse", "HEAD") != manifest["source_head"]:
                    raise ValueError("Restored code commit does not match the source")
                for entry in manifest["entries"]:
                    if entry["kind"] != "local-data":
                        continue
                    name = safe_name(entry["path"])
                    target = destination.joinpath(*name.parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.exists():
                        raise ValueError("Restore would overwrite an existing file")
                    with archive.open(entry["path"]) as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output, BLOCK)
                    if digest(target) != entry["sha256"]:
                        raise ValueError("Restored on-disk file checksum failed")
                git("-C", destination, "fsck", "--full")
            return {
                "verified": True,
                "source_head": manifest["source_head"],
                "local_files": sum(e["kind"] == "local-data" for e in manifest["entries"]),
                "local_bytes": sum(e["bytes"] for e in manifest["entries"] if e["kind"] == "local-data"),
                "destination": str(destination) if destination is not None else None,
            }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(recover(args.backup, args.key, args.destination), ensure_ascii=True))
