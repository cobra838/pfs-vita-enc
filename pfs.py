"""Read and rewrite PS Vita game PFS (files.db and unicv.db).

The implementation follows Vita3K/psvpfsparser's key derivation, CBC sector
operation and unicv signature format. It does not call Vita3K.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import shutil
import struct
import sys
from dataclasses import dataclass, replace
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError as exc:
    raise SystemExit("Install dependency: python -m pip install -r requirements.txt") from exc


PAGE = 0x400
SECTOR = 0x8000
HMAC_KEY0 = bytes.fromhex("e462258b1f3121560745db62b1436723d2bf80fe")
HMAC_KEY1 = bytes.fromhex("afe656bb3c17256a3c809f6e9bf19fdd5a388543")
IV0 = bytes.fromhex("74d20cc39881c213ee770b1010e4bea7")
CONTRACT_KEY = bytes.fromhex("e12213b48016b0e99ab81f8ec02ad4a2")


class PfsError(Exception):
    pass


def sha_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha1).digest()


def aes_ecb(key: bytes, data: bytes, *, decrypt: bool = False) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data) if decrypt else cipher.encrypt(data)


def cbc_tail(data: bytes, key: bytes, iv: bytes, *, decrypt: bool) -> bytes:
    """PFS CBC with the source implementation's short tail handling."""
    prefix = len(data) & ~15
    head = b""
    if prefix:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        head = cipher.decrypt(data[:prefix]) if decrypt else cipher.encrypt(data[:prefix])
    if prefix == len(data):
        return head
    last_ciphertext = data[prefix - 16:prefix] if decrypt and prefix else head[-16:] if prefix else iv
    mask = aes_ecb(key, last_ciphertext)
    return head + bytes(a ^ b for a, b in zip(data[prefix:], mask))


def secret_for(klicensee: bytes, salt: int, files_salt: int) -> bytes:
    salts = struct.pack("<II", files_salt, salt) if files_salt else struct.pack("<I", salt)
    combo = sha_hmac(HMAC_KEY1, salts)
    return cbc_tail(combo, aes_ecb(CONTRACT_KEY, klicensee, decrypt=True), IV0, decrypt=False)


def tweak_for(salt: int, files_salt: int, dbseed: bytes, version: int) -> bytes:
    if version > 1:
        return sha_hmac(HMAC_KEY0, dbseed)[:16]
    salts = struct.pack("<II", files_salt, salt) if files_salt else struct.pack("<I", salt)
    return sha_hmac(HMAC_KEY0, salts)[:16]


@dataclass(frozen=True)
class FileInfo:
    relative: Path
    size: int
    flags: int
    index: int

    @property
    def encrypted(self) -> bool:
        return not self.flags & 0x4000


@dataclass(frozen=True)
class Table:
    salt: int
    sector_size: int
    sectors: int
    version: int
    dbseed: bytes
    signature_offsets: tuple[int, ...]


def parse_files_db(path: Path) -> tuple[int, dict[str, FileInfo]]:
    data = path.read_bytes()
    if len(data) < 2 * PAGE or len(data) % PAGE or data[:8] != b"SCENGPFS":
        raise PfsError("Unsupported or damaged files.db")
    version, image_spec, key_id, page_size = struct.unpack_from("<IHHI", data, 8)
    if version not in (3, 4, 5) or image_spec != 1 or key_id != 0 or page_size != PAGE:
        raise PfsError("Only game PFS with unicv.db and key_id=0 is supported")
    files_salt = struct.unpack_from("<I", data, 0x1C)[0]
    records: list[tuple[int, int, str, int, int]] = []
    for page in range(1, len(data) // PAGE):
        block = memoryview(data)[page * PAGE:(page + 1) * PAGE]
        count = struct.unpack_from("<I", block, 8)[0]
        if count > 9:
            raise PfsError(f"Invalid files.db record count on page {page}")
        for index in range(count):
            offset = 16 + index * 72
            parent = struct.unpack_from("<I", block, offset)[0]
            name = bytes(block[offset + 4:offset + 72]).split(b"\0", 1)[0].decode("utf-8")
            info_offset = 664 + index * 16
            child, flags, _, size, _ = struct.unpack_from("<IHHII", block, info_offset)
            if not name or child == 0xFFFFFFFF or (flags == 0 and size == 0):
                continue
            records.append((child, parent, name, flags, size))
    directories = {child: (parent, name) for child, parent, name, flags, _ in records if flags & 0x8000}

    def relative_path(parent: int, name: str) -> Path:
        parts = [name]
        seen = set()
        while parent:
            if parent in seen or parent not in directories:
                raise PfsError("Invalid directory tree in files.db")
            seen.add(parent)
            parent, directory = directories[parent]
            parts.append(directory)
        parts.reverse()
        if any(part in (".", "..") or "/" in part or "\\" in part for part in parts):
            raise PfsError("Unsafe path in files.db")
        return Path(*parts)

    result: dict[str, FileInfo] = {}
    for child, parent, name, flags, size in records:
        if flags & 0x8000:
            continue
        path_rel = relative_path(parent, name)
        result[str(path_rel).casefold()] = FileInfo(path_rel, size, flags, child)
    return files_salt, result


def parse_unicv(path: Path) -> tuple[bytearray, list[Table]]:
    data = bytearray(path.read_bytes())
    if len(data) < PAGE or len(data) % PAGE or data[:8] != b"SCEIRODB":
        raise PfsError("Unsupported or damaged unicv.db")
    version, page_size = struct.unpack_from("<II", data, 8)
    if version not in (1, 2) or page_size != PAGE:
        raise PfsError("Unsupported unicv.db version")
    tables: list[Table] = []
    page = 1
    while page < len(data) // PAGE:
        offset = page * PAGE
        magic = data[offset:offset + 8]
        if magic == bytes(8):
            page += 1
            continue
        if magic != b"SCEIFTBL":
            raise PfsError(f"Unexpected unicv.db page {page}")
        table_version, block_size, max_signatures, sectors, sector_size = struct.unpack_from("<IIIII", data, offset + 8)
        if table_version not in (1, 2) or block_size != PAGE or max_signatures != 50 or sector_size != SECTOR:
            raise PfsError(f"Unsupported table on unicv.db page {page}")
        dbseed = bytes(data[offset + 52:offset + 72])
        signatures: list[int] = []
        signature_pages = (sectors + 49) // 50
        for part in range(signature_pages):
            sig_page = page + 1 + part
            sig_offset = sig_page * PAGE
            if sig_offset + PAGE > len(data):
                raise PfsError("Truncated unicv.db")
            count = min(50, sectors - part * 50)
            tree_size, sig_size, actual_count, pad = struct.unpack_from("<IIII", data, sig_offset)
            if (tree_size, sig_size, actual_count, pad) != (0x3F8, 20, count, 0):
                raise PfsError(f"Invalid signature page {sig_page}")
            signatures.extend(sig_offset + 16 + i * 20 for i in range(count))
        if sectors:
            # Header is at physical page N; off2page() of the first signature
            # page gives N as its salt.
            tables.append(Table(page, sector_size, sectors, table_version, dbseed, tuple(signatures)))
        page += 1 + signature_pages
    return data, tables


def resize_unicv_table(unicv: bytearray, table: Table, size: int) -> Table:
    """Resize one file table without moving tables belonging to other files."""
    if size < 0 or size > 0xFFFFFFFF:
        raise PfsError("PFS file size must fit in 32 bits")
    sectors = (size + SECTOR - 1) // SECTOR
    old_pages = (table.sectors + 49) // 50
    new_pages = (sectors + 49) // 50
    old_offset = table.salt * PAGE
    header = bytes(unicv[old_offset:old_offset + PAGE])
    if len(header) != PAGE or header[:8] != b"SCEIFTBL":
        raise PfsError(f"Missing unicv.db table at page {table.salt}")

    if new_pages > old_pages:
        # Blank the old table and append the larger one. Existing table page
        # numbers (and therefore their encryption salts) stay unchanged.
        unicv[old_offset:old_offset + (1 + old_pages) * PAGE] = bytes((1 + old_pages) * PAGE)
        salt = len(unicv) // PAGE
        unicv.extend(header)
        unicv.extend(bytes(new_pages * PAGE))
    else:
        salt = table.salt
        for part in range(new_pages, old_pages):
            offset = (salt + 1 + part) * PAGE
            unicv[offset:offset + PAGE] = bytes(PAGE)

    struct.pack_into("<I", unicv, salt * PAGE + 20, sectors)
    offsets: list[int] = []
    for part in range(new_pages):
        offset = (salt + 1 + part) * PAGE
        count = min(50, sectors - part * 50)
        unicv[offset:offset + PAGE] = bytes(PAGE)
        struct.pack_into("<IIII", unicv, offset, 0x3F8, 20, count, 0)
        offsets.extend(offset + 16 + i * 20 for i in range(count))
    struct.pack_into("<Q", unicv, 24, len(unicv) - PAGE)
    return Table(salt, table.sector_size, sectors, table.version, table.dbseed, tuple(offsets))


def files_db_page_icv(data: bytearray, page: int, secret: bytes, version: int) -> bytes:
    offset = (page + 1) * PAGE
    block = data[offset:offset + PAGE]
    if len(block) != PAGE:
        raise PfsError(f"Invalid files.db page {page}")
    if version == 5:
        return sha_hmac(secret, block[4:PAGE])
    kind, count = struct.unpack_from("<II", block, 4)
    if kind not in (0, 1) or count > 9:
        raise PfsError(f"Invalid files.db page {page}")
    result = bytes(20)
    for index in range(count + (kind == 1)):
        item = block[824 + index * 20:844 + index * 20]
        result = sha_hmac(secret, result + item)
    return result


def update_files_db_record(data: bytearray, info: FileInfo, size: int,
                           index: int, klicensee: bytes) -> None:
    version = struct.unpack_from("<I", data, 8)[0]
    salt = struct.unpack_from("<I", data, 0x1C)[0]
    secret = secret_for(klicensee, 0, salt)
    header = bytearray(data[:0x160])
    header[0x4C:0x60] = bytes(20)
    header[0x60:0x160] = bytes(0x100)
    if sha_hmac(secret, header) != data[0x4C:0x60]:
        raise PfsError("Invalid files.db header signature")

    record: tuple[int, int] | None = None
    for physical in range(1, len(data) // PAGE):
        offset = physical * PAGE
        count = struct.unpack_from("<I", data, offset + 8)[0]
        if count > 9:
            raise PfsError(f"Invalid files.db page {physical}")
        for slot in range(count):
            entry = offset + 664 + slot * 16
            if struct.unpack_from("<I", data, entry)[0] == info.index:
                if record is not None:
                    raise PfsError(f"Duplicate files.db index: {info.index}")
                record = (physical - 1, entry)
    if record is None:
        raise PfsError(f"File missing from files.db: {info.relative}")
    page, entry = record
    if struct.unpack_from("<I", data, entry + 8)[0] != info.size:
        raise PfsError(f"Size mismatch in files.db: {info.relative}")

    old_icv = files_db_page_icv(data, page, secret, version)
    struct.pack_into("<I", data, entry, index)
    struct.pack_into("<I", data, entry + 8, size)
    while True:
        new_icv = files_db_page_icv(data, page, secret, version)
        if new_icv == old_icv:
            break
        offset = (page + 1) * PAGE
        parent = struct.unpack_from("<I", data, offset)[0]
        if parent == 0xFFFFFFFF:
            if page != struct.unpack_from("<I", data, 0x18)[0]:
                raise PfsError("Invalid files.db root page")
            data[0x38:0x4C] = new_icv
            break
        parent_offset = (parent + 1) * PAGE
        if parent_offset + PAGE > len(data):
            raise PfsError("Invalid files.db parent page")
        old_parent_icv = files_db_page_icv(data, parent, secret, version)
        matches = [parent_offset + 824 + slot * 20 for slot in range(10)
                   if data[parent_offset + 824 + slot * 20:parent_offset + 844 + slot * 20] == old_icv]
        if len(matches) != 1:
            raise PfsError(f"Cannot update files.db parent hash for page {page}")
        data[matches[0]:matches[0] + 20] = new_icv
        page, old_icv = parent, old_parent_icv

    header = bytearray(data[:0x160])
    header[0x4C:0x60] = bytes(20)
    header[0x60:0x160] = bytes(0x100)
    data[0x4C:0x60] = sha_hmac(secret, header)


def update_pflist_record(data: str, info: FileInfo, size: int, index: int) -> str:
    lines = data.splitlines(keepends=True)
    target = str(info.relative).casefold()
    found = False
    for number, line in enumerate(lines):
        body = line.rstrip("\r\n")
        if body.startswith("#"):
            continue
        fields = body.split("\t")
        if len(fields) < 5 or str(Path(fields[0])).casefold() != target:
            continue
        if found or int(fields[-2], 0) != info.index or int(fields[-1]) != info.size:
            raise PfsError(f"Inconsistent pflist entry: {info.relative}")
        fields[-2] = f"0x{index:08x}"
        fields[-1] = str(size)
        lines[number] = "\t".join(fields) + line[len(body):]
        found = True
    if not found:
        raise PfsError(f"Missing pflist entry: {info.relative}")
    return "".join(lines)


def signature(secret: bytes, sector_index: int, ciphertext: bytes) -> bytes:
    sector_key = sha_hmac(secret, struct.pack("<I", sector_index))
    return sha_hmac(sector_key, ciphertext)


def sector_cipher(data: bytes, key: bytes, tweak_mask: bytes, sector_index: int, *, decrypt: bool) -> bytes:
    offset = sector_index * SECTOR
    tweak = bytes(a ^ b for a, b in zip(struct.pack("<Q", offset) + bytes(8), tweak_mask))
    return cbc_tail(data, key, tweak, decrypt=decrypt)


def map_tables_by_index(infos: dict[str, FileInfo], tables: list[Table]) -> dict[str, Table]:
    """Match files.db file indices to the corresponding unicv.db table pages."""
    by_index = {table.salt: table for table in tables}
    result: dict[str, Table] = {}
    for key, info in infos.items():
        if not info.size:
            continue
        table = by_index.get(info.index)
        if table is None or table.sectors != (info.size + SECTOR - 1) // SECTOR:
            raise PfsError(f"Missing or incompatible unicv.db table: {info.relative}")
        result[key] = table
    return result


def transfer_file(src: Path, dst: Path, info: FileInfo, table: Table,
                  unicv: bytearray, klicensee: bytes, files_salt: int, *, decrypt: bool) -> None:
    secret = secret_for(klicensee, table.salt, files_salt)
    mask = tweak_for(table.salt, files_salt, table.dbseed, table.version)
    key = aes_ecb(CONTRACT_KEY, klicensee, decrypt=True)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as reader, dst.open("wb") as writer:
        for sector_index, sig_offset in enumerate(table.signature_offsets):
            block = reader.read(table.sector_size)
            if not block:
                raise PfsError(f"Truncated file: {src}")
            if decrypt:
                if signature(secret, sector_index, block) != unicv[sig_offset:sig_offset + 20]:
                    raise PfsError(f"PFS signature mismatch: {info.relative}, sector {sector_index}")
                result = sector_cipher(block, key, mask, sector_index, decrypt=True) if info.encrypted else block
            else:
                result = sector_cipher(block, key, mask, sector_index, decrypt=False) if info.encrypted else block
                unicv[sig_offset:sig_offset + 20] = signature(secret, sector_index, result)
            writer.write(result)
        if reader.read(1):
            raise PfsError(f"File size mismatch: {src}")


def input_metadata(source: Path, sce_pfs: Path | None, license_path: Path | None,
                   *, single_file: bool) -> tuple[Path, bytes]:
    if single_file and (sce_pfs is None or license_path is None):
        raise PfsError("File mode requires both --sce-pfs and --license")
    pfs_dir = sce_pfs if sce_pfs is not None else source / "sce_pfs"
    license_file = license_path if license_path is not None else source / "sce_sys/package/work.bin"
    if not pfs_dir.is_dir():
        raise PfsError(f"Missing sce_pfs directory: {pfs_dir}; pass --sce-pfs PATH")
    if not (pfs_dir / "files.db").is_file() or not (pfs_dir / "unicv.db").is_file():
        raise PfsError(f"Missing files.db or unicv.db in {pfs_dir}; pass --sce-pfs PATH")
    if not license_file.is_file():
        raise PfsError(f"Missing license: {license_file}; pass --license PATH")
    license_bytes = license_file.read_bytes()
    if len(license_bytes) < 0x60:
        raise PfsError(f"Truncated license: {license_file}")
    return pfs_dir, license_bytes


def copy_files(source: Path, destination: Path) -> None:
    if not source.is_dir():
        return
    for path in source.rglob("*"):
        if path.is_file():
            target = destination / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def run(mode: str, source: Path, output: Path,
        sce_pfs: Path | None, license_path: Path | None) -> None:
    if not source.is_dir():
        raise PfsError(f"Input is not a directory: {source}")
    if output.exists():
        raise PfsError(f"Output already exists: {output}")
    if output.resolve().is_relative_to(source.resolve()):
        raise PfsError("Output directory must be outside the input directory")
    pfs_dir, license_bytes = input_metadata(source, sce_pfs, license_path, single_file=False)
    klicensee = license_bytes[0x50:0x60]
    files_salt, infos = parse_files_db(pfs_dir / "files.db")
    unicv, tables = parse_unicv(pfs_dir / "unicv.db")
    mapping = map_tables_by_index(infos, tables)
    files_db = bytearray((pfs_dir / "files.db").read_bytes())
    pflist_path = pfs_dir / "pflist"
    pflist = pflist_path.read_bytes().decode("utf-8") if mode == "encrypt" and pflist_path.is_file() else None
    if mode == "encrypt":
        allowed = set(infos)
        actual: set[str] = set()
        for path in source.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(source)
            parts = tuple(part.casefold() for part in relative.parts)
            if parts[0] == "sce_pfs" or parts[:2] == ("sce_sys", "package"):
                continue
            actual.add(str(relative).casefold())
        unexpected = actual - allowed
        if unexpected:
            raise PfsError(f"Unexpected plain files: {', '.join(sorted(unexpected)[:5])}")
        for key, info in list(infos.items()):
            src = source / info.relative
            if not src.is_file():
                raise PfsError(f"Missing file: {src}")
            new_size = src.stat().st_size
            if new_size == info.size:
                continue
            table = mapping.get(key)
            if table is None:
                raise PfsError(f"Cannot resize file without a PFS table: {info.relative}")
            new_table = resize_unicv_table(unicv, table, new_size)
            update_files_db_record(files_db, info, new_size, new_table.salt, klicensee)
            if pflist is not None:
                pflist = update_pflist_record(pflist, info, new_size, new_table.salt)
            infos[key] = replace(info, size=new_size, index=new_table.salt)
            mapping[key] = new_table
            print(f"resize: {info.relative}: {info.size} -> {new_size} bytes", flush=True)
    output.mkdir(parents=True)
    try:
        copy_files(pfs_dir, output / "sce_pfs")
        if mode == "encrypt":
            (output / "sce_pfs/files.db").write_bytes(files_db)
            if pflist is not None:
                (output / "sce_pfs/pflist").write_bytes(pflist.encode("utf-8"))
        copy_files(source / "sce_sys/package", output / "sce_sys/package")
        work_output = output / "sce_sys/package/work.bin"
        work_output.parent.mkdir(parents=True, exist_ok=True)
        work_output.write_bytes(license_bytes)
        for key, info in infos.items():
            src = source / info.relative
            dst = output / info.relative
            if not src.is_file() or src.stat().st_size != info.size:
                raise PfsError(f"Missing file or changed size: {src}")
            table = mapping.get(key)
            if table:
                transfer_file(src, dst, info, table, unicv, klicensee, files_salt, decrypt=mode == "decrypt")
            else:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            print(f"{mode}: {info.relative}", flush=True)
        if mode == "encrypt":
            (output / "sce_pfs/unicv.db").write_bytes(unicv)
    except Exception:
        # Keep partial output for inspection, but never silently report success.
        raise


def pick_file(source: Path, game_root: Path, infos: dict[str, FileInfo],
              relative: str | None) -> FileInfo:
    if relative is not None:
        parts = Path(relative).parts
        if Path(relative).is_absolute() or not parts or any(part in (".", "..") for part in parts):
            raise PfsError("--path must be a relative path inside the PFS title")
        info = infos.get(str(Path(relative)).casefold())
        if info is None:
            raise PfsError(f"File absent from files.db: {relative}")
        return info
    try:
        key = str(source.resolve().relative_to(game_root.resolve())).casefold()
        if key in infos:
            return infos[key]
    except ValueError:
        pass
    matches = [info for info in infos.values() if info.relative.name.casefold() == source.name.casefold()]
    if len(matches) != 1:
        raise PfsError("Cannot infer PFS path from filename; add --path e.g. sysdata/icon.png")
    return matches[0]


def run_file(mode: str, source: Path, output: Path, sce_pfs: Path | None,
             license_path: Path | None, relative: str | None,
             unicv_input: Path | None, unicv_output: Path | None) -> None:
    if not source.is_file():
        raise PfsError(f"Input is not a file: {source}")
    if output.exists():
        raise PfsError(f"Output already exists: {output}")
    if mode == "encrypt":
        unicv_output = unicv_output or output.with_name(output.name + ".unicv.db")
        if unicv_output.exists() or unicv_output.resolve() == output.resolve():
            raise PfsError(f"unicv.db output already exists or conflicts with file output: {unicv_output}")
    pfs_dir, license_bytes = input_metadata(source, sce_pfs, license_path, single_file=True)
    klicensee = license_bytes[0x50:0x60]
    files_salt, infos = parse_files_db(pfs_dir / "files.db")
    unicv, tables = parse_unicv(pfs_dir / "unicv.db")
    mapping = map_tables_by_index(infos, tables)
    info = pick_file(source, pfs_dir.parent, infos, relative)
    if source.stat().st_size != info.size:
        raise PfsError(f"File size differs from files.db: {source}")
    if mode == "decrypt":
        if unicv_input is None:
            sidecar = source.with_name(source.name + ".unicv.db")
            if sidecar.is_file():
                unicv_input = sidecar
        if unicv_input is not None:
            other, other_tables = parse_unicv(unicv_input)
            if len(other) != len(unicv) or other_tables != tables:
                raise PfsError("Provided unicv.db has a different PFS layout")
            unicv = other
    table = mapping.get(str(info.relative).casefold())
    if table is None:
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, output)
    else:
        transfer_file(source, output, info, table, unicv, klicensee, files_salt,
                      decrypt=mode == "decrypt")
    if mode == "encrypt":
        assert unicv_output is not None
        unicv_output.parent.mkdir(parents=True, exist_ok=True)
        unicv_output.write_bytes(unicv)
        print(f"Updated PFS signatures: {unicv_output}")
    print(f"{mode}: {info.relative} -> {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypt or re-encrypt Vita game PFS (unicv.db)")
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode in ("decrypt", "encrypt"):
        cmd = sub.add_parser(mode)
        cmd.add_argument("source", type=Path, help="input file or directory")
        cmd.add_argument("output", type=Path, help="new output file or directory")
        cmd.add_argument("--sce-pfs", type=Path, help="path to sce_pfs directory; required for file mode")
        cmd.add_argument("--license", type=Path, help="path to work.bin or RIF; required for file mode")
        cmd.add_argument("--path", help="file path inside PFS if it cannot be inferred from the filename")
        if mode == "decrypt":
            cmd.add_argument("--unicv", type=Path, help="updated unicv.db for a modified encrypted file")
        else:
            cmd.add_argument("--unicv-output", type=Path, help="where to write updated unicv.db for a single file")
    args = parser.parse_args()
    try:
        if args.source.is_file():
            run_file(args.mode, args.source, args.output, args.sce_pfs, args.license, args.path,
                     getattr(args, "unicv", None), getattr(args, "unicv_output", None))
        else:
            if args.path or getattr(args, "unicv", None) or getattr(args, "unicv_output", None):
                raise PfsError("--path and unicv options are for file mode")
            run(args.mode, args.source, args.output, args.sce_pfs, args.license)
    except (PfsError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
