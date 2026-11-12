"""
Parser de tabela de particoes: MBR (classico) e GPT.

Nao depende do The Sleuth Kit — le diretamente os setores a partir da
imagem. Suficiente para localizar a particao e seu offset em bytes, que
e o que o modulo BitLocker precisa.
"""
from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from typing import List

SECTOR = 512

# Tipos MBR mais relevantes.
MBR_TYPES = {
    0x00: "Vazia",
    0x07: "NTFS / exFAT / HPFS",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x27: "Particao de recuperacao Windows",
    0x82: "Linux swap",
    0x83: "Linux",
    0xEE: "Protective MBR (GPT)",
    0xEF: "EFI System",
}

# GUIDs de tipo de particao GPT relevantes.
GPT_TYPES = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft Reserved (MSR)",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basic Data (NTFS/exFAT)",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows Recovery",
    "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "LDM metadata",
    "AF9B60A0-1431-4F62-BC68-3311714A69AD": "LDM data",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux filesystem",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
    "21686148-6449-6E6F-744E-656564454649": "BIOS boot",
}


@dataclass
class Partition:
    index: int
    scheme: str                 # "MBR" ou "GPT"
    start_offset: int           # offset em bytes na imagem
    length: int                 # tamanho em bytes
    type_code: str              # codigo/GUID do tipo
    type_desc: str              # descricao legivel
    name: str = ""              # rotulo GPT, quando houver
    flags: str = ""
    fs_hint: str = ""           # assinatura de FS detectada (preenchida depois)
    bitlocker: bool = False     # preenchido pelo detector BitLocker

    @property
    def start_sector(self) -> int:
        return self.start_offset // SECTOR

    def human_size(self) -> str:
        return _human(self.length)


def _human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n:.1f} TiB"


def _parse_gpt(image, sector_size: int = SECTOR) -> List[Partition]:
    hdr = image.read(1 * sector_size, sector_size)
    if hdr[0:8] != b"EFI PART":
        return []
    part_lba, = struct.unpack_from("<Q", hdr, 72)
    num_entries, = struct.unpack_from("<I", hdr, 80)
    entry_size, = struct.unpack_from("<I", hdr, 84)

    parts: List[Partition] = []
    table = image.read(part_lba * sector_size, num_entries * entry_size)
    idx = 0
    for i in range(num_entries):
        base = i * entry_size
        entry = table[base:base + entry_size]
        if len(entry) < 128:
            break
        type_guid_raw = entry[0:16]
        if type_guid_raw == b"\x00" * 16:
            continue
        type_guid = str(uuid.UUID(bytes_le=type_guid_raw)).upper()
        first_lba, last_lba = struct.unpack_from("<QQ", entry, 32)
        attrs, = struct.unpack_from("<Q", entry, 48)
        name = entry[56:128].decode("utf-16-le", "ignore").rstrip("\x00")
        idx += 1
        parts.append(Partition(
            index=idx,
            scheme="GPT",
            start_offset=first_lba * sector_size,
            length=(last_lba - first_lba + 1) * sector_size,
            type_code=type_guid,
            type_desc=GPT_TYPES.get(type_guid, "Desconhecido"),
            name=name,
            flags=f"attr=0x{attrs:x}" if attrs else "",
        ))
    return parts


def _parse_mbr(image, sector_size: int = SECTOR) -> List[Partition]:
    mbr = image.read(0, sector_size)
    if mbr[510:512] != b"\x55\xAA":
        return []

    parts: List[Partition] = []
    idx = 0
    for i in range(4):
        base = 446 + i * 16
        entry = mbr[base:base + 16]
        ptype = entry[4]
        start_lba, num_sectors = struct.unpack_from("<II", entry, 8)
        if ptype == 0x00 or num_sectors == 0:
            continue
        if ptype == 0xEE:  # GPT protective -> parse GPT
            gpt = _parse_gpt(image, sector_size)
            if gpt:
                return gpt
        idx += 1
        parts.append(Partition(
            index=idx,
            scheme="MBR",
            start_offset=start_lba * sector_size,
            length=num_sectors * sector_size,
            type_code=f"0x{ptype:02X}",
            type_desc=MBR_TYPES.get(ptype, "Desconhecido"),
            flags="boot" if entry[0] == 0x80 else "",
        ))
    return parts


def _detect_fs(image, part: Partition) -> str:
    """Detecta a assinatura do sistema de arquivos no inicio da particao."""
    head = image.read(part.start_offset, 16)
    if head[3:11] == b"-FVE-FS-":
        return "BitLocker (-FVE-FS-)"
    if head[3:11] == b"MSWIN4.1" and _looks_bitlocker_togo(image, part):
        return "BitLocker To Go"
    if head[3:11] == b"NTFS    ":
        return "NTFS"
    if head[3:11] in (b"EXFAT   ",):
        return "exFAT"
    boot = image.read(part.start_offset, 0x60)
    if boot[0x52:0x5A] == b"FAT32   ":
        return "FAT32"
    return ""


def _looks_bitlocker_togo(image, part: Partition) -> bool:
    # BitLocker To Go usa boot sector tipo FAT, mas contem o GUID FVE.
    data = image.read(part.start_offset, 512)
    return b"\x3b\xd6\x67\x49\x29\x2e\xd8\x4a" in data  # BitLocker To Go GUID (parcial)


def parse(image, sector_size: int = SECTOR) -> List[Partition]:
    """Retorna a lista de particoes da imagem (GPT tem prioridade sobre MBR)."""
    parts = _parse_mbr(image, sector_size)
    if not parts:
        parts = _parse_gpt(image, sector_size)
    for p in parts:
        try:
            p.fs_hint = _detect_fs(image, p)
        except Exception:
            p.fs_hint = ""
    return parts
