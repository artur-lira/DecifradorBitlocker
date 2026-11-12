"""
Parser de metadados do BitLocker (FVE - Full Volume Encryption).

Implementa a leitura das estruturas descritas pela libbde:
  - cabecalho de volume (-FVE-FS-) e os tres offsets de metadados FVE;
  - cabecalho do bloco de metadados e cabecalho de metadados FVE;
  - entradas de metadados, com foco nas entradas VMK (Volume Master Key);
  - enumeracao dos protectors (senha, senha de recuperacao, TPM, etc.);
  - extracao do hash atacavel no formato hashcat (-m 22100).

Referencias de formato: documentacao do projeto libbde (Joachim Metz).
"""
from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from typing import List, Optional

# GUID identificador do BitLocker no cabecalho do volume
# {4967D63B-2E29-4AD8-8399-F6A339E3D001}
BITLOCKER_GUID = bytes.fromhex("3bd667492e2ed84a8399f6a339e3d001")

FVE_SIGNATURE = b"-FVE-FS-"

# Tipos de protecao da VMK (key protection type)
PROTECTION_TYPES = {
    0x0000: "Clear Key (BitLocker SUSPENSO - recuperavel imediatamente)",
    0x0100: "TPM",
    0x0200: "Startup Key (chave externa em USB)",
    0x0500: "TPM + PIN",
    0x0800: "Senha de recuperacao (48 digitos)",
    0x1000: "TPM + Startup Key",
    0x1100: "TPM + PIN + Startup Key",
    0x2000: "Senha de usuario",
}

# Entradas de metadados
ENTRY_TYPE_PROPERTY = 0x0000
ENTRY_TYPE_VMK = 0x0002
ENTRY_TYPE_FVEK = 0x0003
ENTRY_TYPE_VALIDATION = 0x0004
ENTRY_TYPE_STARTUP_KEY = 0x0006
ENTRY_TYPE_DESCRIPTION = 0x0007

# Tipos de valor (value type)
VALUE_ERASED = 0x0000
VALUE_KEY = 0x0001
VALUE_UNICODE = 0x0002
VALUE_STRETCH_KEY = 0x0003
VALUE_USE_KEY = 0x0004
VALUE_AES_CCM_ENCRYPTED = 0x0005
VALUE_TPM_ENCODED = 0x0006
VALUE_VALIDATION = 0x0007
VALUE_VMK = 0x0008
VALUE_EXTERNAL_KEY = 0x0009
VALUE_OFFSET_SIZE = 0x000F

# Metodos de criptografia do volume
ENCRYPTION_METHODS = {
    0x0000: "Nenhum (nao criptografado)",
    0x1000: "Stretch Key",
    0x2000: "AES-CCM 256",
    0x2001: "Chave extern (RAW)",
    0x8000: "AES 128 + Diffuser (Elephant)",
    0x8001: "AES 256 + Diffuser (Elephant)",
    0x8002: "AES 128 (CBC)",
    0x8003: "AES 256 (CBC)",
    0x8004: "AES-XTS 128",
    0x8005: "AES-XTS 256",
}

BITLOCKER_ITERATIONS = 0x100000  # 1.048.576 iteracoes SHA-256 (fixo)


@dataclass
class Protector:
    """Um protector (VMK) encontrado nos metadados."""
    protection_type: int
    protection_desc: str
    guid: str
    salt: Optional[bytes] = None          # 16 bytes (stretch key)
    nonce: Optional[bytes] = None         # 12 bytes (AES-CCM)
    aes_ccm_data: Optional[bytes] = None  # MAC + VMK cifrada
    clear_key: Optional[bytes] = None     # chave em claro (clear key)
    attackable: bool = False              # senha/recuperacao -> hashcat
    instant: bool = False                 # clear key -> recuperavel ja

    def hashcat_hash(self, with_mac: bool = True) -> Optional[str]:
        """Produz o hash no formato hashcat -m 22100 / -m 22101.

        type 0: senha de usuario (sem verificacao MAC)
        type 1: senha de usuario (com verificacao MAC)
        type 2: senha de recuperacao (sem MAC)
        type 3: senha de recuperacao (com MAC)
        """
        if not (self.salt and self.nonce and self.aes_ccm_data):
            return None
        if self.protection_type == 0x2000:
            htype = 1 if with_mac else 0
        elif self.protection_type == 0x0800:
            htype = 3 if with_mac else 2
        else:
            return None
        return (
            f"$bitlocker${htype}${len(self.salt)}${self.salt.hex()}"
            f"${BITLOCKER_ITERATIONS}${len(self.nonce)}${self.nonce.hex()}"
            f"${len(self.aes_ccm_data)}${self.aes_ccm_data.hex()}"
        )


@dataclass
class BitLockerVolume:
    present: bool
    partition_offset: int
    encryption_method: int = 0
    encryption_desc: str = ""
    volume_guid: str = ""
    protectors: List[Protector] = field(default_factory=list)
    fve_offsets: List[int] = field(default_factory=list)
    note: str = ""
    # FVEK (chave de criptografia do volume) cifrada pela VMK
    fvek_nonce: Optional[bytes] = None
    fvek_ccm_data: Optional[bytes] = None
    # Backup dos setores de boot NTFS originais (realocados pelo BitLocker)
    volume_header_offset: int = 0
    volume_header_size: int = 0
    encrypted_volume_size: int = 0

    def attackable_protectors(self) -> List[Protector]:
        return [p for p in self.protectors if p.attackable]

    def has_clear_key(self) -> bool:
        return any(p.instant for p in self.protectors)


def _iter_entries(buf: bytes, start: int, end: int):
    """Itera entradas de metadados (size, entry_type, value_type, version)."""
    pos = start
    while pos + 8 <= end:
        size, entry_type, value_type, version = struct.unpack_from("<HHHH", buf, pos)
        if size < 8 or pos + size > end:
            break
        data = buf[pos + 8: pos + size]
        yield entry_type, value_type, version, data
        pos += size


def _parse_stretch_and_ccm(prop_data: bytes, protector: Protector):
    """Dentro da VMK: localiza stretch key (salt) e AES-CCM (nonce+dados)."""
    # Procura entradas aninhadas dentro desta propriedade.
    for etype, vtype, _ver, data in _iter_entries(prop_data, 0, len(prop_data)):
        if vtype == VALUE_STRETCH_KEY:
            # Stretch key: [4 bytes metodo][16 bytes salt][AES-CCM aninhado]
            if len(data) >= 20:
                protector.salt = data[4:20]
                # o restante contem a propriedade AES-CCM aninhada
                for e2, v2, _v, d2 in _iter_entries(data, 20, len(data)):
                    if v2 == VALUE_AES_CCM_ENCRYPTED and len(d2) >= 12:
                        protector.nonce = d2[0:12]
                        protector.aes_ccm_data = d2[12:]
        elif vtype == VALUE_AES_CCM_ENCRYPTED:
            # AES-CCM direto (clear key tambem passa por aqui)
            if len(data) >= 12 and protector.nonce is None:
                protector.nonce = data[0:12]
                protector.aes_ccm_data = data[12:]
        elif vtype == VALUE_KEY:
            # Chave em claro (clear key): [2 metodo][2 ?][chave]
            if len(data) >= 4:
                protector.clear_key = data[4:]


def _parse_vmk(data: bytes) -> Protector:
    """Interpreta uma entrada VMK."""
    guid = str(uuid.UUID(bytes_le=data[0:16])).upper()
    protection_type, = struct.unpack_from("<H", data, 0x1A)
    desc = PROTECTION_TYPES.get(protection_type, f"Desconhecido (0x{protection_type:04X})")
    prot = Protector(protection_type=protection_type, protection_desc=desc, guid=guid)

    # As propriedades aninhadas comecam apos o cabecalho da VMK (offset 0x1c).
    _parse_stretch_and_ccm(data[0x1C:], prot)

    if protection_type in (0x2000, 0x0800) and prot.salt and prot.aes_ccm_data:
        prot.attackable = True
    if protection_type == 0x0000:
        prot.instant = True
    return prot


def _find_metadata_header(block: bytes) -> int:
    """Localiza o cabecalho de metadados FVE dentro do bloco.

    Cabecalho: [size:4][version:4][header_size:4][size_copy:4]...
    header_size == 0x30 e size == size_copy validam a posicao.
    """
    for off in range(0, min(256, len(block) - 16)):
        size, version, header_size, size_copy = struct.unpack_from("<IIII", block, off)
        if header_size == 0x30 and size == size_copy and 0x30 <= size <= len(block):
            return off
    return -1


def parse_bitlocker(image, partition_offset: int) -> BitLockerVolume:
    """Detecta e interpreta o BitLocker em uma particao (offset em bytes)."""
    header = image.read(partition_offset, 512)

    sig = header[3:11]
    guid_at_a8 = header[0xA8:0xB8]
    is_bitlocker = (sig == FVE_SIGNATURE) or (guid_at_a8 == BITLOCKER_GUID)
    if not is_bitlocker:
        return BitLockerVolume(present=False, partition_offset=partition_offset)

    vol = BitLockerVolume(present=True, partition_offset=partition_offset)

    # Tres offsets de metadados FVE (relativos ao inicio da particao).
    off1, off2, off3 = struct.unpack_from("<QQQ", header, 0xB8)
    vol.fve_offsets = [off1, off2, off3]
    # Backup dos setores NTFS originais realocados pelo BitLocker.
    vol.volume_header_offset, vol.volume_header_size = struct.unpack_from("<QQ", header, 0xD0)

    parsed = False
    for rel in vol.fve_offsets:
        if rel == 0 or rel > image.size:
            continue
        try:
            block = image.read(partition_offset + rel, 64 * 1024)
        except Exception:
            continue
        if block[0:8] != FVE_SIGNATURE:
            # alguns layouts nao repetem a assinatura no bloco; segue tentando
            pass
        mh = _find_metadata_header(block)
        if mh < 0:
            continue

        meta_size, version, header_size, _copy = struct.unpack_from("<IIII", block, mh)
        vol.volume_guid = str(uuid.UUID(bytes_le=block[mh + 0x10: mh + 0x20])).upper()
        enc, = struct.unpack_from("<I", block, mh + 0x24)
        # alguns layouts guardam o metodo como 2 bytes
        enc16, = struct.unpack_from("<H", block, mh + 0x24)
        vol.encryption_method = enc16
        vol.encryption_desc = ENCRYPTION_METHODS.get(enc16, f"0x{enc16:04X}")

        entries_start = mh + header_size
        entries_end = min(mh + meta_size, len(block))
        vhb_set = False
        for etype, vtype, _ver, data in _iter_entries(block, entries_start, entries_end):
            if vtype == VALUE_OFFSET_SIZE and len(data) >= 16 and not vhb_set:
                # "Volume header block": offset+size do backup dos setores de
                # boot NTFS realocados pelo BitLocker (fonte autoritativa no
                # Win7+; substitui o campo 0xD0 do cabecalho).
                o, s = struct.unpack_from("<QQ", data, 0)
                if 0 < o < image.size and 0 < s <= 1024 * 1024:
                    vol.volume_header_offset = o
                    vol.volume_header_size = s
                    vhb_set = True
            if etype == ENTRY_TYPE_VMK and len(data) >= 0x1C:
                try:
                    vol.protectors.append(_parse_vmk(data))
                except Exception:
                    continue
            elif etype == ENTRY_TYPE_FVEK and vol.fvek_ccm_data is None:
                # FVEK: a chave do volume cifrada por AES-CCM (nonce+MAC+chave).
                # Formato real (plano): a propria entrada tem value_type 0x0005.
                if vtype == VALUE_AES_CCM_ENCRYPTED and len(data) >= 12:
                    vol.fvek_nonce = data[0:12]
                    vol.fvek_ccm_data = data[12:]
                else:
                    # Formato aninhado: busca a propriedade AES-CCM interna.
                    for _e, v2, _v, d2 in _iter_entries(data, 0, len(data)):
                        if v2 == VALUE_AES_CCM_ENCRYPTED and len(d2) >= 12:
                            vol.fvek_nonce = d2[0:12]
                            vol.fvek_ccm_data = d2[12:]
        if vol.protectors:
            parsed = True
            break

    if not parsed and not vol.protectors:
        vol.note = (
            "Volume BitLocker detectado, mas nao foi possivel interpretar os "
            "metadados FVE (versao/layout nao suportado). Tente bitlocker2john."
        )
    return vol
