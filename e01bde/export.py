"""
Exportacao da particao BitLocker DESCRIPTOGRAFADA para uma imagem .img
montavel, apos a recuperacao da chave.

Cadeia: senha/recuperacao/clear key -> VMK -> FVEK -> decifra os setores.

Duas vias de decifragem:
  (A) dislocker  (RECOMENDADO): implementacao de referencia, trata
      AES-CBC, Elephant diffuser e AES-XTS, e a realocacao dos setores de boot.
  (B) nativa AES-XTS (EXPERIMENTAL): para Win10/11 (AES-XTS 128/256) quando o
      dislocker nao estiver disponivel. Deve ser conferida contra a via (A) ou
      montando a imagem antes de uso definitivo.
"""
from __future__ import annotations

import os
import shutil
import struct
import subprocess
from typing import Optional

from .fve import BitLockerVolume, Protector
from . import recover as R


SECTOR = 512


# --------------------------------------------------------------------------- #
# Extracao de VMK e FVEK
# --------------------------------------------------------------------------- #

def _key_bytes_from_plaintext(plaintext: bytes) -> bytes:
    """Extrai a chave crua de um 'key' decifrado (entrada de metadados).

    Layout: [size:2][entry_type:2][value_type:2][version:2]
            [reservado:2][metodo:2][chave...]
    """
    if len(plaintext) < 12:
        return plaintext
    return plaintext[12:]


def recover_vmk(volume: BitLockerVolume, candidate: Optional[str] = None,
                recovery: Optional[str] = None,
                iterations: int = 0x100000) -> Optional[bytes]:
    """Recupera a VMK a partir de clear key, senha de usuario ou recuperacao."""
    # 1) Clear key
    for prot in volume.protectors:
        if prot.instant:
            pt = R.recover_clear_key(prot)
            if pt:
                return _key_bytes_from_plaintext(pt)
    # 2) Candidato informado
    if candidate or recovery:
        cand = recovery or candidate
        ttype = 0x0800 if recovery else 0x2000
        for prot in volume.protectors:
            if prot.protection_type != ttype:
                continue
            pt = R.verify_candidate(prot, cand, iterations)
            if pt is not None:
                return _key_bytes_from_plaintext(pt)
    return None


def decrypt_fvek(volume: BitLockerVolume, vmk: bytes) -> Optional[bytes]:
    """Decifra a FVEK (chave do volume) usando a VMK (AES-CCM)."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    except ImportError:
        return None
    if not (volume.fvek_nonce and volume.fvek_ccm_data):
        return None
    mac, ct = volume.fvek_ccm_data[:16], volume.fvek_ccm_data[16:]
    try:
        pt = AESCCM(vmk[:32], tag_length=16).decrypt(volume.fvek_nonce, ct + mac, None)
    except Exception:
        return None
    return _key_bytes_from_plaintext(pt)


# --------------------------------------------------------------------------- #
# Via A — dislocker (recomendada)
# --------------------------------------------------------------------------- #

def export_via_dislocker(partition_dd: str, out_img: str,
                         password: Optional[str] = None,
                         recovery: Optional[str] = None,
                         vmk_file: Optional[str] = None,
                         dislocker_path: Optional[str] = None) -> bool:
    """Decifra `partition_dd` (particao bruta) para `out_img` via dislocker-file.

    Informe UMA credencial: password (senha de usuario), recovery (48 digitos)
    ou vmk_file (arquivo com a VMK em claro).
    """
    tool = dislocker_path or R.find_tool("dislocker-file") or R.find_tool("dislocker")
    if not tool:
        raise RuntimeError(
            "dislocker nao encontrado. Instale (Linux: apt install dislocker; "
            "no Windows use WSL) ou utilize a via nativa AES-XTS.")
    cmd = [tool, "-V", partition_dd]
    if password:
        cmd.append(f"-u{password}")
    elif recovery:
        cmd.append(f"-p{recovery}")
    elif vmk_file:
        cmd += ["-K", vmk_file]
    else:
        raise ValueError("Informe password, recovery ou vmk_file.")
    cmd += ["--", out_img]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"dislocker falhou: {res.stderr.strip() or res.stdout.strip()}")
    return os.path.isfile(out_img) and os.path.getsize(out_img) > 0


# --------------------------------------------------------------------------- #
# Via B — nativa AES-XTS (experimental)
# --------------------------------------------------------------------------- #

CHUNK = 8 * 1024 * 1024          # (compat) bloco antigo de 8 MiB
IO_BUF = 64 * 1024 * 1024        # buffer de I/O grande (64 MiB) p/ reduzir seeks
SUB = 8 * 1024 * 1024            # sub-bloco por worker na decifragem paralela


def _decrypt_region(key: bytes, base_offset: int, buf: bytes,
                    meta_regions) -> bytes:
    """Decifra um bloco de `buf` (setor a setor, AES-XTS).

    Funcao de NIVEL DE MODULO para poder rodar em ProcessPoolExecutor.
    `base_offset` e o offset do bloco relativo ao inicio da particao.
    Setores dentro das regioes de metadados FVE sao copiados sem alterar.

    Usa o laco nativo (ctypes->OpenSSL) quando disponivel; senao, recai na
    biblioteca `cryptography`.
    """
    try:
        from . import xts_native
        if xts_native.available():
            return xts_native.decrypt_region(key, base_offset, buf, meta_regions)
    except Exception:
        pass
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    aes = algorithms.AES(key)
    n = len(buf)
    out = bytearray(n)
    off = 0
    while off < n:
        seclen = min(SECTOR, n - off)
        abs_off = base_offset + off
        skip = seclen < SECTOR
        if not skip:
            for start, size in meta_regions:
                if start <= abs_off < start + size:
                    skip = True
                    break
        if skip:
            out[off:off + seclen] = buf[off:off + seclen]
        else:
            tweak = struct.pack("<Q", abs_off // SECTOR) + b"\x00" * 8
            d = Cipher(aes, modes.XTS(tweak)).decryptor()
            out[off:off + SECTOR] = d.update(buf[off:off + SECTOR]) + d.finalize()
        off += SECTOR
    return bytes(out)


def export_native_xts(image, volume: BitLockerVolume, partition_offset: int,
                      partition_length: int, fvek: bytes, out_img: str,
                      progress=None, workers: int = 1,
                      io_buffer: int = IO_BUF) -> str:
    """Decifra a particao (AES-XTS 128/256) para `out_img`.

    I/O em blocos GRANDES (`io_buffer`, 64 MiB por padrao): uma leitura e uma
    escrita sequenciais por bloco, para reduzir o vai-e-vem da cabeca do disco
    (crucial quando origem e destino estao no mesmo HDD). Com `workers` > 1, a
    decifragem de cada bloco e dividida em sub-blocos processados em paralelo.

    EXPERIMENTAL. Trata a realocacao dos setores de boot originais e pula as
    tres regioes de metadados FVE (que nao sao cifradas). Nao implementa o
    Elephant diffuser (AES-CBC Vista/7) — para esses, use a via dislocker.
    """
    if volume.encryption_method not in (0x8004, 0x8005):
        raise RuntimeError(
            f"Via nativa so suporta AES-XTS (0x8004/0x8005). "
            f"Metodo detectado: 0x{volume.encryption_method:04X}. Use dislocker.")

    # Para XTS-128 a FVEK tem 32 bytes (2x128); para XTS-256, 64 bytes (2x256).
    key = fvek[:32] if volume.encryption_method == 0x8004 else fvek[:64]
    meta_regions = [(rel, 64 * 1024) for rel in volume.fve_offsets if rel]
    total = partition_length
    io_buffer = max(SECTOR, (io_buffer // SECTOR) * SECTOR)

    copied = 0
    if workers and workers > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=workers) as ex, open(out_img, "wb") as out:
            pos = 0
            while pos < total:
                raw = image.read(partition_offset + pos, min(io_buffer, total - pos))
                # divide o bloco grande em sub-blocos para os workers (ordenado)
                offs = list(range(0, len(raw), SUB))
                bufs = [raw[o:o + SUB] for o in offs]
                bases = [pos + o for o in offs]
                parts = ex.map(_decrypt_region, [key] * len(offs), bases, bufs,
                               [meta_regions] * len(offs))
                out.write(b"".join(parts))          # uma escrita sequencial grande
                pos += len(raw)
                copied = pos
                if progress:
                    progress(copied, total)
    else:
        with open(out_img, "wb") as out:
            pos = 0
            while pos < total:
                raw = image.read(partition_offset + pos, min(io_buffer, total - pos))
                out.write(_decrypt_region(key, pos, raw, meta_regions))
                pos += len(raw)
                copied = pos
                if progress:
                    progress(copied, total)

    # Restaura os setores de boot NTFS originais (realocados pelo BitLocker).
    fix_boot_sectors(image, volume, partition_offset, out_img, fvek)
    return out_img


def _is_ntfs(buf: bytes) -> bool:
    return (len(buf) >= 512 and buf[3:11] == b"NTFS    "
            and buf[510:512] == b"\x55\xAA")


def fix_boot_sectors(image, volume: BitLockerVolume, partition_offset: int,
                     out_img: str, fvek: bytes,
                     scan_limit: int = 512 * 1024 * 1024,
                     progress=None, log=None) -> dict:
    """Restaura os setores de boot NTFS originais no inicio de `out_img`.

    1) tenta o offset de backup lido dos metadados (tweak fisico e logico);
    2) se falhar, ESCANEIA o inicio do volume procurando o setor que decifra
       para um boot sector NTFS valido (assinatura 'NTFS    ' + 0x55AA).

    Retorna um dict com o resultado. Nao refaz o volume: so corrige o inicio.
    """
    def _log(m):
        if log:
            log(m)

    if volume.encryption_method not in (0x8004, 0x8005):
        return {"ok": False, "reason": "metodo nao AES-XTS"}
    key = fvek[:32] if volume.encryption_method == 0x8004 else fvek[:64]
    size = volume.volume_header_size or 0x2000

    def write_head(dec: bytes):
        with open(out_img, "r+b") as out:
            out.seek(0)
            out.write(dec)

    # 1) offset de backup conhecido (metadados / cabecalho)
    if volume.volume_header_offset:
        region = image.read(partition_offset + volume.volume_header_offset, size)
        for logical in (False, True):
            base = 0 if logical else volume.volume_header_offset
            dec = _decrypt_region(key, base, region, [])
            if _is_ntfs(dec):
                write_head(dec)
                _log(f"[+] Boot restaurado do offset {volume.volume_header_offset} "
                     f"(tweak {'logico' if logical else 'fisico'}).")
                return {"ok": True, "method": "metadata",
                        "offset": volume.volume_header_offset, "logical": logical}

    # 2) varredura por validacao NTFS
    _log("[*] Procurando os setores de boot originais (varredura)...")
    meta = [(r, 64 * 1024) for r in volume.fve_offsets if r]
    limit = min(scan_limit, image.size - partition_offset)
    pos = 0
    STEP = 8 * 1024 * 1024
    while pos < limit:
        chunk = image.read(partition_offset + pos, min(STEP, limit - pos))
        dec = _decrypt_region(key, pos, chunk, meta)
        for i in range(0, len(dec) - 512 + 1, SECTOR):
            if dec[i + 3:i + 11] == b"NTFS    " and dec[i + 510:i + 512] == b"\x55\xAA":
                found = pos + i
                region = image.read(partition_offset + found, size)
                decr = _decrypt_region(key, found, region, [])
                if _is_ntfs(decr):
                    write_head(decr)
                    _log(f"[+] Boot encontrado por varredura no offset {found}.")
                    return {"ok": True, "method": "scan", "offset": found}
        pos += len(chunk)
        if progress:
            progress(pos, limit)
    _log("[!] Nao foi possivel localizar os setores de boot NTFS originais.")
    return {"ok": False, "reason": "boot nao localizado"}


def write_vmk_file(vmk: bytes, path: str) -> str:
    """Grava a VMK em claro no formato aceito pelo dislocker (-K)."""
    with open(path, "wb") as fh:
        fh.write(vmk)
    return path


def default_decrypted_name(image_path: str, partition) -> str:
    """Nome padrao do arquivo exportado.

    Ex.: "Image.bin.E01 - Partition 3 (235,49 GB)_decrypted.img"
    Tamanho em GiB com 2 casas e virgula decimal (padrao pt-BR), rotulo "GB".
    """
    base = os.path.basename(image_path) if image_path else "Image"
    gib = partition.length / (1024 ** 3)
    size = f"{gib:.2f}".replace(".", ",")
    return f"{base} - Partition {partition.index} ({size} GB)_decrypted.img"


def make_progress(log_fn, min_interval: float = 1.0):
    """Cria um callback de progresso que loga % + velocidade (MB/s) + ETA.

    Limita a no maximo uma atualizacao a cada `min_interval` segundos.
    """
    import time
    state = {"start": None, "last": 0.0}

    def cb(copied, total):
        now = time.time()
        if state["start"] is None:
            state["start"] = now
        if now - state["last"] < min_interval and copied < total:
            return
        state["last"] = now
        el = now - state["start"]
        spd = copied / el / 1e6 if el > 0 else 0          # MB/s (10^6)
        eta = (total - copied) / (copied / el) if copied > 0 and el > 0 else 0
        m, s = divmod(int(eta), 60)
        h, m = divmod(m, 60)
        etastr = f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s"
        log_fn(f"{copied/total*100:5.1f}% | {copied/1e9:5.1f}/{total/1e9:.1f} GB "
               f"| {spd:4.0f} MB/s | ETA {etastr}")

    return cb


def check_decrypted_fs(path: str) -> str:
    """Le o primeiro setor da imagem exportada e identifica o FS.

    Serve para validar rapidamente se a decifragem produziu um sistema de
    arquivos reconhecivel (NTFS/exFAT/FAT), indicando sucesso.
    """
    try:
        with open(path, "rb") as fh:
            boot = fh.read(512)
    except Exception:
        return ""
    if len(boot) < 512:
        return ""
    if boot[3:11] == b"NTFS    ":
        return "NTFS"
    if boot[3:11] == b"EXFAT   ":
        return "exFAT"
    if boot[0x52:0x5A] == b"FAT32   ":
        return "FAT32"
    if boot[510:512] == b"\x55\xAA":
        return "boot sector valido (FS nao identificado)"
    return ""
