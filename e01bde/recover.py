"""
Recuperacao de senha/chave do BitLocker.

Duas estrategias, da mais barata para a mais cara:

1. Clear Key: se o volume estiver suspenso, a VMK esta em claro -> recuperavel
   imediatamente (sem ataque).
2. Verificacao local de um candidato (senha de usuario OU senha de recuperacao
   de 48 digitos) que o usuario ja possua, reproduzindo a derivacao de chave do
   BitLocker e validando por AES-CCM (sem falso-positivo).
3. Ataque de dicionario/forca bruta via hashcat (-m 22100) sobre o hash
   extraido dos metadados. Esta e a unica via quando so se tem a imagem e
   existe um protector de senha de usuario fraca.

A verificacao local (2) e "best-effort" e serve para confirmar uma chave ja
conhecida sem GPU; o hashcat/dislocker continuam sendo as referencias para
quebra em escala.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from typing import List, Optional

from .fve import Protector, BitLockerVolume


# --------------------------------------------------------------------------- #
# Derivacao de chave do BitLocker (stretch key) e verificacao por AES-CCM
# --------------------------------------------------------------------------- #

def _stretch_key(password_hash: bytes, salt: bytes, iterations: int = 0x100000) -> bytes:
    """Algoritmo de alongamento de chave do BitLocker (1.048.576 iteracoes).

    Estrutura de 88 bytes repetidamente re-hashada com SHA-256:
      [0:32]  updated_hash (inicia zerado)
      [32:64] password_hash
      [64:80] salt (16 bytes)
      [80:88] contador (uint64 LE)

    `iterations` e fixo em 0x100000 no BitLocker; e parametrizado apenas para
    permitir testes rapidos.
    """
    buf = bytearray(88)
    buf[32:64] = password_hash
    buf[64:80] = salt
    for i in range(iterations):
        struct.pack_into("<Q", buf, 80, i)
        buf[0:32] = hashlib.sha256(bytes(buf)).digest()
    return bytes(buf[0:32])


def _password_hash_user(password: str) -> bytes:
    """SHA-256 duplo do password em UTF-16LE (protector de senha de usuario)."""
    pw = password.encode("utf-16-le")
    return hashlib.sha256(hashlib.sha256(pw).digest()).digest()


def _recovery_to_bytes(recovery: str) -> Optional[bytes]:
    """Converte uma senha de recuperacao de 48 digitos em 16 bytes.

    Formato: 8 grupos de 6 digitos. Cada grupo deve ser divisivel por 11 e,
    apos a divisao, caber em 16 bits.
    """
    digits = re.sub(r"[^0-9]", "", recovery)
    if len(digits) != 48:
        return None
    out = bytearray()
    for i in range(8):
        block = int(digits[i * 6:(i + 1) * 6])
        if block % 11 != 0:
            return None
        val = block // 11
        if val > 0xFFFF:
            return None
        out += struct.pack("<H", val)
    return bytes(out)


def _password_hash_recovery(recovery_bytes: bytes) -> bytes:
    """SHA-256 simples dos 16 bytes (protector de senha de recuperacao)."""
    return hashlib.sha256(recovery_bytes).digest()


def protector_from_hashcat(hash_str: str) -> Protector:
    """Reconstroi um Protector a partir de um hash no formato hashcat -m 22100.

    Util para validar/verificar a partir de um hash ja extraido (ex.: vetores
    de teste ou hashes obtidos por bitlocker2john).
    """
    parts = hash_str.strip().split("$")
    # ['', 'bitlocker', htype, saltlen, salt, iter, noncelen, nonce, datalen, data]
    if len(parts) < 10 or parts[1] != "bitlocker":
        raise ValueError("Hash nao esta no formato $bitlocker$ do hashcat.")
    htype = int(parts[2])
    salt = bytes.fromhex(parts[4])
    nonce = bytes.fromhex(parts[7])
    data = bytes.fromhex(parts[9])
    ptype = 0x0800 if htype in (2, 3) else 0x2000
    from .fve import PROTECTION_TYPES
    return Protector(
        protection_type=ptype,
        protection_desc=PROTECTION_TYPES.get(ptype, "?"),
        guid="(de hash)", salt=salt, nonce=nonce,
        aes_ccm_data=data, attackable=True,
    )


def verify_candidate(protector: Protector, candidate: str,
                     iterations: int = 0x100000) -> Optional[bytes]:
    """Testa um candidato contra um protector. Retorna a VMK em claro se bater.

    Requer a biblioteca 'cryptography' (AES-CCM). Sem ela, retorna None e a
    camada superior deve avisar que a verificacao local esta indisponivel.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    except ImportError:
        raise RuntimeError(
            "Biblioteca 'cryptography' ausente (pip install cryptography) — "
            "verificacao local de candidato indisponivel."
        )
    if not (protector.salt and protector.nonce and protector.aes_ccm_data):
        return None

    if protector.protection_type == 0x2000:
        ph = _password_hash_user(candidate)
    elif protector.protection_type == 0x0800:
        rb = _recovery_to_bytes(candidate)
        if rb is None:
            return None
        ph = _password_hash_recovery(rb)
    else:
        return None

    key = _stretch_key(ph, protector.salt, iterations)

    # BitLocker guarda MAC(16) || ciphertext; a lib espera ciphertext || tag.
    mac, ct = protector.aes_ccm_data[:16], protector.aes_ccm_data[16:]
    aesccm = AESCCM(key, tag_length=16)
    try:
        plaintext = aesccm.decrypt(protector.nonce, ct + mac, None)
    except Exception:
        return None  # MAC nao confere -> candidato incorreto
    return plaintext  # metadados com a VMK em claro (candidato correto)


# --------------------------------------------------------------------------- #
# Clear Key (volume suspenso)
# --------------------------------------------------------------------------- #

def recover_clear_key(protector: Protector) -> Optional[bytes]:
    """Recupera a VMK quando ha um protector Clear Key (BitLocker suspenso)."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    except ImportError:
        return None
    if not (protector.clear_key and protector.nonce and protector.aes_ccm_data):
        return None
    key = protector.clear_key[:32]
    mac, ct = protector.aes_ccm_data[:16], protector.aes_ccm_data[16:]
    try:
        return AESCCM(key, tag_length=16).decrypt(protector.nonce, ct + mac, None)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Ataque via hashcat
# --------------------------------------------------------------------------- #

@dataclass
class AttackResult:
    cracked: bool
    password: Optional[str] = None
    tool: str = ""
    raw_output: str = ""
    note: str = ""


def find_tool(name: str) -> Optional[str]:
    """Localiza um binario (hashcat / john / bitlocker2john) no PATH."""
    candidates = [name]
    if os.name == "nt":
        candidates += [name + ".exe", name + ".bin"]
    for c in candidates:
        p = shutil.which(c)
        if p:
            return p
    return None


def run_hashcat(hash_str: str, wordlist: Optional[str] = None,
                mask: Optional[str] = None, hashcat_path: Optional[str] = None,
                extra_args: Optional[List[str]] = None,
                progress_cb=None) -> AttackResult:
    """Executa hashcat -m 22100 sobre o hash do BitLocker.

    - wordlist: caminho para dicionario (ataque -a 0).
    - mask: mascara de forca bruta (ataque -a 3), ex.: "?d?d?d?d?d?d".
    Um dos dois deve ser fornecido.
    """
    hc = hashcat_path or find_tool("hashcat")
    if not hc:
        return AttackResult(False, tool="hashcat", note=(
            "hashcat nao encontrado no PATH. Baixe em https://hashcat.net/hashcat/ "
            "e aponte o caminho, ou use o hash extraido manualmente."))

    tmpdir = tempfile.mkdtemp(prefix="e01bde_")
    hash_file = os.path.join(tmpdir, "bitlocker.hash")
    pot_file = os.path.join(tmpdir, "cracked.pot")
    with open(hash_file, "w") as fh:
        fh.write(hash_str + "\n")

    cmd = [hc, "-m", "22100", hash_file, "--potfile-path", pot_file,
           "--status", "--status-timer", "10"]
    if wordlist:
        cmd += ["-a", "0", wordlist]
    elif mask:
        cmd += ["-a", "3", mask]
    else:
        return AttackResult(False, tool="hashcat",
                            note="Informe um dicionario (wordlist) ou uma mascara.")
    if extra_args:
        cmd += extra_args

    out_lines: List[str] = []
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout:  # type: ignore
            out_lines.append(line.rstrip())
            if progress_cb:
                progress_cb(line.rstrip())
        proc.wait()
    except Exception as exc:
        return AttackResult(False, tool="hashcat", note=f"Falha ao executar hashcat: {exc}")

    # Le o resultado: hashcat --show lê o potfile.
    password = None
    try:
        show = subprocess.run([hc, "-m", "22100", hash_file, "--show",
                               "--potfile-path", pot_file],
                              capture_output=True, text=True)
        if ":" in show.stdout:
            password = show.stdout.strip().split(":", 1)[-1]
    except Exception:
        pass

    raw = "\n".join(out_lines)
    if password:
        return AttackResult(True, password=password, tool="hashcat", raw_output=raw)
    return AttackResult(False, tool="hashcat", raw_output=raw,
                        note="Senha nao encontrada com os parametros informados.")


def run_bitlocker2john(raw_partition_path: str) -> Optional[str]:
    """Extrai o(s) hash(es) via bitlocker2john (John the Ripper), se disponivel.

    Util como validacao cruzada da extracao propria da ferramenta.
    """
    tool = find_tool("bitlocker2john")
    if not tool:
        return None
    try:
        res = subprocess.run([tool, "-i", raw_partition_path],
                             capture_output=True, text=True, timeout=120)
        return res.stdout
    except Exception:
        return None
