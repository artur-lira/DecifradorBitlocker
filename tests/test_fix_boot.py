"""
Teste automatizado da restauracao do setor de boot (fix_boot_sectors).

Monta um "volume" bruto contendo, em um offset de backup, um setor de boot
NTFS cifrado com AES-XTS (mesma convencao do exportador). Em seguida chama
fix_boot_sectors com volume_header_offset=0 (forcando a VARREDURA) e verifica
que o inicio do .img passa a conter um boot sector NTFS valido.

Executar:  python tests/test_fix_boot.py   (ou via pytest)
"""
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa
from e01bde import export as X  # noqa
from e01bde.ewfimage import RawImage  # noqa

SECTOR = 512
BACKUP_OFF = 50 * 1024 * 1024          # backup a 50 MiB dentro do volume
VOL_SIZE = 64 * 1024 * 1024


class _Vol:
    encryption_method = 0x8004          # AES-XTS 128
    volume_header_offset = 0            # forca a varredura
    volume_header_size = 0x200
    fve_offsets = []


def _ntfs_boot() -> bytes:
    b = bytearray(512)
    b[0:3] = b"\xeb\x52\x90"
    b[3:11] = b"NTFS    "
    b[510:512] = b"\x55\xAA"
    return bytes(b)


def run():
    fvek = os.urandom(32)
    tweak = struct.pack("<Q", BACKUP_OFF // SECTOR) + b"\x00" * 8
    enc = Cipher(algorithms.AES(fvek), modes.XTS(tweak)).encryptor()
    cipher_boot = enc.update(_ntfs_boot()) + enc.finalize()

    tmp = tempfile.mkdtemp(prefix="fixboot_")
    vol_path = os.path.join(tmp, "vol.raw")
    with open(vol_path, "wb") as f:
        f.truncate(VOL_SIZE)
        f.seek(BACKUP_OFF)
        f.write(cipher_boot)

    out = os.path.join(tmp, "out.img")
    with open(out, "wb") as f:
        f.write(os.urandom(512))        # inicio "errado"
        f.truncate(1 * 1024 * 1024)

    img = RawImage(vol_path)
    res = X.fix_boot_sectors(img, _Vol(), 0, out, fvek,
                             scan_limit=VOL_SIZE)
    assert res.get("ok"), f"fix_boot_sectors falhou: {res}"
    assert res.get("offset") == BACKUP_OFF, res
    fs = X.check_decrypted_fs(out)
    assert fs == "NTFS", f"FS inesperado: {fs!r}"
    print(f"OK: boot localizado no offset {res['offset']} e .img reconhecido como {fs}.")


if __name__ == "__main__":
    run()
