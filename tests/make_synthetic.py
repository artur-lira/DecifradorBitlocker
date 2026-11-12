"""
Gera uma imagem BRUTA sintetica com:
  - MBR + 1 particao NTFS/BitLocker iniciando no setor 2048
  - cabecalho de volume BitLocker (-FVE-FS-) + GUID + 3 offsets FVE
  - bloco de metadados FVE com cabecalho + 1 entrada VMK (senha de usuario)
  - stretch key (salt) + AES-CCM encriptado com chave derivada de uma SENHA
    conhecida, para validar o roundtrip de verificacao.

NAO reproduz um volume BitLocker real byte a byte — serve para exercitar o
parsing das estruturas e a logica de derivacao/AES-CCM da ferramenta.
"""
import os
import struct
import sys
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from e01bde.recover import _stretch_key, _password_hash_user  # noqa
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

SECTOR = 512
PART_START_SECTOR = 2048
TEST_PASSWORD = "Senha123!"
TEST_ITERATIONS = 64  # reduzido so para o teste
FVE_REL_OFFSET = 0x10000  # offset dos metadados FVE dentro da particao

BITLOCKER_GUID = bytes.fromhex("3bd667492e2ed84a8399f6a339e3d001")
FVE_SIGNATURE = b"-FVE-FS-"

KNOWN_VMK = bytes(range(0x10, 0x30))                 # 32 bytes (VMK conhecida)
KNOWN_FVEK = bytes(range(0x40, 0x60))                # 32 bytes (FVEK conhecida)


def build_entry(entry_type, value_type, data, version=1):
    size = 8 + len(data)
    return struct.pack("<HHHH", size, entry_type, value_type, version) + data


def _key_entry(raw_key, method=0x8004):
    """Plaintext de uma entrada 'key': header(8)+reservado(2)+metodo(2)+chave."""
    body = struct.pack("<HH", 0x0000, method) + raw_key
    return build_entry(0x0000, 0x0001, body)  # value_type 0x0001 = KEY


def _aes_ccm_encrypt(enc_key, plaintext, nonce):
    ct_tag = AESCCM(enc_key, tag_length=16).encrypt(nonce, plaintext, None)
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    return nonce + tag + ct  # BitLocker: nonce || MAC || ciphertext


def build_aes_ccm_property(password, salt):
    """Propriedade AES-CCM que protege a VMK com a chave derivada da senha."""
    key = _stretch_key(_password_hash_user(password), salt, iterations=TEST_ITERATIONS)
    ccm_data = _aes_ccm_encrypt(key, _key_entry(KNOWN_VMK), bytes(range(12)))
    return build_entry(0x0000, 0x0005, ccm_data)


def build_fvek_entry():
    """Entrada FVEK: a FVEK cifrada (AES-CCM) com a VMK.

    Formato REAL (plano): entry_type 0x0003, value_type 0x0005, e o dado da
    entrada e o proprio bloco AES-CCM (nonce || MAC || FVEK cifrada).
    """
    ccm_data = _aes_ccm_encrypt(KNOWN_VMK, _key_entry(KNOWN_FVEK), bytes(range(20, 32)))
    return build_entry(0x0003, 0x0005, ccm_data)  # entry_type 0x0003, value 0x0005


def build_stretch_key(password):
    salt = bytes(range(16, 32))
    method = struct.pack("<I", 0x1000)
    ccm_prop = build_aes_ccm_property(password, salt)
    data = method + salt + ccm_prop
    return build_entry(0x0000, 0x0003, data)


def build_vmk(password):
    guid = bytes(range(16))              # VMK GUID
    mod_time = b"\x00" * 8
    unknown = b"\x00\x00"
    prot_type = struct.pack("<H", 0x2000)  # senha de usuario
    header = guid + mod_time + unknown + prot_type
    stretch = build_stretch_key(password)
    return build_entry(0x0002, 0x0000, header + stretch)


def build_fve_metadata(password):
    vmk = build_vmk(password)
    header_size = 0x30
    # cabecalho de metadados FVE
    volume_guid = bytes(range(0x40, 0x50))
    enc_method = struct.pack("<I", 0x8004)  # AES-XTS 128
    creation = b"\x00" * 8
    nonce_counter = b"\x00" * 4
    body = vmk + build_fvek_entry()
    meta_size = header_size + len(body)
    md_header = (struct.pack("<I", meta_size) + struct.pack("<I", 1) +
                 struct.pack("<I", header_size) + struct.pack("<I", meta_size) +
                 volume_guid + nonce_counter + enc_method + creation)
    assert len(md_header) == header_size, len(md_header)
    # cabecalho do bloco FVE
    block_header = FVE_SIGNATURE + struct.pack("<H", 0) + struct.pack("<H", 2)
    block_header += b"\x00" * (0x40 - len(block_header))  # bloco de 64 bytes
    return block_header + md_header + body


def build_volume_header():
    vh = bytearray(512)
    vh[0:3] = b"\xeb\x58\x90"
    vh[3:11] = FVE_SIGNATURE
    vh[0xA8:0xB8] = BITLOCKER_GUID
    struct.pack_into("<QQQ", vh, 0xB8, FVE_REL_OFFSET, FVE_REL_OFFSET, FVE_REL_OFFSET)
    vh[510:512] = b"\x55\xAA"
    return bytes(vh)


def build_mbr(part_sectors):
    mbr = bytearray(512)
    # entrada 1: bootavel, tipo 0x07, inicio PART_START_SECTOR
    off = 446
    mbr[off] = 0x80
    mbr[off + 4] = 0x07
    struct.pack_into("<II", mbr, off + 8, PART_START_SECTOR, part_sectors)
    mbr[510:512] = b"\x55\xAA"
    return bytes(mbr)


def main(out_path):
    part_sectors = (FVE_REL_OFFSET + 0x10000) // SECTOR
    total_sectors = PART_START_SECTOR + part_sectors
    with open(out_path, "wb") as fh:
        fh.write(build_mbr(part_sectors))
        fh.seek((PART_START_SECTOR) * SECTOR)
        fh.write(build_volume_header())
        fh.seek(PART_START_SECTOR * SECTOR + FVE_REL_OFFSET)
        fh.write(build_fve_metadata(TEST_PASSWORD))
        fh.truncate(total_sectors * SECTOR)
    print(f"Imagem sintetica criada: {out_path}")
    print(f"  Senha de teste: {TEST_PASSWORD}  (iteracoes reduzidas={TEST_ITERATIONS})")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "synthetic.dd")
