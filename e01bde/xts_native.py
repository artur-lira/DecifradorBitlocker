"""
Decifragem AES-XTS acelerada via ctypes -> OpenSSL (libcrypto).

Elimina o overhead do Python por setor: o contexto EVP_CIPHER_CTX e a chave
sao configurados UMA vez; a cada setor apenas o tweak (IV de 16 bytes) e
redefinido com EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv). Isso evita
recriar objeto de cifra e re-agendar a chave 460 milhoes de vezes.

Se o libcrypto nao for localizavel, `available()` retorna False e o chamador
usa a implementacao baseada na biblioteca `cryptography`.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import struct
import sys

SECTOR = 512

_lib = None
_loaded = False


def _load_libcrypto():
    candidates = []
    found = ctypes.util.find_library("crypto")
    if found:
        candidates.append(found)
    if os.name == "nt":
        names = ["libcrypto-3-x64.dll", "libcrypto-3.dll",
                 "libcrypto-1_1-x64.dll", "libcrypto-1_1.dll"]
        dirs = [os.path.join(sys.base_prefix, "DLLs"),
                sys.base_prefix,
                os.path.dirname(sys.executable)]
        for d in dirs:
            for n in names:
                p = os.path.join(d, n)
                if os.path.isfile(p):
                    candidates.append(p)
        candidates += names
    else:
        candidates += ["libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"]

    for name in candidates:
        try:
            lib = ctypes.CDLL(name)
            # confere se os simbolos de XTS existem
            if hasattr(lib, "EVP_aes_256_xts") and hasattr(lib, "EVP_CIPHER_CTX_new"):
                return lib
        except OSError:
            continue
    return None


def _setup(lib):
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_CIPHER_CTX_reset.argtypes = [ctypes.c_void_p]
    lib.EVP_aes_128_xts.restype = ctypes.c_void_p
    lib.EVP_aes_256_xts.restype = ctypes.c_void_p
    lib.EVP_DecryptInit_ex.restype = ctypes.c_int
    lib.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_void_p, ctypes.c_char_p,
                                       ctypes.c_void_p]
    lib.EVP_DecryptUpdate.restype = ctypes.c_int
    lib.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_int),
                                      ctypes.c_void_p, ctypes.c_int]
    lib.EVP_CIPHER_CTX_set_padding.restype = ctypes.c_int
    lib.EVP_CIPHER_CTX_set_padding.argtypes = [ctypes.c_void_p, ctypes.c_int]


def available() -> bool:
    global _lib, _loaded
    if not _loaded:
        _loaded = True
        lib = _load_libcrypto()
        if lib is not None:
            try:
                _setup(lib)
                _lib = lib
            except Exception:
                _lib = None
    return _lib is not None


class _XtsCtx:
    """Contexto XTS reutilizavel (chave configurada uma vez)."""

    def __init__(self, key: bytes):
        self.lib = _lib
        self.ctx = self.lib.EVP_CIPHER_CTX_new()
        if not self.ctx:
            raise RuntimeError("EVP_CIPHER_CTX_new falhou")
        cipher = (self.lib.EVP_aes_128_xts() if len(key) == 32
                  else self.lib.EVP_aes_256_xts())
        # define cifra + chave; IV sera definido por setor
        if self.lib.EVP_DecryptInit_ex(self.ctx, cipher, None, key, None) != 1:
            raise RuntimeError("EVP_DecryptInit_ex (chave) falhou")
        self.lib.EVP_CIPHER_CTX_set_padding(self.ctx, 0)
        self._outlen = ctypes.c_int(0)

    def __del__(self):
        try:
            if getattr(self, "ctx", None):
                self.lib.EVP_CIPHER_CTX_free(self.ctx)
        except Exception:
            pass


def decrypt_region(key: bytes, base_offset: int, buf: bytes, meta_regions) -> bytes:
    """Decifra um bloco setor a setor com OpenSSL, reaproveitando o contexto.

    Otimizado: os enderecos dos buffers de entrada/saida sao obtidos UMA vez e
    os setores sao enderecados por aritmetica de offset — sem alocar objetos
    ctypes por setor. So ha 2 chamadas C por setor (init do IV + update).
    """
    if not available():
        raise RuntimeError("libcrypto (OpenSSL) indisponivel para XTS nativo.")
    ctx = _XtsCtx(key)
    lib = ctx.lib
    ctxp = ctx.ctx
    outlen = ctypes.c_int(0)
    outlen_ref = ctypes.byref(outlen)
    init = lib.EVP_DecryptInit_ex
    update = lib.EVP_DecryptUpdate

    n = len(buf)
    src = bytearray(buf)                 # uma copia (buffer gravavel)
    out = bytearray(n)
    # mantem as views vivas e pega os enderecos base uma unica vez
    src_c = (ctypes.c_char * n).from_buffer(src)
    out_c = (ctypes.c_char * n).from_buffer(out)
    src_base = ctypes.addressof(src_c)
    out_base = ctypes.addressof(out_c)
    iv = bytearray(16)
    iv_c = (ctypes.c_char * 16).from_buffer(iv)
    iv_addr = ctypes.addressof(iv_c)
    pack_into = struct.pack_into

    # so interessam as regioes de metadados que caem DENTRO deste bloco
    chunk_end = base_offset + n
    regions = [(s, s + sz) for s, sz in meta_regions
               if s < chunk_end and s + sz > base_offset]

    off = 0
    full = n - (n % SECTOR)
    if not regions:
        # caminho rapido: nenhum metadado neste bloco (caso comum)
        sec = base_offset // SECTOR
        while off < full:
            pack_into("<Q", iv, 0, sec)
            init(ctxp, None, None, None, iv_addr)
            update(ctxp, out_base + off, outlen_ref, src_base + off, SECTOR)
            off += SECTOR
            sec += 1
    else:
        while off < full:
            abs_off = base_offset + off
            skip = False
            for s0, s1 in regions:
                if s0 <= abs_off < s1:
                    skip = True
                    break
            if skip:
                out[off:off + SECTOR] = src[off:off + SECTOR]
            else:
                pack_into("<Q", iv, 0, abs_off // SECTOR)
                init(ctxp, None, None, None, iv_addr)
                update(ctxp, out_base + off, outlen_ref, src_base + off, SECTOR)
            off += SECTOR
    if off < n:                       # resto parcial (< 512 bytes)
        out[off:n] = src[off:n]

    # libera as views antes de retornar (necessario p/ bytearray mutavel)
    del src_c, out_c, iv_c
    return bytes(out)
