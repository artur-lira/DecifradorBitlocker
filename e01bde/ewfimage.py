"""
Leitura de imagens no formato Expert Witness (EnCase) .E01/.Ex01.

Usa pyewf (biblioteca libewf) quando disponivel. A imagem pode estar
segmentada (E01, E02, E03, ...); o pyewf localiza automaticamente os
segmentos a partir do primeiro arquivo informado.

Expoe uma interface simples de acesso por offset em bytes, que e o que
os parsers de particao e do BitLocker precisam.
"""
from __future__ import annotations

import os
import glob
from typing import List


class EwfImage:
    """Acesso somente-leitura ao conteudo bruto de uma imagem .E01."""

    def __init__(self, first_segment: str):
        try:
            import pyewf  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "A biblioteca 'pyewf' (libewf) nao esta instalada.\n"
                "Instale com:  pip install libewf-python\n"
                "No Windows tambem e possivel usar os binarios oficiais do libewf."
            ) from exc

        self._pyewf = pyewf
        # No Windows o libewf usa o prefixo de caminho longo \\?\, que NAO
        # aceita barras normais (/). Normalizamos para o separador do SO.
        first_segment = os.path.normpath(first_segment)
        if not os.path.isfile(first_segment):
            raise FileNotFoundError(f"Arquivo nao encontrado: {first_segment}")

        self.segments = [os.path.normpath(s) for s in
                         self._discover_segments(first_segment)]
        self._handle = pyewf.handle()
        self._handle.open(self.segments)
        self._size = self._handle.get_media_size()

    @staticmethod
    def _discover_segments(first_segment: str) -> List[str]:
        """Descobre todos os segmentos (E01, E02, ...) a partir do primeiro."""
        import pyewf  # type: ignore

        try:
            return pyewf.glob(first_segment)
        except Exception:
            # Fallback manual: troca a extensao final por um curinga.
            base, ext = os.path.splitext(first_segment)
            pattern = base + "." + ("E" if ext[1:2].upper() == "E" else "e") + "??"
            found = sorted(glob.glob(pattern))
            return found or [first_segment]

    @property
    def size(self) -> int:
        """Tamanho total da midia em bytes."""
        return self._size

    def read(self, offset: int, length: int) -> bytes:
        """Le `length` bytes a partir de `offset` (em bytes) da midia."""
        self._handle.seek(offset, os.SEEK_SET)
        return self._handle.read(length)

    def info(self) -> dict:
        """Metadados da aquisicao, quando presentes no cabecalho EWF."""
        data = {"segments": len(self.segments), "media_size": self._size}
        try:
            for key in (
                "case_number", "description", "examiner_name",
                "evidence_number", "notes", "acquiry_date",
                "acquiry_operating_system", "acquiry_software_version",
                "md5_hash", "sha1_hash",
            ):
                try:
                    val = self._handle.get_header_value(key)
                    if val:
                        data[key] = val
                except Exception:
                    pass
            try:
                md5 = self._handle.get_hash_value("MD5")
                if md5:
                    data["md5_stored"] = md5
            except Exception:
                pass
        except Exception:
            pass
        return data

    def export_range(self, offset: int, length: int, out_path: str,
                     chunk: int = 8 * 1024 * 1024, progress=None) -> str:
        """Exporta um intervalo (ex.: uma particao) para um arquivo bruto .dd.

        `progress(copiado, total)` e chamado periodicamente, se fornecido.
        """
        remaining = length
        pos = offset
        copied = 0
        with open(out_path, "wb") as fh:
            while remaining > 0:
                n = min(chunk, remaining)
                fh.write(self.read(pos, n))
                pos += n
                remaining -= n
                copied += n
                if progress:
                    progress(copied, length)
        return out_path

    def close(self):
        try:
            self._handle.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class RawImage(EwfImage):
    """Acesso a uma imagem bruta (.dd / .raw / .img), sem depender do pyewf.

    Util para testar o restante da ferramenta sem uma E01 real.
    """

    def __init__(self, path: str):  # noqa: super-init-not-called
        path = os.path.normpath(path)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Arquivo nao encontrado: {path}")
        self.segments = [path]
        self._fh = open(path, "rb")
        self._fh.seek(0, os.SEEK_END)
        self._size = self._fh.tell()
        self._fh.seek(0)

    def read(self, offset: int, length: int) -> bytes:
        self._fh.seek(offset, os.SEEK_SET)
        return self._fh.read(length)

    def info(self) -> dict:
        return {"segments": 1, "media_size": self._size, "format": "raw"}

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass


def open_image(path: str) -> EwfImage:
    """Abre uma imagem E01/Ex01 ou, se for .dd/.raw/.img, em modo bruto."""
    path = os.path.normpath(path)
    ext = os.path.splitext(path)[1].lower()
    if ext in (".dd", ".raw", ".img", ".bin"):
        return RawImage(path)
    return EwfImage(path)
