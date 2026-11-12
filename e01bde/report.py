"""
Geracao de relatorio do volume BitLocker.

Coleta os dados da imagem, da particao, dos protectors e das chaves
recuperadas (VMK e FVEK) e produz:
  - um texto estruturado (.txt), sem dependencias;
  - um documento .docx (se a biblioteca python-docx estiver instalada).

As chaves sao apresentadas em hexadecimal agrupado e em Base64 (mesmo
formato usado por outras ferramentas), facilitando a conferencia
cruzada e a transcricao no relatorio.
"""
from __future__ import annotations

import base64
import datetime
from dataclasses import dataclass, field
from typing import List, Optional

from .fve import BitLockerVolume, ENCRYPTION_METHODS


def hex_grouped(data: bytes, group: int = 1, per_line: int = 16) -> str:
    """Formata bytes em hexadecimal agrupado (2 em 2), com quebra por linha."""
    hx = data.hex().upper()
    pairs = [hx[i:i + group * 2] for i in range(0, len(hx), group * 2)]
    lines = [" ".join(pairs[i:i + per_line]) for i in range(0, len(pairs), per_line)]
    return "\n".join(lines)


@dataclass
class ReportData:
    image_path: str = ""
    image_size: int = 0
    segments: int = 0
    ewf_md5: str = ""
    case_number: str = ""
    evidence_number: str = ""
    examiner: str = ""
    acquiry_date: str = ""
    partition_index: int = 0
    partition_scheme: str = ""
    partition_offset: int = 0
    partition_size: int = 0
    partition_type: str = ""
    partition_fs: str = ""
    volume_guid: str = ""
    encryption_desc: str = ""
    protectors: List[tuple] = field(default_factory=list)  # (desc, guid, tag)
    recovery_method: str = ""
    clear_key: Optional[bytes] = None
    clear_key_guid: str = ""
    vmk: Optional[bytes] = None
    fvek: Optional[bytes] = None
    cracked_password: Optional[str] = None
    generated_at: str = ""
    institution: str = "[SUA INSTITUICAO]"


def collect(image, partition, volume: BitLockerVolume,
            vmk: Optional[bytes] = None, fvek: Optional[bytes] = None,
            recovery_method: str = "", cracked_password: Optional[str] = None,
            institution: str = "[SUA INSTITUICAO]") -> ReportData:
    meta = {}
    try:
        meta = image.info()
    except Exception:
        pass
    prots = []
    clear_key = None
    clear_key_guid = ""
    for p in volume.protectors:
        tag = ("RECUPERAVEL IMEDIATAMENTE (clear key)" if p.instant
               else "ATACAVEL (senha/recuperacao)" if p.attackable else "")
        prots.append((p.protection_desc, p.guid, tag))
        if p.instant and p.clear_key:
            clear_key = p.clear_key[:32]
            clear_key_guid = p.guid
    return ReportData(
        image_path=getattr(image, "image_path", "") or
                   (image.segments[0] if getattr(image, "segments", None) else ""),
        image_size=meta.get("media_size", image.size),
        segments=meta.get("segments", 1),
        ewf_md5=meta.get("md5_stored", "") or meta.get("md5_hash", ""),
        case_number=meta.get("case_number", ""),
        evidence_number=meta.get("evidence_number", ""),
        examiner=meta.get("examiner_name", ""),
        acquiry_date=meta.get("acquiry_date", ""),
        partition_index=partition.index,
        partition_scheme=partition.scheme,
        partition_offset=partition.start_offset,
        partition_size=partition.length,
        partition_type=partition.type_desc,
        partition_fs=partition.fs_hint,
        volume_guid=volume.volume_guid,
        encryption_desc=volume.encryption_desc,
        protectors=prots,
        recovery_method=recovery_method,
        clear_key=clear_key, clear_key_guid=clear_key_guid,
        vmk=vmk, fvek=fvek, cracked_password=cracked_password,
        generated_at=datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        institution=institution,
    )


def _human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.2f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n} B"


def render_txt(d: ReportData) -> str:
    L = []
    L.append("=" * 68)
    L.append(f"{d.institution}")
    L.append("RELATORIO TECNICO — ANALISE DE VOLUME BITLOCKER")
    L.append("=" * 68)
    L.append(f"Gerado em: {d.generated_at}")
    L.append("")
    L.append("1. IDENTIFICACAO DA EVIDENCIA")
    L.append("-" * 68)
    if d.case_number:    L.append(f"  Caso            : {d.case_number}")
    if d.evidence_number:L.append(f"  Evidencia       : {d.evidence_number}")
    if d.examiner:       L.append(f"  Examinador      : {d.examiner}")
    if d.acquiry_date:   L.append(f"  Data aquisicao  : {d.acquiry_date}")
    L.append(f"  Imagem          : {d.image_path}")
    L.append(f"  Tamanho da midia: {d.image_size} bytes ({_human(d.image_size)})")
    L.append(f"  Segmentos (E01+): {d.segments}")
    if d.ewf_md5:        L.append(f"  MD5 (cabecalho) : {d.ewf_md5}")
    L.append("")
    L.append("2. PARTICAO ANALISADA")
    L.append("-" * 68)
    L.append(f"  Indice          : {d.partition_index} ({d.partition_scheme})")
    L.append(f"  Offset          : {d.partition_offset} bytes "
             f"(setor {d.partition_offset // 512})")
    L.append(f"  Tamanho         : {_human(d.partition_size)}")
    L.append(f"  Tipo / FS       : {d.partition_type}  {d.partition_fs}")
    L.append("")
    L.append("3. VOLUME BITLOCKER")
    L.append("-" * 68)
    L.append(f"  GUID do volume  : {d.volume_guid}")
    L.append(f"  Metodo de cifra : {d.encryption_desc}")
    L.append(f"  Protectors ({len(d.protectors)}):")
    for desc, guid, tag in d.protectors:
        extra = f"  <-- {tag}" if tag else ""
        L.append(f"     - {desc} [{guid}]{extra}")
    L.append("")
    L.append("4. RECUPERACAO")
    L.append("-" * 68)
    L.append(f"  Metodo de recuperacao: {d.recovery_method or 'n/a'}")
    if d.cracked_password:
        L.append(f"  Senha de usuario recuperada: {d.cracked_password}")
    else:
        L.append("  Senha de abertura: NAO HA senha armazenada no volume.")
        L.append("  (O BitLocker nao guarda a senha em claro; recupera-se a CHAVE.)")
    L.append("")
    if d.clear_key:
        L.append("  Clear Key — chave em claro que destrava a VMK "
                 f"({len(d.clear_key)} bytes):")
        if d.clear_key_guid:
            L.append(f"     GUID do protector: {d.clear_key_guid}")
        for ln in hex_grouped(d.clear_key).splitlines():
            L.append(f"     {ln}")
        L.append(f"     Base64: {base64.b64encode(d.clear_key).decode()}")
        L.append("")
    if d.vmk:
        L.append("  VMK — Volume Master Key "
                 f"({len(d.vmk)} bytes / {len(d.vmk)*8} bits):")
        for ln in hex_grouped(d.vmk).splitlines():
            L.append(f"     {ln}")
        L.append(f"     Base64: {base64.b64encode(d.vmk).decode()}")
        L.append("")
    if d.fvek:
        L.append(f"  FVEK — Full Volume Encryption Key ({len(d.fvek)} bytes):")
        for ln in hex_grouped(d.fvek).splitlines():
            L.append(f"     {ln}")
        L.append(f"     Base64: {base64.b64encode(d.fvek).decode()}")
        L.append("")
    L.append("5. OBSERVACOES METODOLOGICAS")
    L.append("-" * 68)
    L.append(_conclusion_text(d))
    L.append("")
    L.append("=" * 68)
    L.append("Documento gerado por e01bde. Chaves conferiveis em Base64 contra")
    L.append("ferramentas de referencia (dislocker, bitlocker2john).")
    return "\n".join(L)


def _conclusion_parts(d: ReportData) -> List[str]:
    """Retorna os paragrafos da conclusao, sem quebra manual de linha."""
    has_clear = any("clear key" in t.lower() for _, _, t in d.protectors)
    parts = []
    if has_clear:
        parts.append(
            "O volume apresentava protector do tipo Clear Key, indicando que a "
            "protecao BitLocker encontrava-se SUSPENSA no momento da aquisicao. "
            "A chave-mestra do volume (VMK) foi recuperada diretamente dos "
            "metadados FVE, sem necessidade de senha, permitindo a decifragem "
            "integral da particao.")
    elif d.cracked_password:
        parts.append(
            "A senha do protector de usuario foi recuperada por ataque de "
            "dicionario/forca bruta sobre o hash extraido dos metadados FVE, "
            "permitindo a decifragem do volume.")
    else:
        parts.append(
            "A chave do volume foi recuperada a partir da credencial fornecida, "
            "permitindo a decifragem do volume.")
    parts.append(
        "Nao ha senha de abertura armazenada no volume: o BitLocker mantem "
        "apenas material criptografico (VMKs cifradas, salts, nonces e MACs), "
        "de modo que o resultado e expresso em CHAVES recuperadas, nao "
        "em senha.")
    return parts


def _conclusion_text(d: ReportData) -> str:
    """Versao para .txt: quebra os paragrafos em linhas de largura fixa."""
    out = []
    for p in _conclusion_parts(d):
        out.extend("  " + s for s in _wrap(p))
        out.append("")
    return "\n".join(out).rstrip()


def _wrap(text: str, width: int = 64) -> List[str]:
    words, line, out = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            out.append(line); line = w
        else:
            line = (line + " " + w).strip()
    if line:
        out.append(line)
    return out


def write_txt(d: ReportData, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_txt(d))
    return path


def write_docx(d: ReportData, path: str) -> str:
    """Gera o relatorio em .docx. Requer python-docx; senao, gera .txt."""
    try:
        from docx import Document
        from docx.shared import Pt, RGBColor
        from docx.enum.text import WD_ALIGN_PARAGRAPH
    except ImportError:
        alt = path.rsplit(".", 1)[0] + ".txt"
        write_txt(d, alt)
        raise RuntimeError(
            f"python-docx ausente (pip install python-docx). "
            f"Relatorio gravado em TXT: {alt}")

    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)

    h = doc.add_heading(d.institution, level=0)
    h.alignment = WD_ALIGN_PARAGRAPH.CENTER
    t = doc.add_heading("Relatório Técnico — Análise de Volume BitLocker", level=1)
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p = doc.add_paragraph(f"Gerado em: {d.generated_at}")
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER

    def kv_table(title, rows):
        doc.add_heading(title, level=2)
        tbl = doc.add_table(rows=0, cols=2)
        tbl.style = "Light Grid Accent 1"
        for k, v in rows:
            if v in (None, "", 0):
                continue
            c = tbl.add_row().cells
            c[0].text = str(k); c[1].text = str(v)
        return tbl

    kv_table("1. Identificação da Evidência", [
        ("Caso", d.case_number), ("Evidência", d.evidence_number),
        ("Examinador", d.examiner), ("Data de aquisição", d.acquiry_date),
        ("Imagem", d.image_path),
        ("Tamanho da mídia", f"{d.image_size} bytes ({_human(d.image_size)})"),
        ("Segmentos (E01+)", d.segments), ("MD5 (cabeçalho EWF)", d.ewf_md5),
    ])
    kv_table("2. Partição Analisada", [
        ("Índice", f"{d.partition_index} ({d.partition_scheme})"),
        ("Offset", f"{d.partition_offset} bytes (setor {d.partition_offset // 512})"),
        ("Tamanho", _human(d.partition_size)),
        ("Tipo / FS", f"{d.partition_type}  {d.partition_fs}"),
    ])

    doc.add_heading("3. Volume BitLocker", level=2)
    doc.add_paragraph(f"GUID do volume: {d.volume_guid}")
    doc.add_paragraph(f"Método de criptografia: {d.encryption_desc}")
    doc.add_paragraph("Protectors identificados:")
    ptbl = doc.add_table(rows=1, cols=3)
    ptbl.style = "Light Grid Accent 1"
    hdr = ptbl.rows[0].cells
    hdr[0].text, hdr[1].text, hdr[2].text = "Tipo", "GUID", "Situação"
    for desc, guid, tag in d.protectors:
        c = ptbl.add_row().cells
        c[0].text, c[1].text, c[2].text = desc, guid, tag or "-"

    doc.add_heading("4. Recuperação e Chaves", level=2)
    doc.add_paragraph(f"Método de recuperação: {d.recovery_method or 'n/a'}")
    if d.cracked_password:
        doc.add_paragraph(f"Senha de usuário recuperada: {d.cracked_password}")
    else:
        doc.add_paragraph(
            "Senha de abertura: NÃO HÁ senha armazenada no volume. O BitLocker "
            "não guarda a senha em claro — o resultado é expresso em chaves.")

    def key_block(title, key: bytes, guid: str = ""):
        if not key:
            return
        doc.add_paragraph(f"{title} ({len(key)} bytes / {len(key)*8} bits):")
        if guid:
            doc.add_paragraph(f"GUID do protector: {guid}")
        mono = doc.add_paragraph()
        lines = hex_grouped(key).split("\n")
        for j, ln in enumerate(lines):
            run = mono.add_run(ln)
            run.font.name = "Consolas"
            run.font.size = Pt(10)
            if j < len(lines) - 1:
                run.add_break()  # quebra de linha REAL do Word (mesmo paragrafo)
        b = doc.add_paragraph()
        rb = b.add_run("Base64: " + base64.b64encode(key).decode())
        rb.font.name = "Consolas"; rb.font.size = Pt(9)

    if d.clear_key or d.vmk or d.fvek:
        chain = doc.add_paragraph()
        rc = chain.add_run(
            "Cadeia de decifragem: Clear Key → VMK → FVEK → setores do volume.")
        rc.italic = True
    key_block("Clear Key — chave em claro que destrava a VMK", d.clear_key,
              d.clear_key_guid)
    key_block("VMK — Volume Master Key", d.vmk)
    key_block("FVEK — Full Volume Encryption Key", d.fvek)

    doc.add_heading("5. Observações Metodológicas", level=2)
    for parag in _conclusion_parts(d):
        p = doc.add_paragraph(parag)
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    doc.add_paragraph()
    foot = doc.add_paragraph(
        "Documento gerado por e01bde. Chaves conferíveis em Base64 contra "
        "ferramentas de referência (dislocker, bitlocker2john).")
    foot.runs[0].font.size = Pt(8)
    foot.runs[0].font.color.rgb = RGBColor(0x80, 0x80, 0x80)

    doc.save(path)
    return path
