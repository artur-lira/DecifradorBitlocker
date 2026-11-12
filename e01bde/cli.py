"""
Interface de linha de comando do e01bde.

Uso tipico:

  # 1) Inspecionar a imagem (particoes + deteccao de BitLocker)
  python -m e01bde.cli info caso.E01

  # 2) Extrair o hash atacavel (formato hashcat -m 22100)
  python -m e01bde.cli extract caso.E01 -p 2 -o caso.hash

  # 3) Verificar uma senha/chave de recuperacao que voce ja possui
  python -m e01bde.cli verify caso.E01 -p 2 --candidate "SENHA"
  python -m e01bde.cli verify caso.E01 -p 2 --recovery "123456-....-...."

  # 4) Atacar com dicionario via hashcat
  python -m e01bde.cli crack caso.E01 -p 2 --wordlist rockyou.txt
"""
from __future__ import annotations

import argparse
import os
import sys

from .ewfimage import open_image
from . import partitions as P
from . import fve as FVE
from . import recover as R
from . import export as X
from . import report as RPT


def _banner():
    print("=" * 70)
    print(" e01bde — Analise de imagem E01 e recuperacao BitLocker")
    print("=" * 70)


def _pick_bitlocker_partition(image, part_index=None):
    parts = P.parse(image)
    chosen = None
    for p in parts:
        if part_index and p.index == part_index:
            chosen = p
        if "BitLocker" in p.fs_hint and not part_index and chosen is None:
            chosen = p
    if chosen is None and part_index is None and parts:
        # ultima tentativa: qualquer uma com assinatura FVE
        for p in parts:
            vol = FVE.parse_bitlocker(image, p.start_offset)
            if vol.present:
                return p, vol
    if chosen is None:
        return None, None
    vol = FVE.parse_bitlocker(image, chosen.start_offset)
    return chosen, vol


def cmd_info(args):
    _banner()
    with open_image(args.image) as image:
        meta = image.info()
        print(f"\nImagem: {args.image}")
        print(f"Tamanho da midia: {meta.get('media_size')} bytes "
              f"({meta.get('media_size', 0) / (1024**3):.2f} GiB)")
        print(f"Segmentos: {meta.get('segments')}  Formato: {meta.get('format', 'EWF/E01')}")
        for k in ("case_number", "evidence_number", "examiner_name",
                  "description", "acquiry_date", "md5_stored"):
            if meta.get(k):
                print(f"  {k}: {meta[k]}")

        parts = P.parse(image)
        if not parts:
            print("\n[!] Nenhuma tabela de particao (MBR/GPT) reconhecida.")
            return
        print(f"\nParticoes ({len(parts)}):")
        print(f"{'#':>2} {'Esquema':7} {'Inicio(setor)':>13} {'Tamanho':>12}  Tipo / FS")
        print("-" * 70)
        for p in parts:
            fs = f"  [{p.fs_hint}]" if p.fs_hint else ""
            print(f"{p.index:>2} {p.scheme:7} {p.start_sector:>13} "
                  f"{p.human_size():>12}  {p.type_desc}{fs}")

        print("\nAnalise BitLocker:")
        found_any = False
        for p in parts:
            vol = FVE.parse_bitlocker(image, p.start_offset)
            if not vol.present:
                continue
            found_any = True
            print(f"\n  >> Particao {p.index} — VOLUME BITLOCKER")
            print(f"     GUID do volume : {vol.volume_guid}")
            print(f"     Criptografia   : {vol.encryption_desc}")
            if vol.note:
                print(f"     Obs            : {vol.note}")
            if not vol.protectors:
                continue
            print(f"     Protectors ({len(vol.protectors)}):")
            for prot in vol.protectors:
                tag = ""
                if prot.instant:
                    tag = "  <== RECUPERAVEL IMEDIATAMENTE (clear key)"
                elif prot.attackable:
                    tag = "  <== ATACAVEL (hashcat / verificacao)"
                print(f"       - {prot.protection_desc}  [{prot.guid}]{tag}")
        if not found_any:
            print("  Nenhum volume BitLocker encontrado nas particoes.")


def cmd_extract(args):
    _banner()
    with open_image(args.image) as image:
        part, vol = _pick_bitlocker_partition(image, args.partition)
        if not vol or not vol.present:
            print("[!] Nenhum volume BitLocker encontrado/selecionado.")
            sys.exit(2)
        attackable = vol.attackable_protectors()
        if not attackable:
            print("[!] Nenhum protector atacavel (senha/recuperacao) presente.")
            if vol.has_clear_key():
                print("    Porem ha CLEAR KEY — use 'verify' (recuperacao imediata).")
            else:
                print("    Protectors presentes exigem TPM/USB/dump de RAM.")
            sys.exit(3)
        out = args.output
        lines = []
        for prot in attackable:
            h = prot.hashcat_hash(with_mac=True)
            if h:
                lines.append(h)
                print(f"\n[{prot.protection_desc}]")
                print(h)
        if out and lines:
            with open(out, "w") as fh:
                fh.write("\n".join(lines) + "\n")
            print(f"\n[+] Hash(es) salvos em: {out}")
            print(f"    Ataque:  hashcat -m 22100 {out} <wordlist>")


def cmd_verify(args):
    _banner()
    with open_image(args.image) as image:
        part, vol = _pick_bitlocker_partition(image, args.partition)
        if not vol or not vol.present:
            print("[!] Nenhum volume BitLocker encontrado/selecionado.")
            sys.exit(2)

        # Clear key primeiro
        for prot in vol.protectors:
            if prot.instant:
                vmk = X.recover_vmk(vol)
                if vmk:
                    print("[+] CLEAR KEY: VMK recuperada diretamente dos metadados.")
                    print(f"    VMK (hex): {vmk.hex().upper()}")
                    fvek = X.decrypt_fvek(vol, vmk)
                    if fvek:
                        print(f"    FVEK (hex): {fvek.hex().upper()}")
                    return

        candidate = args.candidate or args.recovery
        if not candidate:
            print("[!] Informe --candidate SENHA ou --recovery 48-digitos.")
            sys.exit(2)
        target_type = 0x0800 if args.recovery else 0x2000
        tested = False
        for prot in vol.protectors:
            if prot.protection_type != target_type:
                continue
            tested = True
            try:
                res = R.verify_candidate(prot, candidate)
            except RuntimeError as exc:
                print(f"[!] {exc}")
                sys.exit(4)
            if res is not None:
                print(f"[+] CORRETO! Candidato valido para: {prot.protection_desc}")
                print(f"    Protector GUID: {prot.guid}")
                print("    VMK desbloqueada (MAC verificado).")
                return
        if tested:
            print("[-] Candidato INCORRETO (MAC nao confere).")
        else:
            print("[!] Nao ha protector do tipo pedido neste volume.")


def cmd_crack(args):
    _banner()
    with open_image(args.image) as image:
        part, vol = _pick_bitlocker_partition(image, args.partition)
        if not vol or not vol.present:
            print("[!] Nenhum volume BitLocker encontrado/selecionado.")
            sys.exit(2)
        attackable = vol.attackable_protectors()
        if not attackable:
            print("[!] Nenhum protector atacavel presente.")
            sys.exit(3)
        prot = attackable[0]
        h = prot.hashcat_hash(with_mac=True)
        print(f"[*] Protector: {prot.protection_desc}")
        print(f"[*] Hash: {h}")
        print("[*] Iniciando hashcat (pode levar muito tempo)...\n")
        result = R.run_hashcat(h, wordlist=args.wordlist, mask=args.mask,
                               hashcat_path=args.hashcat,
                               progress_cb=lambda l: print("   ", l))
        print()
        if result.cracked:
            print(f"[+] SENHA ENCONTRADA: {result.password}")
        else:
            print(f"[-] {result.note}")


def cmd_export(args):
    _banner()
    with open_image(args.image) as image:
        part, vol = _pick_bitlocker_partition(image, args.partition)
        if not vol or not vol.present:
            print("[!] Nenhum volume BitLocker encontrado/selecionado.")
            sys.exit(2)

        print("[*] Recuperando VMK...")
        vmk = X.recover_vmk(vol, candidate=args.candidate, recovery=args.recovery)
        if not vmk:
            print("[!] Nao foi possivel recuperar a VMK (sem clear key e sem "
                  "senha/recuperacao valida informada).")
            sys.exit(3)
        print(f"[+] VMK recuperada: {vmk[:16].hex()}...")

        out = args.output or X.default_decrypted_name(args.image, part)
        method = args.method

        if method == "dislocker" and not (
                R.find_tool("dislocker-file") or R.find_tool("dislocker")):
            print("[!] dislocker nao encontrado — usando a via nativa AES-XTS.")
            method = "native"

        if method == "dislocker":
            # Exporta a particao bruta e decifra com dislocker.
            tmp_dd = out + ".part.dd"
            print(f"[*] Exportando particao bruta para {tmp_dd} ...")
            image.export_range(part.start_offset, part.length, tmp_dd,
                               progress=lambda c, t: None)
            vmk_file = out + ".vmk"
            X.write_vmk_file(vmk, vmk_file)
            print("[*] Decifrando com dislocker...")
            try:
                ok = X.export_via_dislocker(
                    tmp_dd, out, password=args.candidate,
                    recovery=args.recovery,
                    vmk_file=None if (args.candidate or args.recovery) else vmk_file)
            except RuntimeError as exc:
                print(f"[!] {exc}")
                sys.exit(4)
            if ok:
                print(f"[+] Imagem decifrada: {out}")
        else:
            fvek = X.decrypt_fvek(vol, vmk)
            if not fvek:
                if not vol.fvek_ccm_data:
                    print("[!] FVEK nao localizada nos metadados FVE (layout nao suportado).")
                else:
                    print("[!] FVEK localizada, mas a decifragem AES-CCM falhou (MAC).")
                sys.exit(4)
            nw = args.workers if args.workers else (os.cpu_count() or 1)
            print(f"[+] FVEK decifrada ({len(fvek)} bytes). Decifrando (AES-XTS, "
                  f"{nw} nucleo(s))...")
            try:
                X.export_native_xts(
                    image, vol, part.start_offset, part.length, fvek, out,
                    workers=nw,
                    progress=X.make_progress(lambda m: print("    " + m, end="\r")))
            except RuntimeError as exc:
                print(f"\n[!] {exc}")
                sys.exit(4)
            print(f"\n[+] Imagem decifrada (EXPERIMENTAL): {out}")
            fs = X.check_decrypted_fs(out)
            if fs:
                print(f"[+] Verificacao: setor de boot = {fs}  (decifragem OK)")
            else:
                print("[!] Verificacao: setor de boot NAO reconhecido — a "
                      "decifragem nativa pode estar incorreta para este volume.")
                print("    Use dislocker (WSL) ou a imagem decifrada de uma "
                      "ferramenta de referencia.")
            print("    Confira montando a imagem antes de uso definitivo.")


def cmd_report(args):
    _banner()
    with open_image(args.image) as image:
        part, vol = _pick_bitlocker_partition(image, args.partition)
        if not vol or not vol.present:
            print("[!] Nenhum volume BitLocker encontrado/selecionado.")
            sys.exit(2)

        vmk = fvek = None
        method = ""
        if vol.has_clear_key():
            vmk = X.recover_vmk(vol)
            method = "Clear Key (volume suspenso) — recuperacao direta da VMK"
        elif args.candidate or args.recovery:
            vmk = X.recover_vmk(vol, candidate=args.candidate, recovery=args.recovery)
            method = ("Senha de recuperacao fornecida" if args.recovery
                      else "Senha de usuario fornecida")
        if vmk:
            fvek = X.decrypt_fvek(vol, vmk)
            print(f"[+] VMK recuperada: {vmk.hex().upper()}")
            if fvek:
                print(f"[+] FVEK recuperada: {fvek.hex().upper()}")
        else:
            print("[*] Chaves nao recuperadas (sem clear key / credencial). "
                  "Relatorio sera gerado apenas com o diagnostico.")

        data = RPT.collect(image, part, vol, vmk=vmk, fvek=fvek,
                           recovery_method=method,
                           cracked_password=args.candidate if args.candidate and
                           not args.recovery and vmk else None,
                           institution=args.institution)
        out = args.output or f"relatorio_bitlocker_particao{part.index}.docx"
        try:
            path = RPT.write_docx(data, out)
            print(f"[+] Relatorio .docx gerado: {path}")
        except RuntimeError as exc:
            print(f"[!] {exc}")


def cmd_fixboot(args):
    _banner()
    with open_image(args.image) as image:
        part, vol = _pick_bitlocker_partition(image, args.partition)
        if not vol or not vol.present:
            print("[!] Nenhum volume BitLocker encontrado/selecionado.")
            sys.exit(2)
        print("[*] Recuperando VMK/FVEK...")
        vmk = X.recover_vmk(vol, candidate=args.candidate, recovery=args.recovery)
        fvek = X.decrypt_fvek(vol, vmk) if vmk else None
        if not fvek:
            print("[!] Nao foi possivel recuperar a FVEK (chave/credencial?).")
            sys.exit(3)
        print(f"[*] Corrigindo o inicio de: {args.img}")
        res = X.fix_boot_sectors(image, vol, part.start_offset, args.img, fvek,
                                 progress=lambda c, t: print(f"    varredura {c/t*100:4.1f}%",
                                                             end="\r"),
                                 log=print)
        if res.get("ok"):
            fs = X.check_decrypted_fs(args.img)
            print(f"\n[+] Boot corrigido ({res.get('method')}). "
                  f"Setor de boot agora: {fs or 'nao reconhecido'}")
        else:
            print(f"\n[!] Falha: {res.get('reason')}")
            sys.exit(4)


def build_parser():
    ap = argparse.ArgumentParser(
        prog="e01bde",
        description="Analise de imagem .E01 e recuperacao do BitLocker.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("info", help="Lista particoes e detecta BitLocker.")
    p.add_argument("image")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("extract", help="Extrai hash atacavel (formato hashcat).")
    p.add_argument("image")
    p.add_argument("-p", "--partition", type=int, help="Indice da particao.")
    p.add_argument("-o", "--output", help="Arquivo de saida do hash.")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("verify", help="Verifica senha/chave de recuperacao conhecida.")
    p.add_argument("image")
    p.add_argument("-p", "--partition", type=int)
    p.add_argument("--candidate", help="Senha de usuario a testar.")
    p.add_argument("--recovery", help="Senha de recuperacao de 48 digitos.")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("crack", help="Ataque de dicionario/mascara via hashcat.")
    p.add_argument("image")
    p.add_argument("-p", "--partition", type=int)
    p.add_argument("--wordlist", help="Caminho do dicionario (-a 0).")
    p.add_argument("--mask", help="Mascara de forca bruta (-a 3), ex.: ?d?d?d?d?d?d")
    p.add_argument("--hashcat", help="Caminho do executavel hashcat.")
    p.set_defaults(func=cmd_crack)

    p = sub.add_parser("export", help="Exporta a particao DECIFRADA para .img.")
    p.add_argument("image")
    p.add_argument("-p", "--partition", type=int)
    p.add_argument("-o", "--output", help="Arquivo .img de saida.")
    p.add_argument("--candidate", help="Senha de usuario (desbloqueio).")
    p.add_argument("--recovery", help="Senha de recuperacao de 48 digitos.")
    p.add_argument("--method", choices=["dislocker", "native"], default="dislocker",
                   help="dislocker (recomendado) ou native (AES-XTS experimental).")
    p.add_argument("--workers", type=int, default=0,
                   help="Nucleos para a decifragem nativa (0 = todos disponiveis).")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("report", help="Gera relatorio .docx (com chaves).")
    p.add_argument("image")
    p.add_argument("-p", "--partition", type=int)
    p.add_argument("-o", "--output", help="Arquivo .docx de saida.")
    p.add_argument("--candidate", help="Senha de usuario (para recuperar a chave).")
    p.add_argument("--recovery", help="Senha de recuperacao de 48 digitos.")
    p.add_argument("--institution", default="[SUA INSTITUICAO]",
                   help="Nome da instituicao no cabecalho.")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("fix-boot",
                       help="Corrige o setor de boot de um .img ja exportado.")
    p.add_argument("image", help="Imagem E01/Ex01 de origem.")
    p.add_argument("--img", required=True, help="Arquivo .img decifrado a corrigir.")
    p.add_argument("-p", "--partition", type=int)
    p.add_argument("--candidate", help="Senha de usuario.")
    p.add_argument("--recovery", help="Senha de recuperacao de 48 digitos.")
    p.set_defaults(func=cmd_fixboot)

    return ap


def main(argv=None):
    import multiprocessing
    multiprocessing.freeze_support()  # necessario para o .exe (PyInstaller)
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        args.func(args)
    except FileNotFoundError as exc:
        print(f"[!] {exc}")
        sys.exit(1)
    except RuntimeError as exc:
        print(f"[!] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
