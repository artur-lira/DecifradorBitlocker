"""
Interface grafica (Tkinter) do e01bde para Windows.

Fluxo de uso:
  1. Abrir imagem .E01 (ou .dd/.raw).
  2. Listar particoes e detectar o volume BitLocker automaticamente.
  3. Ver os protectors e o diagnostico de viabilidade.
  4. Extrair o hash (hashcat), verificar uma senha/chave conhecida, ou
     disparar um ataque de dicionario via hashcat.

Tkinter acompanha o instalador oficial do Python no Windows.
"""
from __future__ import annotations

import os
import threading
import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

from .ewfimage import open_image
from . import partitions as P
from . import fve as FVE
from . import recover as R
from . import export as X
from . import report as RPT


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("e01bde — Analise E01 / BitLocker")
        self.geometry("980x680")
        self.image = None
        self.image_path = None
        self.partitions = []
        self.volumes = {}         # index -> BitLockerVolume
        self.log_q: queue.Queue = queue.Queue()

        self._build_ui()
        self.after(150, self._drain_log)

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Button(top, text="Abrir imagem (.E01/.dd)…",
                   command=self.on_open).pack(side="left")
        self.lbl_path = ttk.Label(top, text="Nenhuma imagem aberta",
                                  foreground="#555")
        self.lbl_path.pack(side="left", padx=10)

        mid = ttk.Panedwindow(self, orient="horizontal")
        mid.pack(fill="both", expand=True, padx=8, pady=4)

        # --- Esquerda: particoes
        left = ttk.Frame(mid)
        ttk.Label(left, text="Particoes").pack(anchor="w")
        cols = ("idx", "scheme", "start", "size", "type", "fs")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", height=10)
        for c, t, w in (("idx", "#", 30), ("scheme", "Esq.", 50),
                        ("start", "Setor", 80), ("size", "Tamanho", 90),
                        ("type", "Tipo", 160), ("fs", "FS", 140)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_select_partition)
        mid.add(left, weight=3)

        # --- Direita: BitLocker
        right = ttk.Frame(mid)
        ttk.Label(right, text="Diagnostico BitLocker").pack(anchor="w")
        self.info = scrolledtext.ScrolledText(right, height=12, wrap="word")
        self.info.pack(fill="both", expand=True)
        mid.add(right, weight=4)

        # --- Acoes
        act = ttk.LabelFrame(self, text="Acoes", padding=8)
        act.pack(fill="x", padx=8, pady=4)

        ttk.Button(act, text="Extrair hash (hashcat)",
                   command=self.on_extract).grid(row=0, column=0, padx=4, pady=3)

        ttk.Label(act, text="Senha de usuario:").grid(row=1, column=0, sticky="e")
        self.ent_pw = ttk.Entry(act, width=28)
        self.ent_pw.grid(row=1, column=1, padx=4)
        ttk.Button(act, text="Verificar senha",
                   command=lambda: self.on_verify(False)).grid(row=1, column=2, padx=4)

        ttk.Label(act, text="Senha de recuperacao (48):").grid(row=2, column=0, sticky="e")
        self.ent_rec = ttk.Entry(act, width=52)
        self.ent_rec.grid(row=2, column=1, padx=4)
        ttk.Button(act, text="Verificar recuperacao",
                   command=lambda: self.on_verify(True)).grid(row=2, column=2, padx=4)

        ttk.Label(act, text="Dicionario (hashcat):").grid(row=3, column=0, sticky="e")
        self.ent_wl = ttk.Entry(act, width=52)
        self.ent_wl.grid(row=3, column=1, padx=4)
        ttk.Button(act, text="…", width=3,
                   command=self.on_pick_wordlist).grid(row=3, column=2, sticky="w")
        ttk.Button(act, text="Atacar com hashcat",
                   command=self.on_crack).grid(row=3, column=2, padx=4, sticky="e")

        ttk.Separator(act, orient="horizontal").grid(
            row=4, column=0, columnspan=3, sticky="ew", pady=6)
        ttk.Label(act, text="Exportar particao DECIFRADA (.img):").grid(
            row=5, column=0, sticky="e")
        # No Windows o dislocker nao e nativo; o padrao e a via nativa AES-XTS.
        self.export_method = tk.StringVar(
            value="native" if os.name == "nt" else "dislocker")
        ttk.Radiobutton(act, text="dislocker (recomendado)", value="dislocker",
                        variable=self.export_method).grid(row=5, column=1, sticky="w")
        ttk.Radiobutton(act, text="nativo AES-XTS (experimental)", value="native",
                        variable=self.export_method).grid(row=6, column=1, sticky="w")
        expf = ttk.Frame(act)
        expf.grid(row=6, column=2, padx=4, sticky="e")
        ttk.Label(expf, text="Núcleos:").pack(side="left")
        self.spin_workers = ttk.Spinbox(expf, from_=1, to=64, width=4)
        self.spin_workers.set(os.cpu_count() or 1)  # paralelo por padrao (todos)
        self.spin_workers.pack(side="left", padx=(2, 6))
        ttk.Button(expf, text="Exportar .img",
                   command=self.on_export_img).pack(side="left")

        ttk.Separator(act, orient="horizontal").grid(
            row=7, column=0, columnspan=3, sticky="ew", pady=6)
        ttk.Label(act, text="Instituição (relatório):").grid(row=8, column=0, sticky="e")
        self.ent_inst = ttk.Entry(act, width=52)
        self.ent_inst.insert(0, "[SUA INSTITUICAO]")
        self.ent_inst.grid(row=8, column=1, padx=4)
        ttk.Button(act, text="Gerar relatório (.docx)",
                   command=self.on_report).grid(row=8, column=2, padx=4)

        # --- Log
        logf = ttk.LabelFrame(self, text="Saida / Log", padding=4)
        logf.pack(fill="both", expand=False, padx=8, pady=4)
        self.log = scrolledtext.ScrolledText(logf, height=10, wrap="word",
                                             background="#111", foreground="#0f0")
        self.log.pack(fill="both", expand=True)

    # -------------------------------------------------------------- helpers
    def _log(self, msg):
        self.log_q.put(msg)

    def _drain_log(self):
        try:
            while True:
                msg = self.log_q.get_nowait()
                self.log.insert("end", msg + "\n")
                self.log.see("end")
        except queue.Empty:
            pass
        self.after(150, self._drain_log)

    def _selected_volume(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Selecao", "Selecione uma particao BitLocker.")
            return None, None
        idx = int(self.tree.item(sel[0], "values")[0])
        vol = self.volumes.get(idx)
        if not vol or not vol.present:
            messagebox.showwarning("BitLocker", "A particao selecionada nao e BitLocker.")
            return None, None
        return idx, vol

    # --------------------------------------------------------------- events
    def on_open(self):
        path = filedialog.askopenfilename(
            title="Selecione a imagem",
            filetypes=[("Imagens", "*.E01 *.Ex01 *.dd *.raw *.img"),
                       ("Todos", "*.*")])
        if not path:
            return
        self.image_path = path
        self.lbl_path.config(text=path)
        self._log(f"[*] Abrindo {path} ...")
        threading.Thread(target=self._load_image, daemon=True).start()

    def _load_image(self):
        try:
            if self.image:
                self.image.close()
            self.image = open_image(self.image_path)
            meta = self.image.info()
            self._log(f"[+] Midia: {meta.get('media_size')} bytes, "
                      f"segmentos={meta.get('segments')}")
            self.partitions = P.parse(self.image)
            self.volumes = {}
            for p in self.partitions:
                vol = FVE.parse_bitlocker(self.image, p.start_offset)
                if vol.present:
                    self.volumes[p.index] = vol
                    p.bitlocker = True
            self.after(0, self._refresh_tree)
        except Exception as exc:
            self._log(f"[!] Erro ao abrir: {exc}")
            self.after(0, lambda: messagebox.showerror("Erro", str(exc)))

    def _refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        for p in self.partitions:
            self.tree.insert("", "end", values=(
                p.index, p.scheme, p.start_sector, p.human_size(),
                p.type_desc, p.fs_hint))
        if self.volumes:
            first = min(self.volumes)
            for iid in self.tree.get_children():
                if int(self.tree.item(iid, "values")[0]) == first:
                    self.tree.selection_set(iid)
                    break
        self._log(f"[+] {len(self.partitions)} particao(oes); "
                  f"{len(self.volumes)} com BitLocker.")

    def on_select_partition(self, _evt=None):
        idx, vol = self._selected_volume()
        self.info.delete("1.0", "end")
        if not vol:
            return
        t = []
        t.append(f"VOLUME BITLOCKER — particao {idx}")
        t.append(f"GUID do volume : {vol.volume_guid}")
        t.append(f"Criptografia   : {vol.encryption_desc}")
        if vol.note:
            t.append(f"Observacao     : {vol.note}")
        t.append("")
        t.append(f"Protectors ({len(vol.protectors)}):")
        for prot in vol.protectors:
            marca = ""
            if prot.instant:
                marca = "  [RECUPERAVEL IMEDIATAMENTE]"
            elif prot.attackable:
                marca = "  [ATACAVEL]"
            t.append(f"  • {prot.protection_desc}{marca}")
            t.append(f"      GUID: {prot.guid}")
        t.append("")
        if vol.has_clear_key():
            t.append(">> Clear Key presente: use 'Verificar' (recuperacao direta).")
        elif vol.attackable_protectors():
            t.append(">> Ha protector de senha: extraia o hash ou faca ataque.")
        else:
            t.append(">> Apenas TPM/USB: sem a imagem nao basta — exige o hardware\n"
                     "   original ou a FVEK obtida de dump de memoria (RAM).")
        self.info.insert("1.0", "\n".join(t))

    def on_extract(self):
        idx, vol = self._selected_volume()
        if not vol:
            return
        attackable = vol.attackable_protectors()
        if not attackable:
            messagebox.showinfo("Extrair", "Nenhum protector atacavel neste volume.")
            return
        out = filedialog.asksaveasfilename(
            title="Salvar hash", defaultextension=".hash",
            initialfile=f"particao{idx}.hash")
        lines = [p.hashcat_hash(with_mac=True) for p in attackable
                 if p.hashcat_hash(with_mac=True)]
        for h in lines:
            self._log(h)
        if out and lines:
            with open(out, "w") as fh:
                fh.write("\n".join(lines) + "\n")
            self._log(f"[+] Hash salvo em {out}")
            self._log(f"    hashcat -m 22100 \"{out}\" <wordlist>")

    def on_verify(self, recovery: bool):
        idx, vol = self._selected_volume()
        if not vol:
            return
        # Clear key tem prioridade
        if vol.has_clear_key():
            vmk = X.recover_vmk(vol)
            if vmk:
                self._log("[+] CLEAR KEY (volume suspenso): VMK recuperada.")
                self._log(f"    VMK  (hex): {vmk.hex().upper()}")
                fvek = X.decrypt_fvek(vol, vmk)
                if fvek:
                    self._log(f"    FVEK (hex): {fvek.hex().upper()}")
                messagebox.showinfo(
                    "Clear Key",
                    "Volume suspenso — VMK recuperada (sem senha).\n"
                    "Use 'Gerar relatório' para registrar as chaves.")
                return
        candidate = (self.ent_rec.get() if recovery else self.ent_pw.get()).strip()
        if not candidate:
            messagebox.showinfo("Verificar", "Informe o candidato.")
            return
        ttype = 0x0800 if recovery else 0x2000
        self._log(f"[*] Verificando candidato (pode levar alguns segundos)...")

        def work():
            for prot in vol.protectors:
                if prot.protection_type != ttype:
                    continue
                try:
                    res = R.verify_candidate(prot, candidate)
                except RuntimeError as exc:
                    self._log(f"[!] {exc}")
                    return
                if res is not None:
                    self._log(f"[+] CORRETO para {prot.protection_desc} "
                              f"(GUID {prot.guid}) — VMK desbloqueada.")
                    self.after(0, lambda: messagebox.showinfo(
                        "Sucesso", "Candidato VALIDO — VMK desbloqueada."))
                    return
            self._log("[-] Candidato incorreto (MAC nao confere).")

        threading.Thread(target=work, daemon=True).start()

    def on_export_img(self):
        idx, vol = self._selected_volume()
        if not vol:
            return
        part = next((p for p in self.partitions if p.index == idx), None)
        if not part:
            return
        pw = self.ent_pw.get().strip() or None
        rec = self.ent_rec.get().strip() or None
        if not (pw or rec or vol.has_clear_key()):
            messagebox.showinfo("Exportar",
                                "Informe a senha ou a chave de recuperacao "
                                "(ou use um volume com Clear Key).")
            return
        out = filedialog.asksaveasfilename(
            title="Salvar imagem decifrada", defaultextension=".img",
            initialfile=X.default_decrypted_name(self.image_path, part))
        if not out:
            return
        method = self.export_method.get()
        self._log(f"[*] Recuperando VMK e exportando (metodo={method})...")

        def work():
            nonlocal method
            try:
                vmk = X.recover_vmk(vol, candidate=pw, recovery=rec)
                if not vmk:
                    self._log("[!] VMK nao recuperada (credencial invalida?).")
                    return
                self._log(f"[+] VMK: {vmk[:16].hex()}...")
                # Se dislocker foi pedido mas nao existe, cai para a via nativa.
                if method == "dislocker" and not (
                        R.find_tool("dislocker-file") or R.find_tool("dislocker")):
                    self._log("[!] dislocker nao encontrado — usando via nativa "
                              "AES-XTS automaticamente.")
                    method = "native"
                if method == "dislocker":
                    tmp_dd = out + ".part.dd"
                    self._log(f"[*] Exportando particao bruta ({part.human_size()})...")
                    self.image.export_range(
                        part.start_offset, part.length, tmp_dd,
                        progress=X.make_progress(self._log))
                    vmk_file = out + ".vmk"
                    X.write_vmk_file(vmk, vmk_file)
                    X.export_via_dislocker(
                        tmp_dd, out, password=pw, recovery=rec,
                        vmk_file=None if (pw or rec) else vmk_file)
                else:
                    fvek = X.decrypt_fvek(vol, vmk)
                    if not fvek:
                        if not vol.fvek_ccm_data:
                            self._log("[!] FVEK nao localizada nos metadados FVE "
                                      "(layout nao suportado). Envie o caso para análise.")
                        else:
                            self._log("[!] FVEK localizada, mas a decifragem AES-CCM "
                                      "falhou (MAC nao confere).")
                        return
                    try:
                        nw = int(self.spin_workers.get())
                    except (ValueError, tk.TclError):
                        nw = 1
                    self._log(f"[*] Decifrando (AES-XTS, {nw} nucleo(s))...")
                    X.export_native_xts(
                        self.image, vol, part.start_offset, part.length, fvek, out,
                        workers=nw, progress=X.make_progress(self._log))
                    fs = X.check_decrypted_fs(out)
                    if fs:
                        self._log(f"[+] Verificacao: setor de boot = {fs} (OK)")
                    else:
                        self._log("[!] Verificacao: boot sector nao reconhecido — "
                                  "a decifragem nativa pode estar incorreta. Prefira "
                                  "uma ferramenta de referencia ou dislocker (WSL).")
                self._log(f"[+] Imagem decifrada salva: {out}")
                self.after(0, lambda: messagebox.showinfo(
                    "Concluido", f"Imagem decifrada:\n{out}"))
            except Exception as exc:
                self._log(f"[!] Falha na exportacao: {exc}")
                self.after(0, lambda e=exc: messagebox.showerror("Erro", str(e)))

        threading.Thread(target=work, daemon=True).start()

    def on_report(self):
        idx, vol = self._selected_volume()
        if not vol:
            return
        part = next((p for p in self.partitions if p.index == idx), None)
        if not part:
            return
        pw = self.ent_pw.get().strip() or None
        rec = self.ent_rec.get().strip() or None
        inst = self.ent_inst.get().strip() or "[SUA INSTITUICAO]"
        out = filedialog.asksaveasfilename(
            title="Salvar relatório", defaultextension=".docx",
            initialfile=f"relatorio_bitlocker_particao{idx}.docx",
            filetypes=[("Word", "*.docx"), ("Texto", "*.txt")])
        if not out:
            return
        self._log("[*] Gerando relatório...")

        def work():
            vmk = fvek = None
            method = ""
            if vol.has_clear_key():
                vmk = X.recover_vmk(vol)
                method = "Clear Key (volume suspenso) — recuperação direta da VMK"
            elif pw or rec:
                vmk = X.recover_vmk(vol, candidate=pw, recovery=rec)
                method = "Senha de recuperação fornecida" if rec else "Senha de usuário fornecida"
            if vmk:
                fvek = X.decrypt_fvek(vol, vmk)
                self._log(f"[+] VMK: {vmk.hex().upper()}")
                if fvek:
                    self._log(f"[+] FVEK: {fvek.hex().upper()}")
            data = RPT.collect(self.image, part, vol, vmk=vmk, fvek=fvek,
                               recovery_method=method,
                               cracked_password=pw if (pw and not rec and vmk) else None,
                               institution=inst)
            try:
                path = RPT.write_docx(data, out)
                self._log(f"[+] Relatório salvo: {path}")
                self.after(0, lambda: messagebox.showinfo("Relatório", f"Salvo:\n{path}"))
            except RuntimeError as exc:
                self._log(f"[!] {exc}")
                self.after(0, lambda e=exc: messagebox.showwarning("Relatório", str(e)))

        threading.Thread(target=work, daemon=True).start()

    def _progress(self, copied, total):
        if total:
            self._log(f"    {copied/total*100:5.1f}%  ({copied}/{total} bytes)")

    def on_pick_wordlist(self):
        path = filedialog.askopenfilename(title="Dicionario")
        if path:
            self.ent_wl.delete(0, "end")
            self.ent_wl.insert(0, path)

    def on_crack(self):
        idx, vol = self._selected_volume()
        if not vol:
            return
        attackable = vol.attackable_protectors()
        if not attackable:
            messagebox.showinfo("Atacar", "Nenhum protector atacavel.")
            return
        wl = self.ent_wl.get().strip()
        if not wl or not os.path.isfile(wl):
            messagebox.showwarning("Atacar", "Selecione um dicionario valido.")
            return
        h = attackable[0].hashcat_hash(with_mac=True)
        self._log(f"[*] hashcat -m 22100 (protector: {attackable[0].protection_desc})")

        def work():
            res = R.run_hashcat(h, wordlist=wl, progress_cb=self._log)
            if res.cracked:
                self._log(f"[+] SENHA ENCONTRADA: {res.password}")
                self.after(0, lambda: messagebox.showinfo(
                    "Sucesso", f"Senha: {res.password}"))
            else:
                self._log(f"[-] {res.note}")

        threading.Thread(target=work, daemon=True).start()


def main():
    import multiprocessing
    multiprocessing.freeze_support()  # necessario para o .exe (PyInstaller)
    App().mainloop()


if __name__ == "__main__":
    main()
