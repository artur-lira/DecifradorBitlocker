# e01bde — Análise de imagem `.E01` e recuperação do BitLocker

Ferramenta (Windows/Linux) que:

1. Abre uma imagem **Expert Witness `.E01`/`.Ex01`** (EnCase/FTK Imager), ou uma imagem bruta `.dd`/`.raw`;
2. Lê a **tabela de partições** (MBR e GPT) e identifica o sistema de arquivos;
3. **Detecta o volume BitLocker** e interpreta os metadados **FVE**;
4. **Enumera os *protectors*** (senha de usuário, senha de recuperação, TPM, TPM+PIN, Startup Key, Clear Key);
5. **Extrai o hash** atacável no formato **hashcat `-m 22100`**;
6. **Verifica localmente** uma senha / chave de recuperação que você já possua (AES-CCM, sem GPU, sem falso-positivo);
7. Dispara um **ataque de dicionário/máscara** via **hashcat**;
8. **Exporta a partição descriptografada para `.img`** montável (via `dislocker` ou decifragem nativa AES-XTS), recuperando VMK → FVEK → setores.

> ⚙️ Uso restrito a contextos devidamente autorizados. Opere sobre **cópia** da imagem, preservando a cadeia de custódia.

---

## ⚠️ O que é — e o que não é — possível no BitLocker

Nenhum programa "descobre" a senha lendo a imagem. O que se faz é identificar o(s) *protector(es)* e, conforme o tipo, recuperar a chave:

| Protector no volume | Recuperável só com a imagem? | Via |
|---|---|---|
| **Clear Key** (volume **suspenso**) | ✅ Sim, imediata | VMK em claro nos metadados |
| **Senha de usuário** | ⚠️ Só por dicionário/força bruta | `extract` → hashcat `-m 22100` |
| **Senha de recuperação** (48 dígitos) | ⚠️ Inviável às cegas; viável se você já a tem | `verify` / hashcat |
| **TPM**, **TPM+PIN**, **Startup Key** | ❌ Não | Exige o TPM/USB originais ou a **FVEK** obtida de **dump de RAM** |

Em resumo: **sem Clear Key, sem senha de usuário fraca e sem a chave de recuperação, o volume é computacionalmente inquebrável** a partir apenas do `.E01`.

---

## Instalação

```bash
pip install -r requirements.txt
```

- `libewf-python` (pyewf) — leitura do `.E01`. No Windows: `pip install libewf-python`. Para `.dd`/`.raw` não é necessário.
- `cryptography` — verificação local e Clear Key.
- **hashcat** (opcional, para quebra): https://hashcat.net/hashcat/ — deixe no `PATH` ou informe o caminho.
- **bitlocker2john** (opcional, validação cruzada) — vem com o John the Ripper.

### Executável único para Windows
```bat
build_windows.bat
```
Gera `dist\e01bde-gui.exe` (interface) e `dist\e01bde.exe` (linha de comando).

---

## Uso — interface gráfica

```bash
python e01bde_gui.py
```
Abra a imagem → selecione a partição BitLocker → leia o diagnóstico → **Extrair hash**, **Verificar** senha/recuperação, ou **Atacar com hashcat**.

## Uso — linha de comando

```bash
# 1) Inspecionar: partições + BitLocker + protectors
python -m e01bde.cli info  caso.E01

# 2) Extrair o hash atacável (hashcat -m 22100)
python -m e01bde.cli extract caso.E01 -p 2 -o caso.hash

# 3) Verificar uma senha / chave de recuperação já conhecida
python -m e01bde.cli verify caso.E01 -p 2 --candidate "MinhaSenha"
python -m e01bde.cli verify caso.E01 -p 2 --recovery "123456-234567-..."

# 4) Atacar com dicionário via hashcat
python -m e01bde.cli crack caso.E01 -p 2 --wordlist rockyou.txt
#   ou máscara de força bruta:
python -m e01bde.cli crack caso.E01 -p 2 --mask "?d?d?d?d?d?d"

# 5) Exportar a partição DECIFRADA para .img montável (após obter a chave)
python -m e01bde.cli export caso.E01 -p 2 --candidate "SENHA" -o decifrada.img
python -m e01bde.cli export caso.E01 -p 2 --recovery "123456-..." --method dislocker
#   --method native usa decifragem AES-XTS interna (experimental, Win10/11)
```

Com o hash extraído, o ataque também pode ser feito diretamente:
```bash
hashcat -m 22100 caso.hash rockyou.txt
```

---

## Metodologia sugerida

| Passo | Ação |
|---|---|
| 1 | Trabalhar sobre **cópia verificada** da `.E01` (confira o MD5/SHA do cabeçalho EWF). |
| 2 | `info` → mapear partições e localizar o volume BitLocker. |
| 3 | Ler os **protectors**. Há **Clear Key**? → recuperação imediata (`verify`). |
| 4 | Há **senha de usuário**? → `extract` e atacar com dicionário dirigido ao caso. |
| 5 | Possui a **chave de recuperação** (48 dígitos, p.ex. via conta Microsoft/AD/MDM sob ordem judicial)? → `verify --recovery`. |
| 6 | Só **TPM/USB**? → documentar a inviabilidade a partir da imagem; buscar o hardware ou **captura de memória** da máquina ligada/em repouso. |
| 7 | Registrar tudo no relatório: GUID do volume, método de criptografia, protectors, hash e resultado. |

---

## Arquitetura

```
e01bde/
  ewfimage.py   Abre .E01/.Ex01 (pyewf) e .dd/.raw; acesso por offset
  partitions.py Parser MBR/GPT e detecção de FS (inclui -FVE-FS-)
  fve.py        Parser dos metadados FVE; protectors; FVEK; hash hashcat
  recover.py    KDF BitLocker, AES-CCM, Clear Key, verificação e hashcat
  export.py     VMK -> FVEK -> decifragem; export .img (dislocker / AES-XTS)
  cli.py        Linha de comando
  gui.py        Interface Tkinter
```

## Validação

**1. Contra vetor REAL do BitLocker** — `tests/validate_real_vector.py` usa o
vetor de teste oficial do hashcat (modo 22100, senha pública `hashcat`, extraído
de `hashcat/hashcat → src/modules/module_22100.c`). O KDF completo
(SHA-256 duplo + 1.048.576 iterações de *stretch*) + AES-CCM **valida o MAC**
com a senha conhecida e **rejeita** senha errada, provando que a derivação do
protector de **senha de usuário** é compatível byte-a-byte com o BitLocker real:

```bash
python tests/validate_real_vector.py   # -> VALIDACAO OK
```

**2. Cadeia estrutural e export** — `tests/make_synthetic.py` gera uma imagem
(MBR + volume BitLocker + FVE com protector de senha + FVEK) e exercita:
partição → detecção → enumeração de protectors → hash hashcat → recuperação
**VMK → FVEK** → export `.img`.

```bash
python tests/make_synthetic.py synthetic.dd
python -m e01bde.cli info synthetic.dd
```

> **Nota de precisão (para o relatório):**
> - O KDF de **senha de usuário** está validado contra vetor real (item 1).
> - A extração **VMK → FVEK** (AES-CCM) está validada por cadeia conhecida (item 2).
> - A derivação da **senha de recuperação** (48 dígitos) está implementada conforme o algoritmo público, mas recomenda-se confirmá-la contra uma chave de recuperação real antes de uso definitivo.
> - A decifragem **nativa AES-XTS** (`--method native`) é **experimental**: para casework use `--method dislocker` (implementação de referência) e confirme montando a imagem. O Elephant diffuser (AES-CBC, Vista/7) só é tratado pelo `dislocker`.
> - `bitlocker2john` serve como referência cruzada da extração do hash.

## Licença

Distribuído sob a licença **MIT**. Veja o arquivo [LICENSE](LICENSE).
