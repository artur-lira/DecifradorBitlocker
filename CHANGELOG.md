# Changelog

Todas as mudanças relevantes deste projeto são documentadas aqui.
O formato segue, de modo geral, o [Keep a Changelog](https://keepachangelog.com/pt-BR/).

## [2.0.0] — 2026-11-12

Primeira versão pública estável. Fluxo completo validado de ponta a ponta
contra uma evidência real (recuperação de chave conferida por ferramenta
independente e imagem decifrada montável).

### Adicionado
- Leitura de imagens Expert Witness `.E01`/`.Ex01` (segmentadas) via `libewf`
  e de imagens brutas `.dd`/`.raw`/`.img`.
- Parser de tabela de partições **MBR** e **GPT**, com detecção de sistema de
  arquivos (NTFS, exFAT, FAT32 e assinatura BitLocker `-FVE-FS-`).
- Parser de metadados **FVE** do BitLocker: GUID do volume, método de cifra,
  enumeração de *protectors* (senha, senha de recuperação, TPM, TPM+PIN,
  Startup Key, Clear Key).
- Extração de **hash atacável** no formato `hashcat -m 22100`.
- **Verificação local** de uma senha ou chave de recuperação conhecida
  (derivação de chave do BitLocker + AES-CCM, sem falso-positivo).
- Recuperação por **Clear Key** (volume suspenso) e por credencial fornecida:
  cadeia **VMK → FVEK**.
- **Exportação** da partição decifrada para `.img`:
  - laço AES-XTS nativo via **ctypes → OpenSSL** (~2× sobre a via `cryptography`);
  - **multiprocessamento** (todos os núcleos por padrão);
  - **I/O em blocos de 64 MiB** para reduzir o vai-e-vem do disco;
  - via **dislocker** como alternativa de referência.
- **Correção do setor de boot** (`fix-boot`): restaura os setores NTFS
  realocados pelo BitLocker, por offset dos metadados (`0x000f`) ou por
  **varredura com validação NTFS**, sem refazer o volume inteiro.
- **Relatório `.docx`** (e `.txt`): identificação, partição, volume, protectors
  e chaves (VMK/FVEK/Clear Key em hexadecimal e Base64), com a cadeia
  `Clear Key → VMK → FVEK`.
- Interface gráfica (Tkinter) e linha de comando (`info`, `extract`, `verify`,
  `crack`, `export`, `fix-boot`, `report`).
- Instalador tudo-em-um (`build.bat`) e empacotamento para `.exe` (PyInstaller).

### Validação
- KDF da senha de usuário conferido contra o vetor de teste público do
  `hashcat` (modo 22100).
- Cadeia VMK → FVEK conferida por imagem sintética.
- Decifragem nativa (ctypes) idêntica, bit a bit, à via `cryptography`.
- `fix_boot_sectors` coberto por teste automatizado.
