"""
e01bde — Analise de imagens .E01 e recuperacao do BitLocker.

Modulos:
  ewfimage   abertura de imagens E01/Ex01 (pyewf) e brutas .dd
  partitions parser de tabela de particoes MBR/GPT
  fve        parser de metadados BitLocker e extracao de hash (hashcat)
  recover    verificacao local de candidato, clear key e ataque via hashcat
"""
__version__ = "2.0.0"
