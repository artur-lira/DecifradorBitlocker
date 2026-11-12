"""
Validacao do KDF do BitLocker contra o VETOR DE TESTE REAL do hashcat
(modo 22100). Fonte: hashcat/hashcat, src/modules/module_22100.c
  ST_PASS = "hashcat"
  ST_HASH = "$bitlocker$1$16$6f972989...$1048576$12$3a33a8ea...$60$316b0f6d..."

Se o MAC do AES-CCM confere ao derivar a chave a partir da senha conhecida,
entao a derivacao (SHA-256 duplo + stretch de 1.048.576 iteracoes) e a
reordenacao MAC||ciphertext estao corretas e compativeis com o BitLocker real.

Executar:  python tests/validate_real_vector.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from e01bde import recover as R  # noqa

REAL_PASS = "hashcat"
REAL_HASH = ("$bitlocker$1$16$6f972989ddc209f1eccf07313a7266a2$1048576$12$"
             "3a33a8eaff5e6f81d907b591$60$316b0f6d4cb445fb056f0e3e0633c4135"
             "26ff4481bbf588917b70a4e8f8075f5ceb45958a800b42cb7ff9b7f5e17c6"
             "145bf8561ea86f52d3592059fb")


def main():
    prot = R.protector_from_hashcat(REAL_HASH)
    print(f"Vetor real do hashcat (modo 22100). Senha esperada: {REAL_PASS!r}")
    print("Derivando chave (1.048.576 iteracoes) e verificando MAC...")

    ok = R.verify_candidate(prot, REAL_PASS) is not None
    bad = R.verify_candidate(prot, "senha_incorreta") is not None

    print(f"  senha correta  -> {'MAC OK (KDF compativel com BitLocker real)' if ok else 'FALHOU'}")
    print(f"  senha incorreta-> {'ACEITOU (ERRO!)' if bad else 'rejeitada (correto)'}")

    assert ok, "KDF nao reproduziu o vetor real — verifique a implementacao."
    assert not bad, "Falso-positivo com senha errada — verifique o AES-CCM."
    print("\nVALIDACAO OK.")


if __name__ == "__main__":
    main()
