#!/usr/bin/env python3
"""
file_encryption_pro.py - Criptografador Pro com Relatório e Filtros
AES-256-GCM + PBKDF2 (600.000 iterações)
Exclusão segura com sobrescrita dos originais antes da remoção.
"""

import os
import sys
import getpass
import traceback
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b"FCRYPT1"
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERATIONS = 600_000
EXT_ENC = ".enc"

# Extensões ignoradas na criptografia (arquivos de sistema/imagem de disco grandes etc.)
FILTRO_IGNORAR = {".exe", ".dll", ".sys", ".iso", ".tmp"}
TAMANHO_MAX_MB = 2048  # ignora arquivos maiores que 2 GB


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode())


def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    return MAGIC + salt + nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt_bytes(data: bytes, password: str) -> bytes:
    if not data.startswith(MAGIC):
        raise ValueError("Formato inválido")
    off = len(MAGIC)
    salt = data[off:off + SALT_SIZE]
    nonce = data[off + SALT_SIZE:off + SALT_SIZE + NONCE_SIZE]
    ciphertext = data[off + SALT_SIZE + NONCE_SIZE:]
    key = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def wipe_file(path: str, passes: int = 3) -> None:
    """
    Exclusão segura: sobrescreve o arquivo com bytes aleatórios
    (e uma passada final de zeros) antes de removê-lo.
    """
    tamanho = os.path.getsize(path)
    if tamanho == 0:
        return
    with open(path, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            restante = tamanho
            while restante > 0:
                bloco = os.urandom(min(1024 * 1024, restante))
                f.write(bloco)
                restante -= len(bloco)
            f.flush()
            os.fsync(f.fileno())
        # passada final de zeros
        f.seek(0)
        restante = tamanho
        while restante > 0:
            bloco = b"\x00" * min(1024 * 1024, restante)
            f.write(bloco)
            restante -= len(bloco)
        f.flush()
        os.fsync(f.fileno())


def get_files(path: str, mode: str) -> list:
    """Retorna lista de arquivos a processar, aplicando filtros."""
    if os.path.isfile(path):
        return [path]

    arquivos = []
    for raiz, _, nomes in os.walk(path):
        for nome in nomes:
            caminho = os.path.join(raiz, nome)
            ext = os.path.splitext(nome)[1].lower()

            if mode == "encrypt":
                if ext in FILTRO_IGNORAR or ext == EXT_ENC:
                    continue
                if nome.startswith("relatorio_"):
                    continue
                try:
                    if os.path.getsize(caminho) > TAMANHO_MAX_MB * 1024 * 1024:
                        continue
                except OSError:
                    continue
            else:  # decrypt: só arquivos .enc
                if ext != EXT_ENC:
                    continue

            arquivos.append(caminho)
    return arquivos


def processar(arquivos: list, password: str, mode: str) -> list:
    resultados = []
    for caminho in arquivos:
        try:
            with open(caminho, "rb") as f:
                data = f.read()

            if mode == "encrypt":
                novo = caminho + EXT_ENC
                conteudo = encrypt_bytes(data, password)
            else:
                novo = caminho[:-len(EXT_ENC)] if caminho.endswith(EXT_ENC) else caminho + ".dec"
                conteudo = decrypt_bytes(data, password)

            with open(novo, "wb") as f:
                f.write(conteudo)
                f.flush()
                os.fsync(f.fileno())

            # Exclusão segura do original (nas duas direções):
            # sobrescreve com bytes aleatórios antes de remover.
            # Se qualquer etapa anterior falhar (senha errada, arquivo
            # corrompido, erro de escrita), a exceção dispara ANTES daqui
            # e o original é preservado intacto.
            wipe_file(caminho)
            os.remove(caminho)

            resultados.append((caminho, novo, "SUCESSO", ""))
            print(f"  -> [SUCESSO] {caminho}")

        except Exception as e:
            resultados.append((caminho, "", "FALHA", str(e)))
            print(f"  -> [FALHA]   {caminho} ({e})")
    return resultados


def gerar_relatorio(resultados: list, mode: str, alvo: str) -> str:
    acao = "criptografia" if mode == "encrypt" else "descriptografia"
    nome = f"relatorio_{acao}.txt"
    sucesso = sum(1 for r in resultados if r[2] == "SUCESSO")
    falha = len(resultados) - sucesso

    with open(nome, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write(f"RELATÓRIO DE {acao.upper()}\n")
        f.write("=" * 60 + "\n")
        f.write(f"Data/Hora : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write(f"Alvo      : {alvo}\n")
        f.write(f"Arquivos  : {len(resultados)} | Sucesso: {sucesso} | Falha: {falha}\n")
        f.write("=" * 60 + "\n\n")
        for origem, destino, status, erro in resultados:
            f.write(f"[{status}] {origem}\n")
            if destino:
                f.write(f"        -> {destino}\n")
            if erro:
                f.write(f"        Erro: {erro}\n")
    return os.path.abspath(nome)


def main():
    print("=== Criptografador Pro com Relatório e Filtros ===")
    print("1. Criptografar Arquivo ou Pasta")
    print("2. Descriptografar Arquivo ou Pasta\n")

    opcao = input("Escolha uma opção (1 ou 2): ").strip()
    if opcao not in ("1", "2"):
        sys.exit("[!] Opção inválida.")
    mode = "encrypt" if opcao == "1" else "decrypt"

    caminho = input("Digite o caminho do arquivo ou da pasta: ").strip().strip('"')
    if not os.path.exists(caminho):
        sys.exit("[!] Caminho não encontrado.")

    pwd = getpass.getpass("Digite a senha de criptografia: ")
    if not pwd:
        sys.exit("[!] A senha não pode ser vazia.")

    arquivos = get_files(caminho, mode)
    if not arquivos:
        sys.exit("[!] Nenhum arquivo elegível encontrado.")

    acao = "criptografar" if mode == "encrypt" else "descriptografar"
    print(f"\n[*] Iniciando processo de {acao} em: {caminho}")
    print(f"[*] {len(arquivos)} arquivo(s) elegível(is).")

    # Confirmação: os originais serão sobrescritos e apagados
    resp = input(f"[?] Os originais serão apagados com exclusão segura. Continuar? (s/n): ").strip().lower()
    if resp not in ("s", "sim"):
        sys.exit("[!] Operação cancelada pelo usuário.")

    resultados = processar(arquivos, pwd, mode)
    relatorio = gerar_relatorio(resultados, mode, caminho)
    print(f"\n[+] Relatório salvo em: {relatorio}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operação cancelada pelo usuário.")
    except Exception:
        traceback.print_exc()