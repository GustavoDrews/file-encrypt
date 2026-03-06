"""
=============================================================================
Programa de Criptografia Assimétrica (RSA) para Arquivos
=============================================================================

Este programa permite criptografar e descriptografar arquivos utilizando
criptografia assimétrica RSA com esquema híbrido (RSA + AES).

Como a criptografia RSA possui limitação no tamanho dos dados que pode
cifrar diretamente, utilizamos um esquema híbrido:
  1. Geramos uma chave simétrica AES aleatória para cifrar o arquivo.
  2. Ciframos essa chave AES com a chave pública RSA.
  3. Salvamos a chave AES cifrada junto com o conteúdo cifrado.
  4. Na descriptografia, usamos a chave privada RSA para recuperar a chave
     AES e então descriptografar o conteúdo do arquivo.

Dependências: pip install cryptography

Autor: Estudante
Data: Março 2026
"""

import os
import sys

# --- Módulos da biblioteca 'cryptography' ---

# RSA: geração de chaves e operações assimétricas
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding

# Serialização de chaves (salvar/carregar em arquivos PEM)
from cryptography.hazmat.primitives import serialization, hashes

# AES: criptografia simétrica usada internamente (esquema híbrido)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Geração segura de bytes aleatórios
from os import urandom


# =============================================================================
# Constantes
# =============================================================================

TAMANHO_CHAVE_RSA = 2048       # Bits da chave RSA (2048 é o mínimo recomendado)
TAMANHO_CHAVE_AES = 32         # Bytes (256 bits) para AES-256
TAMANHO_IV = 16                # Bytes do vetor de inicialização (IV) para AES
EXTENSAO_CIFRADO = ".enc"      # Extensão do arquivo cifrado
EXTENSAO_DECIFRADO = ".dec"    # Extensão do arquivo descriptografado


# =============================================================================
# Funções de Geração e Gerenciamento de Chaves RSA
# =============================================================================

def gerar_par_de_chaves(pasta_destino="."):
    """
    Gera um par de chaves RSA (pública e privada) e salva em arquivos PEM.

    Parâmetros:
        pasta_destino (str): Pasta onde as chaves serão salvas.

    Retorna:
        tuple: Caminhos dos arquivos (chave_privada, chave_publica).
    """
    # Gera a chave privada RSA
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,       # Expoente público padrão (recomendado)
        key_size=TAMANHO_CHAVE_RSA,  # Tamanho da chave em bits
    )

    # Deriva a chave pública a partir da chave privada
    chave_publica = chave_privada.public_key()

    # Define os caminhos dos arquivos
    caminho_privada = os.path.join(pasta_destino, "chave_privada.pem")
    caminho_publica = os.path.join(pasta_destino, "chave_publica.pem")

    # Salva a chave privada em formato PEM (sem senha para simplificar)
    with open(caminho_privada, "wb") as arquivo:
        arquivo.write(
            chave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Salva a chave pública em formato PEM
    with open(caminho_publica, "wb") as arquivo:
        arquivo.write(
            chave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print(f"[OK] Chave privada salva em: {caminho_privada}")
    print(f"[OK] Chave pública salva em: {caminho_publica}")

    return caminho_privada, caminho_publica


def carregar_chave_publica(caminho):
    """
    Carrega uma chave pública RSA a partir de um arquivo PEM.

    Parâmetros:
        caminho (str): Caminho do arquivo PEM da chave pública.

    Retorna:
        RSAPublicKey: Objeto da chave pública.
    """
    with open(caminho, "rb") as arquivo:
        chave = serialization.load_pem_public_key(arquivo.read())
    return chave


def carregar_chave_privada(caminho):
    """
    Carrega uma chave privada RSA a partir de um arquivo PEM.

    Parâmetros:
        caminho (str): Caminho do arquivo PEM da chave privada.

    Retorna:
        RSAPrivateKey: Objeto da chave privada.
    """
    with open(caminho, "rb") as arquivo:
        chave = serialization.load_pem_private_key(arquivo.read(), password=None)
    return chave


# =============================================================================
# Funções de Criptografia e Descriptografia
# =============================================================================

def criptografar_arquivo(caminho_arquivo, caminho_chave_publica):
    """
    Criptografa um arquivo usando esquema híbrido RSA + AES.

    Processo:
        1. Gera uma chave AES aleatória e um IV (vetor de inicialização).
        2. Cifra o conteúdo do arquivo com AES-256-CFB.
        3. Cifra a chave AES com a chave pública RSA (OAEP + SHA-256).
        4. Salva no arquivo de saída: [chave AES cifrada][IV][dados cifrados].

    Parâmetros:
        caminho_arquivo (str): Caminho do arquivo a ser criptografado.
        caminho_chave_publica (str): Caminho do arquivo PEM da chave pública.

    Retorna:
        str: Caminho do arquivo cifrado gerado.
    """
    # Carrega a chave pública RSA
    chave_publica = carregar_chave_publica(caminho_chave_publica)

    # Lê o conteúdo original do arquivo
    with open(caminho_arquivo, "rb") as arquivo:
        dados_originais = arquivo.read()

    # --- Etapa 1: Gera chave AES e IV aleatórios ---
    chave_aes = urandom(TAMANHO_CHAVE_AES)  # 256 bits
    iv = urandom(TAMANHO_IV)                 # 128 bits

    # --- Etapa 2: Cifra o conteúdo com AES-256-CFB ---
    cifrador = Cipher(algorithms.AES(chave_aes), modes.CFB(iv))
    encriptador = cifrador.encryptor()
    dados_cifrados = encriptador.update(dados_originais) + encriptador.finalize()

    # --- Etapa 3: Cifra a chave AES com RSA (OAEP + SHA-256) ---
    chave_aes_cifrada = chave_publica.encrypt(
        chave_aes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # --- Etapa 4: Monta e salva o arquivo cifrado ---
    # Formato: [tamanho da chave AES cifrada (2 bytes)][chave AES cifrada][IV][dados cifrados]
    caminho_saida = caminho_arquivo + EXTENSAO_CIFRADO
    with open(caminho_saida, "wb") as arquivo:
        # Grava o tamanho da chave AES cifrada (2 bytes, big-endian)
        tamanho_chave = len(chave_aes_cifrada)
        arquivo.write(tamanho_chave.to_bytes(2, byteorder="big"))
        # Grava a chave AES cifrada
        arquivo.write(chave_aes_cifrada)
        # Grava o IV
        arquivo.write(iv)
        # Grava os dados cifrados
        arquivo.write(dados_cifrados)

    print(f"[OK] Arquivo criptografado salvo em: {caminho_saida}")
    return caminho_saida


def descriptografar_arquivo(caminho_arquivo_cifrado, caminho_chave_privada):
    """
    Descriptografa um arquivo cifrado usando a chave privada RSA.

    Processo:
        1. Lê o arquivo cifrado e separa: chave AES cifrada, IV e dados cifrados.
        2. Usa a chave privada RSA para recuperar a chave AES original.
        3. Usa a chave AES recuperada para descriptografar os dados com AES-256-CFB.
        4. Salva o conteúdo original descriptografado.

    Parâmetros:
        caminho_arquivo_cifrado (str): Caminho do arquivo cifrado (.enc).
        caminho_chave_privada (str): Caminho do arquivo PEM da chave privada.

    Retorna:
        str: Caminho do arquivo descriptografado gerado.
    """
    # Carrega a chave privada RSA
    chave_privada = carregar_chave_privada(caminho_chave_privada)

    # Lê o conteúdo do arquivo cifrado
    with open(caminho_arquivo_cifrado, "rb") as arquivo:
        conteudo = arquivo.read()

    # --- Etapa 1: Separa os componentes do arquivo cifrado ---
    # Lê o tamanho da chave AES cifrada (primeiros 2 bytes)
    tamanho_chave = int.from_bytes(conteudo[:2], byteorder="big")

    # Extrai a chave AES cifrada
    chave_aes_cifrada = conteudo[2 : 2 + tamanho_chave]

    # Extrai o IV (logo após a chave AES cifrada)
    iv = conteudo[2 + tamanho_chave : 2 + tamanho_chave + TAMANHO_IV]

    # Extrai os dados cifrados (restante do arquivo)
    dados_cifrados = conteudo[2 + tamanho_chave + TAMANHO_IV :]

    # --- Etapa 2: Recupera a chave AES com a chave privada RSA ---
    chave_aes = chave_privada.decrypt(
        chave_aes_cifrada,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # --- Etapa 3: Descriptografa os dados com AES-256-CFB ---
    decifrador = Cipher(algorithms.AES(chave_aes), modes.CFB(iv))
    decriptador = decifrador.decryptor()
    dados_originais = decriptador.update(dados_cifrados) + decriptador.finalize()

    # --- Etapa 4: Salva o arquivo descriptografado ---
    # Remove a extensão .enc e adiciona .dec para evitar sobrescrever o original
    if caminho_arquivo_cifrado.endswith(EXTENSAO_CIFRADO):
        caminho_saida = caminho_arquivo_cifrado[: -len(EXTENSAO_CIFRADO)] + EXTENSAO_DECIFRADO
    else:
        caminho_saida = caminho_arquivo_cifrado + EXTENSAO_DECIFRADO

    with open(caminho_saida, "wb") as arquivo:
        arquivo.write(dados_originais)

    print(f"[OK] Arquivo descriptografado salvo em: {caminho_saida}")
    return caminho_saida


# =============================================================================
# Interface com o Usuário (Menu Interativo)
# =============================================================================

def exibir_menu():
    """Exibe o menu principal do programa."""
    print("\n" + "=" * 60)
    print("   PROGRAMA DE CRIPTOGRAFIA ASSIMÉTRICA (RSA)")
    print("=" * 60)
    print("  [1] Gerar par de chaves RSA (pública e privada)")
    print("  [2] Criptografar um arquivo")
    print("  [3] Descriptografar um arquivo")
    print("  [0] Sair")
    print("=" * 60)


def solicitar_caminho(mensagem):
    """
    Solicita ao usuário um caminho de arquivo e valida se ele existe.

    Parâmetros:
        mensagem (str): Mensagem exibida ao usuário.

    Retorna:
        str: Caminho validado do arquivo.
    """
    while True:
        caminho = input(mensagem).strip().strip('"')  # Remove aspas caso o usuário arraste o arquivo
        if os.path.isfile(caminho):
            return caminho
        print(f"[ERRO] Arquivo não encontrado: {caminho}")
        print("       Verifique o caminho e tente novamente.\n")


def main():
    """Função principal que controla o fluxo do programa."""
    print("\nBem-vindo ao programa de criptografia RSA!")
    print("Este programa utiliza criptografia assimétrica (RSA) com esquema")
    print("híbrido (RSA + AES) para criptografar e descriptografar arquivos.\n")

    while True:
        exibir_menu()
        opcao = input("\nEscolha uma opção: ").strip()

        # ----- Opção 1: Gerar par de chaves -----
        if opcao == "1":
            print("\n--- Geração de Chaves RSA ---")
            pasta = input("Pasta para salvar as chaves (Enter = pasta atual): ").strip().strip('"')
            if not pasta:
                pasta = "."
            if not os.path.isdir(pasta):
                print(f"[ERRO] Pasta não encontrada: {pasta}")
                continue

            gerar_par_de_chaves(pasta)
            print("\nAs chaves foram geradas com sucesso!")
            print("IMPORTANTE: Guarde a chave privada em local seguro.")
            print("            A chave pública pode ser compartilhada.")

        # ----- Opção 2: Criptografar arquivo -----
        elif opcao == "2":
            print("\n--- Criptografar Arquivo ---")
            caminho_arquivo = solicitar_caminho("Caminho do arquivo a criptografar: ")
            caminho_chave = solicitar_caminho("Caminho da chave pública (.pem): ")

            try:
                criptografar_arquivo(caminho_arquivo, caminho_chave)
                print("\nArquivo criptografado com sucesso!")
            except Exception as erro:
                print(f"\n[ERRO] Falha ao criptografar: {erro}")

        # ----- Opção 3: Descriptografar arquivo -----
        elif opcao == "3":
            print("\n--- Descriptografar Arquivo ---")
            caminho_arquivo = solicitar_caminho("Caminho do arquivo cifrado (.enc): ")
            caminho_chave = solicitar_caminho("Caminho da chave privada (.pem): ")

            try:
                descriptografar_arquivo(caminho_arquivo, caminho_chave)
                print("\nArquivo descriptografado com sucesso!")
            except Exception as erro:
                print(f"\n[ERRO] Falha ao descriptografar: {erro}")
                print("       Verifique se está usando a chave privada correta.")

        # ----- Opção 0: Sair -----
        elif opcao == "0":
            print("\nEncerrando o programa. Até logo!")
            sys.exit(0)

        else:
            print("\n[ERRO] Opção inválida. Tente novamente.")


# =============================================================================
# Ponto de Entrada
# =============================================================================

if __name__ == "__main__":
    main()
