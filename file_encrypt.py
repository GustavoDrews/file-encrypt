"""
=============================================================================
Programa de Criptografia Assimétrica (RSA) para Arquivos — Interface Gráfica
=============================================================================

Este programa permite criptografar e descriptografar arquivos utilizando
criptografia assimétrica RSA com esquema híbrido (RSA + AES).

Interface gráfica construída com tkinter (biblioteca padrão do Python).

Dependências: pip install cryptography

Autor: Estudante
Data: Março 2026
"""

import os
import tkinter as tk
from tkinter import filedialog, messagebox
from os import urandom

# --- Módulos da biblioteca 'cryptography' ---
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# =============================================================================
# Constantes
# =============================================================================

TAMANHO_CHAVE_RSA = 2048       # Bits da chave RSA (2048 é o mínimo recomendado)
TAMANHO_CHAVE_AES = 32         # Bytes (256 bits) para AES-256
TAMANHO_IV = 16                # Bytes do vetor de inicialização (IV) para AES
EXTENSAO_CIFRADO = ".enc"      # Extensão do arquivo cifrado
EXTENSAO_DECIFRADO = ".dec"    # Extensão do arquivo descriptografado


# =============================================================================
# Funções de Criptografia (lógica de negócio)
# =============================================================================

def gerar_par_de_chaves(pasta_destino):
    """
    Gera um par de chaves RSA (pública e privada) e salva em arquivos PEM.

    Parâmetros:
        pasta_destino (str): Pasta onde as chaves serão salvas.

    Retorna:
        tuple: Caminhos dos arquivos (chave_privada, chave_publica).
    """
    # Gera a chave privada RSA
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=TAMANHO_CHAVE_RSA,
    )

    # Deriva a chave pública a partir da privada
    chave_publica = chave_privada.public_key()

    # Define os caminhos dos arquivos
    caminho_privada = os.path.join(pasta_destino, "chave_privada.pem")
    caminho_publica = os.path.join(pasta_destino, "chave_publica.pem")

    # Salva a chave privada em formato PEM
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

    return caminho_privada, caminho_publica


def carregar_chave_publica(caminho):
    """Carrega uma chave pública RSA a partir de um arquivo PEM."""
    with open(caminho, "rb") as arquivo:
        return serialization.load_pem_public_key(arquivo.read())


def carregar_chave_privada(caminho):
    """Carrega uma chave privada RSA a partir de um arquivo PEM."""
    with open(caminho, "rb") as arquivo:
        return serialization.load_pem_private_key(arquivo.read(), password=None)


def criptografar_arquivo(caminho_arquivo, caminho_chave_publica):
    """
    Criptografa um arquivo usando esquema híbrido RSA + AES.

    Processo:
        1. Gera chave AES aleatória e IV.
        2. Cifra o conteúdo com AES-256-CFB.
        3. Cifra a chave AES com a chave pública RSA (OAEP + SHA-256).
        4. Salva: [tamanho chave AES cifrada][chave AES cifrada][IV][dados cifrados].
    """
    chave_publica = carregar_chave_publica(caminho_chave_publica)

    with open(caminho_arquivo, "rb") as arquivo:
        dados_originais = arquivo.read()

    # Gera chave AES e IV aleatórios
    chave_aes = urandom(TAMANHO_CHAVE_AES)
    iv = urandom(TAMANHO_IV)

    # Cifra o conteúdo com AES-256-CFB
    cifrador = Cipher(algorithms.AES(chave_aes), modes.CFB(iv))
    encriptador = cifrador.encryptor()
    dados_cifrados = encriptador.update(dados_originais) + encriptador.finalize()

    # Cifra a chave AES com RSA (OAEP + SHA-256)
    chave_aes_cifrada = chave_publica.encrypt(
        chave_aes,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Monta e salva o arquivo cifrado
    caminho_saida = caminho_arquivo + EXTENSAO_CIFRADO
    with open(caminho_saida, "wb") as arquivo:
        tamanho_chave = len(chave_aes_cifrada)
        arquivo.write(tamanho_chave.to_bytes(2, byteorder="big"))
        arquivo.write(chave_aes_cifrada)
        arquivo.write(iv)
        arquivo.write(dados_cifrados)

    return caminho_saida


def descriptografar_arquivo(caminho_arquivo_cifrado, caminho_chave_privada):
    """
    Descriptografa um arquivo cifrado usando a chave privada RSA.

    Processo:
        1. Separa: chave AES cifrada, IV e dados cifrados.
        2. Recupera a chave AES com a chave privada RSA.
        3. Descriptografa os dados com AES-256-CFB.
    """
    chave_privada = carregar_chave_privada(caminho_chave_privada)

    with open(caminho_arquivo_cifrado, "rb") as arquivo:
        conteudo = arquivo.read()

    # Separa os componentes do arquivo cifrado
    tamanho_chave = int.from_bytes(conteudo[:2], byteorder="big")
    chave_aes_cifrada = conteudo[2 : 2 + tamanho_chave]
    iv = conteudo[2 + tamanho_chave : 2 + tamanho_chave + TAMANHO_IV]
    dados_cifrados = conteudo[2 + tamanho_chave + TAMANHO_IV :]

    # Recupera a chave AES com a chave privada RSA
    chave_aes = chave_privada.decrypt(
        chave_aes_cifrada,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Descriptografa os dados com AES-256-CFB
    decifrador = Cipher(algorithms.AES(chave_aes), modes.CFB(iv))
    decriptador = decifrador.decryptor()
    dados_originais = decriptador.update(dados_cifrados) + decriptador.finalize()

    # Salva o arquivo descriptografado
    if caminho_arquivo_cifrado.endswith(EXTENSAO_CIFRADO):
        caminho_saida = caminho_arquivo_cifrado[: -len(EXTENSAO_CIFRADO)] + EXTENSAO_DECIFRADO
    else:
        caminho_saida = caminho_arquivo_cifrado + EXTENSAO_DECIFRADO

    with open(caminho_saida, "wb") as arquivo:
        arquivo.write(dados_originais)

    return caminho_saida


# =============================================================================
# Interface Gráfica (tkinter)
# =============================================================================

class AplicativoCriptografia:
    """Classe principal da interface gráfica do programa de criptografia RSA."""

    def __init__(self, janela_raiz):
        self.janela = janela_raiz
        self.janela.title("Criptografia RSA — Segurança dos Dados")
        self.janela.geometry("620x520")
        self.janela.resizable(False, False)

        # Configura o estilo geral
        self.janela.configure(bg="#f0f0f0")

        self._criar_interface()

    def _criar_interface(self):
        """Monta todos os elementos visuais da interface."""

        # --- Título ---
        frame_titulo = tk.Frame(self.janela, bg="#2c3e50", pady=15)
        frame_titulo.pack(fill="x")

        tk.Label(
            frame_titulo,
            text="🔐 Criptografia Assimétrica (RSA)",
            font=("Segoe UI", 16, "bold"),
            fg="white",
            bg="#2c3e50",
        ).pack()

        tk.Label(
            frame_titulo,
            text="Esquema híbrido RSA + AES-256 para arquivos",
            font=("Segoe UI", 9),
            fg="#bdc3c7",
            bg="#2c3e50",
        ).pack()

        # --- Botões de ação ---
        frame_botoes = tk.Frame(self.janela, bg="#f0f0f0", pady=20)
        frame_botoes.pack(fill="x", padx=30)

        # Botão 1: Gerar chaves
        self._criar_botao(
            frame_botoes,
            texto="🔑  Gerar Par de Chaves RSA",
            descricao="Cria chave pública e privada (arquivos .pem)",
            comando=self._acao_gerar_chaves,
            cor="#27ae60",
        )

        # Botão 2: Criptografar
        self._criar_botao(
            frame_botoes,
            texto="🔒  Criptografar Arquivo",
            descricao="Selecione um arquivo e a chave pública para cifrar",
            comando=self._acao_criptografar,
            cor="#2980b9",
        )

        # Botão 3: Descriptografar
        self._criar_botao(
            frame_botoes,
            texto="🔓  Descriptografar Arquivo",
            descricao="Selecione um arquivo .enc e a chave privada para decifrar",
            comando=self._acao_descriptografar,
            cor="#8e44ad",
        )

        # --- Área de log (registro de operações) ---
        frame_log = tk.LabelFrame(
            self.janela,
            text=" Registro de Operações ",
            font=("Segoe UI", 10, "bold"),
            bg="#f0f0f0",
            padx=10,
            pady=5,
        )
        frame_log.pack(fill="both", expand=True, padx=30, pady=(0, 15))

        self.texto_log = tk.Text(
            frame_log,
            height=8,
            font=("Consolas", 9),
            bg="#1e1e1e",
            fg="#00ff00",
            insertbackground="white",
            state="disabled",
            wrap="word",
        )
        self.texto_log.pack(fill="both", expand=True)

        self._log("Programa iniciado. Selecione uma opção acima.")

    def _criar_botao(self, pai, texto, descricao, comando, cor):
        """Cria um botão estilizado com descrição abaixo."""
        frame = tk.Frame(pai, bg="#f0f0f0", pady=5)
        frame.pack(fill="x")

        botao = tk.Button(
            frame,
            text=texto,
            font=("Segoe UI", 12, "bold"),
            bg=cor,
            fg="white",
            activebackground=cor,
            activeforeground="white",
            relief="flat",
            cursor="hand2",
            command=comando,
            height=1,
            padx=15,
        )
        botao.pack(fill="x")

        tk.Label(
            frame,
            text=descricao,
            font=("Segoe UI", 8),
            fg="#7f8c8d",
            bg="#f0f0f0",
        ).pack(anchor="w", padx=5)

    def _log(self, mensagem):
        """Adiciona uma mensagem na área de log."""
        self.texto_log.configure(state="normal")
        self.texto_log.insert("end", f"> {mensagem}\n")
        self.texto_log.see("end")
        self.texto_log.configure(state="disabled")

    # -------------------------------------------------------------------------
    # Ações dos botões
    # -------------------------------------------------------------------------

    def _acao_gerar_chaves(self):
        """Ação do botão 'Gerar Par de Chaves RSA'."""
        # Solicita a pasta onde salvar as chaves
        pasta = filedialog.askdirectory(title="Selecione a pasta para salvar as chaves")
        if not pasta:
            return  # Usuário cancelou

        try:
            caminho_privada, caminho_publica = gerar_par_de_chaves(pasta)
            self._log(f"Chave privada salva em: {caminho_privada}")
            self._log(f"Chave pública salva em: {caminho_publica}")
            messagebox.showinfo(
                "Chaves Geradas",
                f"Par de chaves RSA gerado com sucesso!\n\n"
                f"Chave privada:\n{caminho_privada}\n\n"
                f"Chave pública:\n{caminho_publica}\n\n"
                f"⚠ Guarde a chave privada em local seguro!",
            )
        except Exception as erro:
            self._log(f"ERRO ao gerar chaves: {erro}")
            messagebox.showerror("Erro", f"Falha ao gerar chaves:\n{erro}")

    def _acao_criptografar(self):
        """Ação do botão 'Criptografar Arquivo'."""
        # 1. Seleciona o arquivo a ser criptografado
        caminho_arquivo = filedialog.askopenfilename(
            title="Selecione o arquivo para criptografar"
        )
        if not caminho_arquivo:
            return

        # 2. Seleciona a chave pública
        caminho_chave = filedialog.askopenfilename(
            title="Selecione a chave pública (.pem)",
            filetypes=[("Arquivo PEM", "*.pem"), ("Todos os arquivos", "*.*")],
        )
        if not caminho_chave:
            return

        try:
            caminho_saida = criptografar_arquivo(caminho_arquivo, caminho_chave)
            self._log(f"Arquivo criptografado: {caminho_saida}")
            messagebox.showinfo(
                "Criptografia Concluída",
                f"Arquivo criptografado com sucesso!\n\nSalvo em:\n{caminho_saida}",
            )
        except Exception as erro:
            self._log(f"ERRO ao criptografar: {erro}")
            messagebox.showerror("Erro", f"Falha ao criptografar:\n{erro}")

    def _acao_descriptografar(self):
        """Ação do botão 'Descriptografar Arquivo'."""
        # 1. Seleciona o arquivo cifrado
        caminho_arquivo = filedialog.askopenfilename(
            title="Selecione o arquivo cifrado (.enc)",
            filetypes=[("Arquivo cifrado", "*.enc"), ("Todos os arquivos", "*.*")],
        )
        if not caminho_arquivo:
            return

        # 2. Seleciona a chave privada
        caminho_chave = filedialog.askopenfilename(
            title="Selecione a chave privada (.pem)",
            filetypes=[("Arquivo PEM", "*.pem"), ("Todos os arquivos", "*.*")],
        )
        if not caminho_chave:
            return

        try:
            caminho_saida = descriptografar_arquivo(caminho_arquivo, caminho_chave)
            self._log(f"Arquivo descriptografado: {caminho_saida}")
            messagebox.showinfo(
                "Descriptografia Concluída",
                f"Arquivo descriptografado com sucesso!\n\nSalvo em:\n{caminho_saida}",
            )
        except Exception as erro:
            self._log(f"ERRO ao descriptografar: {erro}")
            messagebox.showerror(
                "Erro",
                f"Falha ao descriptografar:\n{erro}\n\n"
                f"Verifique se está usando a chave privada correta.",
            )


# =============================================================================
# Ponto de Entrada
# =============================================================================

if __name__ == "__main__":
    janela = tk.Tk()
    app = AplicativoCriptografia(janela)
    janela.mainloop()
