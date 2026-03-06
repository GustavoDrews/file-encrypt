# file-encrypt

Atividade 1 - Criptografia | Disciplina de Segurança dos Dados

## Descrição

Programa de **criptografia assimétrica (RSA)** para arquivos com **interface gráfica (tkinter)**, utilizando esquema híbrido RSA + AES-256 para garantir a **integridade e confidencialidade** dos dados.

## Por que um sistema híbrido (RSA + AES)?

O RSA é um algoritmo de criptografia **assimétrica** muito seguro, mas possui uma limitação importante: ele só consegue cifrar uma quantidade pequena de dados por vez (para uma chave de 2048 bits, o máximo é cerca de **190 bytes** com padding OAEP). Isso significa que **não é possível cifrar um arquivo inteiro diretamente com RSA**.

Para resolver isso, utilizamos um **esquema híbrido** que combina o melhor dos dois mundos:

| Algoritmo | Tipo | Papel no programa |
|-----------|------|-------------------|
| **RSA** | Assimétrico (par de chaves) | Protege a chave AES — só quem tem a chave privada consegue recuperá-la |
| **AES-256** | Simétrico (chave única) | Cifra o conteúdo do arquivo — rápido e sem limite de tamanho |

### Fluxo da criptografia híbrida

```
┌─────────────────────────────────────────────────────────┐
│                    CRIPTOGRAFAR                         │
├─────────────────────────────────────────────────────────┤
│  1. Gera uma chave AES-256 aleatória (descartável)     │
│  2. Cifra o arquivo inteiro com AES-256-CFB             │
│  3. Cifra a chave AES com a chave PÚBLICA RSA           │
│  4. Salva tudo junto no arquivo .enc                    │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                   DESCRIPTOGRAFAR                       │
├─────────────────────────────────────────────────────────┤
│  1. Lê o arquivo .enc e separa os componentes           │
│  2. Usa a chave PRIVADA RSA para recuperar a chave AES  │
│  3. Usa a chave AES para descriptografar o arquivo      │
│  4. Salva o arquivo original com extensão .dec          │
└─────────────────────────────────────────────────────────┘
```

> **Resumo:** o RSA protege a "chave da chave" (a chave AES), e o AES faz o trabalho pesado de cifrar os dados. Assim temos a **segurança do RSA** (par de chaves pública/privada) com a **eficiência do AES** (cifra arquivos de qualquer tamanho).

## Como funciona

| Etapa | Descrição |
|-------|-----------|
| **Geração de chaves** | Gera um par de chaves RSA (pública e privada) de 2048 bits |
| **Criptografia** | Gera uma chave AES-256 aleatória, cifra o arquivo com AES-CFB e protege a chave AES com a chave pública RSA (OAEP + SHA-256) |
| **Descriptografia** | Usa a chave privada RSA para recuperar a chave AES e descriptografar o arquivo |

## Pré-requisitos

- Python 3.8 ou superior
- Biblioteca `cryptography`

## Instalação

```bash
pip install -r requirements.txt
```

## Uso

### Interface gráfica

Execute o programa:

```bash
python file_encrypt.py
```

A janela oferece 3 botões:

- **🔑 Gerar Par de Chaves RSA** — cria `chave_privada.pem` e `chave_publica.pem` na pasta escolhida
- **🔒 Criptografar Arquivo** — selecione o arquivo e a chave pública; gera um arquivo `.enc`
- **🔓 Descriptografar Arquivo** — selecione o arquivo `.enc` e a chave privada; gera um arquivo `.dec`

### Exemplo passo a passo

```
1. Clique em "Gerar Par de Chaves RSA" e escolha uma pasta
2. Clique em "Criptografar Arquivo", selecione o arquivo e a chave pública
3. Clique em "Descriptografar Arquivo", selecione o .enc e a chave privada
4. O arquivo original é recuperado com extensão .dec
```

### Gerando o executável (.exe)

Para distribuir o programa sem precisar de Python instalado:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "CriptografiaRSA" file_encrypt.py
```

O executável será gerado em `dist/CriptografiaRSA.exe`.

## Estrutura do Arquivo Cifrado

```
[2 bytes: tamanho da chave AES cifrada]
[N bytes: chave AES cifrada com RSA]
[16 bytes: IV (vetor de inicialização)]
[restante: dados cifrados com AES-256-CFB]
```

## Tecnologias

- **RSA 2048** — criptografia assimétrica (par de chaves)
- **AES-256-CFB** — criptografia simétrica (cifra os dados)
- **OAEP + SHA-256** — padding seguro para RSA
- **tkinter** — interface gráfica (biblioteca padrão do Python)
- **PyInstaller** — geração de executável (.exe)
