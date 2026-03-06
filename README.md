# file-encrypt

Atividade 1 - Criptografia | Disciplina de Segurança dos Dados

## Descrição

Programa de **criptografia assimétrica (RSA)** para arquivos, utilizando esquema híbrido RSA + AES-256 para garantir a **integridade e confidencialidade** dos dados.

### Como funciona

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

Execute o programa:

```bash
python file_encrypt.py
```

O menu interativo oferece 3 opções:

1. **Gerar par de chaves RSA** — cria `chave_privada.pem` e `chave_publica.pem`
2. **Criptografar um arquivo** — selecione o arquivo e a chave pública; gera um arquivo `.enc`
3. **Descriptografar um arquivo** — selecione o arquivo `.enc` e a chave privada; gera um arquivo `.dec`

### Exemplo passo a passo

```
1. Escolha a opção [1] para gerar as chaves
2. Escolha a opção [2] e informe o arquivo a criptografar + chave pública
3. Escolha a opção [3] e informe o arquivo .enc + chave privada
4. O arquivo original é recuperado com extensão .dec
```

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
