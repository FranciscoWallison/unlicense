# Unlicense - Documentacao Completa

Ferramenta Python 3 para desempacotar dinamicamente executaveis protegidos com
**Themida/WinLicense 2.x e 3.x**.

**Autor original:** Erwan Grelet
**Licenca:** GPL-3.0-or-later
**Versao atual:** 0.4.0
**Repositorio:** https://github.com/ergrelet/unlicense

---

## Indice

1. [O que e o Unlicense](#1-o-que-e-o-unlicense)
2. [Como funciona internamente](#2-como-funciona-internamente)
3. [Estrutura do projeto](#3-estrutura-do-projeto)
4. [Dependencias](#4-dependencias)
5. [Como configurar o ambiente](#5-como-configurar-o-ambiente)
6. [Como usar a ferramenta](#6-como-usar-a-ferramenta)
7. [Como compilar o EXE com PyInstaller](#7-como-compilar-o-exe-com-pyinstaller)
8. [Flags e opcoes da CLI](#8-flags-e-opcoes-da-cli)
9. [Limitacoes conhecidas](#9-limitacoes-conhecidas)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. O que e o Unlicense

O Unlicense e uma ferramenta de engenharia reversa que remove a protecao
Themida/WinLicense de executaveis (EXE e DLL). O Themida e um software
comercial de protecao que ofusca e empacota binarios para impedir analise
e engenharia reversa.

### O que a ferramenta faz:

1. **Executa o binario protegido** em ambiente controlado (via Frida)
2. **Detecta o Original Entry Point (OEP)** - o ponto de entrada real do programa
3. **Recupera a Import Address Table (IAT)** - a tabela de funcoes importadas que
   foi ofuscada pelo Themida
4. **Faz o dump do processo** da memoria para um novo arquivo PE
5. **Reconstroi o executavel** com as importacoes corrigidas

### Funcionalidades:

- Suporta Themida/WinLicense 2.x e 3.x
- Suporta PEs 32-bit e 64-bit (EXE e DLL)
- Suporta .NET assemblies 32-bit e 64-bit (somente EXE)
- Recuperacao automatica do OEP
- Recuperacao automatica da IAT ofuscada

---

## 2. Como funciona internamente

### Fluxo completo de execucao:

```
Entrada (arquivo PE protegido)
         |
         v
[1] Deteccao de Versao (Themida 2.x ou 3.x?)
         |
         v
[2] Verificacao de Arquitetura (32-bit ou 64-bit?)
         |
         v
[3] Analise de Secoes (.text, .themida, etc.)
         |
         v
[4] Frida: Spawn e Instrumentacao do Processo
         |
         v
[5] Espera OEP ser atingido (com timeout)
         |
         v
[6] Recuperacao de Imports (IAT)
    |                    |
    v                    v
  v2.x                v3.x
    |                    |
    v                    v
[7] Dump da memoria via pyscylla
         |
         v
[8] Correcao da IAT no PE
         |
         v
[9] Reconstrucao do PE (LIEF)
         |
         v
Saida: unpacked_[nome_original].exe
```

### Etapa 1: Deteccao de Versao (`version_detection.py`)

Analisa os headers PE em busca de marcadores especificos do Themida:
- **Versao 3.x:** Procura secoes chamadas `.themida` ou `.winlice`
- **Versao 2.x:** Verifica padroes de importacao especificos (kernel32.dll com
  lstrcpy, comctl32.dll com InitCommonControls) e padroes de instrucoes x86

### Etapa 2: Spawn e Deteccao de OEP (`frida_exec.py`)

Usa o **Frida** (framework de instrumentacao dinamica) para:
- Criar o processo do executavel protegido em estado suspenso
- Injetar um script JavaScript (`frida.js`) que monitora a execucao
- Rastrear a secao `.text` para detectar quando o codigo desempacotado e executado
- Registrar o endereco base da imagem, OEP e se e .NET

### Etapa 3: Recuperacao de Imports

#### Para Themida 2.x (`winlicense2.py`):
1. Desassembla a secao `.text` usando **Capstone** para encontrar instrucoes
   `call` e `jmp`
2. Identifica "wrapped imports" (chamadas para wrappers em vez de imports diretos)
3. Resolve wrappers usando duas estrategias:
   - **Hash-matching (somente 32-bit):** Calcula xxhash de cada funcao e compara
     com hashes de exports
   - **Emulacao:** Usa o emulador **Unicorn** para executar o wrapper e capturar
     o endereco da API resolvida
4. Gera uma nova IAT na memoria do processo
5. Corrige os sites de call/jmp para apontar para a nova IAT

#### Para Themida 3.x (`winlicense3.py`):
1. Primeiro tenta busca linear nas secoes de dados para encontrar a IAT ofuscada
2. Caso falhe, busca wrapped imports nas secoes de codigo
3. Usa emulacao (Unicorn) para resolver funcoes wrapper para APIs reais
4. Detecta chamadas "bogus" de API (como `Sleep`) adicionadas pelo Themida 3.1.4.0
5. Trata TLS callbacks e casos especiais (ExitProcess, FatalExit)

### Etapa 4: Dump e Reconstrucao (`dump_utils.py`)

Usa **pyscylla** para:
1. Fazer dump da memoria do processo no OEP para um arquivo
2. Corrigir a IAT baseado nas importacoes recuperadas
3. Reconstruir secoes e headers do PE

Usa **LIEF** para:
1. Renomear secoes adequadamente (.text, .rsrc, etc.)
2. Desabilitar ASLR (remove flag de base dinamica)
3. Calcular tamanho correto do PE
4. Reconstruir o DOS stub

### Motor de Emulacao (`emulation.py`)

- Configura o emulador Unicorn com stack falsa, TEB/PEB simulados
- Mapeia paginas sob demanda a partir do processo em execucao
- Intercepta acessos a memoria e execucao de blocos
- Para quando atinge uma API exportada ou endereco de retorno magico
- Retorna o endereco da API resolvida (registrador EAX/RAX)

---

## 3. Estrutura do projeto

```
unlicense/
|-- unlicense/                     # Pacote Python principal
|   |-- __init__.py
|   |-- __main__.py               # Ponto de entrada (entry point)
|   |-- application.py            # Orquestrador principal e CLI
|   |-- version_detection.py      # Deteccao de versao Themida
|   |-- frida_exec.py             # Instrumentacao Frida e deteccao de OEP
|   |-- process_control.py        # Interface abstrata de controle de processo
|   |-- dump_utils.py             # Utilitarios de dump PE via pyscylla
|   |-- winlicense2.py            # Logica de unpacking Themida 2.x
|   |-- winlicense3.py            # Logica de unpacking Themida 3.x
|   |-- emulation.py              # Emulacao Unicorn para resolucao de wrappers
|   |-- imports.py                # Deteccao e analise de imports
|   |-- function_hashing.py       # Hashing de funcoes com xxhash
|   |-- lief_utils.py             # Wrappers para LIEF
|   |-- logger.py                 # Configuracao de logging
|   |-- resources/
|   |   |-- __init__.py
|   |   +-- frida.js              # Script de instrumentacao Frida (JavaScript)
|   +-- __pycache__/
|-- assets/
|   +-- unlicense.ico             # Icone do executavel
|-- .github/workflows/
|   |-- check.yml                 # CI: linting e type checking
|   +-- pyinstaller.yml           # CI: build do EXE via PyInstaller
|-- pyproject.toml                # Configuracao Poetry (dependencias)
|-- poetry.lock                   # Dependencias travadas
|-- unlicense.spec                # Spec do PyInstaller para gerar o EXE
|-- README.md                     # Documentacao basica
|-- CHANGELOG.md                  # Historico de versoes
|-- LICENSE                       # Licenca GPL-3.0
+-- .gitignore
```

---

## 4. Dependencias

### Dependencias de producao:

| Pacote     | Versao   | Funcao                                           |
|------------|----------|--------------------------------------------------|
| frida      | ^16.1    | Instrumentacao dinamica / hooking de processos    |
| unicorn    | ^1.0     | Emulador de CPU para analisar wrappers            |
| lief       | ^0.13    | Parsing e manipulacao de binarios PE              |
| fire       | ^0.4     | Framework CLI (gera CLI a partir de funcoes)      |
| capstone   | ^4.0     | Engine de desassembly (disassembler)              |
| xxhash     | ^2.0     | Hashing rapido para identificacao de funcoes      |
| pyscylla   | ^0.11    | Dump de PE e reconstrucao de IAT                  |

### Dependencias de desenvolvimento:

| Pacote      | Versao  | Funcao                                |
|-------------|---------|---------------------------------------|
| mypy        | ^0.910  | Verificacao de tipos estatica         |
| pylint      | ^2.11   | Linting de codigo                     |
| yapf        | ^0.32.0 | Formatacao automatica de codigo       |
| toml        | ^0.10.2 | Parsing de arquivos TOML              |
| pyinstaller | ^5.13   | Compilacao para executavel standalone |

---

## 5. Como configurar o ambiente

### Requisitos:

- **Windows** (obrigatorio - a ferramenta usa Frida para instrumentacao Windows)
- **Python 3.9 (32-bit)** para desempacotar EXEs de 32-bit
- **Python 3.11 (64-bit)** para desempacotar EXEs de 64-bit

> **IMPORTANTE:** O bitness do Python DEVE corresponder ao bitness do EXE alvo.
> Python 32-bit para EXE 32-bit, Python 64-bit para EXE 64-bit.

### Metodo 1: Usando pip (simples)

```bash
# 1. Instale Python 3.9 32-bit (para EXEs 32-bit)
# Download: https://www.python.org/ftp/python/3.9.13/python-3.9.13.exe
# Marque "Add Python to PATH" durante instalacao

# 2. Crie um ambiente virtual
py -3.9-32 -m venv unlicense_env
unlicense_env\Scripts\activate

# 3. Instale o LIEF compativel (32-bit)
# Baixe de: https://github.com/lief-project/LIEF/releases
# Procure por: lief-0.13.1-cp39-cp39-win32.whl
pip install lief-0.13.1-cp39-cp39-win32.whl

# 4. Instale o unlicense
pip install git+https://github.com/ergrelet/unlicense.git
```

### Metodo 2: Usando Poetry (desenvolvimento)

```bash
# 1. Instale o Poetry
pip install poetry

# 2. Clone o repositorio
git clone https://github.com/ergrelet/unlicense.git
cd unlicense

# 3. Instale todas as dependencias
poetry install

# 4. Execute via Poetry
poetry run python -m unlicense SeuEXE.exe
```

### Metodo 3: Usando o EXE pre-compilado

Baixe o executavel diretamente da secao "Releases" do GitHub:
https://github.com/ergrelet/unlicense/releases

Disponivel em versoes 32-bit e 64-bit.

---

## 6. Como usar a ferramenta

### Uso basico (CLI):

```bash
# Forma mais simples
python -m unlicense MeuExecutavel.exe

# Com verbose (recomendado para debug)
python -m unlicense MeuExecutavel.exe --verbose=True

# Pausar no OEP (util para inspecao manual)
python -m unlicense MeuExecutavel.exe --verbose=True --pause_on_oep=True

# Apenas dump sem correcao de imports
python -m unlicense MeuExecutavel.exe --no_imports=True

# Forcar OEP manual (RVA)
python -m unlicense MeuExecutavel.exe --force_oep=0x12345

# Forcar versao do Themida
python -m unlicense MeuExecutavel.exe --target_version=3

# Timeout customizado (padrao: 10 segundos)
python -m unlicense MeuExecutavel.exe --timeout=30
```

### Uso por drag-and-drop:

Arraste o arquivo EXE/DLL alvo sobre o `unlicense.exe` (versao compilada).

### Saida:

O arquivo desempacotado sera gerado no mesmo diretorio com o prefixo `unpacked_`:
```
MeuExecutavel.exe  -->  unpacked_MeuExecutavel.exe
```

---

## 7. Como compilar o EXE com PyInstaller

Este e o processo para gerar um executavel standalone a partir do codigo fonte.

### Pre-requisitos:

- Python instalado (32 ou 64-bit conforme necessidade)
- Todas as dependencias instaladas

### Metodo 1: Via Poetry (recomendado)

```bash
# 1. Instale as dependencias (incluindo pyinstaller)
poetry install

# 2. Compile o EXE usando o arquivo .spec
poetry run pyinstaller unlicense.spec

# 3. O EXE sera gerado em:
#    dist/unlicense.exe
```

### Metodo 2: Via pip direto

```bash
# 1. Instale o PyInstaller
pip install pyinstaller

# 2. Instale as dependencias do projeto
pip install frida unicorn lief fire capstone xxhash pyscylla

# 3. Compile usando o spec file
pyinstaller unlicense.spec

# 4. O EXE sera gerado em:
#    dist/unlicense.exe
```

### O que o arquivo `unlicense.spec` faz:

```python
# Coleta DLLs dinamicas do Capstone e Unicorn
dlls = collect_dynamic_libs("capstone") + collect_dynamic_libs("unicorn")

# Inclui todo o pacote unlicense/ como dados
resource_files = [('unlicense/', 'unlicense')]

# Configuracao do executavel:
# - Entry point: unlicense/__main__.py
# - Binarios: DLLs do Capstone + Unicorn
# - Dados: pacote unlicense (inclui frida.js)
# - Icone: assets/unlicense.ico
# - Console: True (aplicacao de terminal)
# - UPX: False (nao comprime o executavel)
```

### Compilacao para ambas arquiteturas:

Para gerar EXEs de 32 e 64-bit, voce precisa compilar separadamente:

```bash
# Para 32-bit: use Python 32-bit
py -3.9-32 -m venv venv32
venv32\Scripts\activate
pip install poetry
poetry install
poetry run pyinstaller unlicense.spec
# Resultado: dist/unlicense.exe (32-bit)

# Para 64-bit: use Python 64-bit
py -3.11 -m venv venv64
venv64\Scripts\activate
pip install poetry
poetry install
poetry run pyinstaller unlicense.spec
# Resultado: dist/unlicense.exe (64-bit)
```

### Verificando o build:

```bash
# Testar se o EXE foi gerado corretamente
dist\unlicense.exe --help
```

---

## 8. Flags e opcoes da CLI

| Flag                | Tipo          | Padrao  | Descricao                                          |
|---------------------|---------------|---------|-----------------------------------------------------|
| `PE_TO_DUMP`        | str           | -       | Caminho do arquivo PE a ser desempacotado (obrigatorio) |
| `--verbose`         | bool          | False   | Ativa logs detalhados para debug                    |
| `--pause_on_oep`    | bool          | False   | Pausa a execucao ao atingir o OEP (para inspecao)   |
| `--no_imports`      | bool          | False   | Faz dump no OEP sem corrigir imports                |
| `--force_oep`       | int (opcional)| None    | Forca um RVA especifico como OEP                    |
| `--target_version`  | int (opcional)| None    | Forca versao do Themida (2 ou 3), auto-detecta se omitido |
| `--timeout`         | int           | 10      | Timeout em segundos para deteccao do OEP            |

---

## 9. Limitacoes conhecidas

1. **Nao trata DLLs .NET** - somente EXEs .NET sao suportados
2. **Dumps geralmente nao sao executaveis** - o executavel gerado pode nao rodar
   diretamente na maioria dos casos
3. **Resolucao de imports lenta para 32-bit + Themida 2.x** - o processo de
   hash-matching e emulacao e demorado
4. **Requer licenca valida** - se o executavel protegido com WinLicense exige
   arquivo de licenca para iniciar, voce precisa dele
5. **Bitness deve corresponder** - Python 32-bit para PEs 32-bit, Python 64-bit
   para PEs 64-bit
6. **Executar em VM** - o binario alvo e executado durante o processo, entao
   use em maquina virtual se nao confia no arquivo

---

## 10. Troubleshooting

### Erro: "Target PE cannot be dumped with this interpreter"
**Causa:** Mismatch de bitness entre Python e o EXE alvo.
**Solucao:** Use Python 32-bit para EXEs 32-bit e Python 64-bit para EXEs 64-bit.

### Erro: "Failed to automatically detect packer version"
**Causa:** O arquivo pode nao estar protegido com Themida/WinLicense, ou e uma
versao nao reconhecida.
**Solucao:** Tente usar `--target_version=2` ou `--target_version=3` para forcar.

### Erro: "Original entry point wasn't reached before timeout"
**Causa:** O programa demorou mais que o timeout para atingir o OEP.
**Solucao:** Aumente o timeout com `--timeout=60`. Se o programa requer
interacao do usuario ou licenca, isso tambem pode ser a causa.

### O dump nao executa
**Causa:** Limitacao conhecida. O Themida aplica diversas camadas de protecao
e o dump pode ter imports incompletos ou secoes corrompidas.
**Solucao:** Tente com `--pause_on_oep=True` para verificar manualmente o estado.
Use ferramentas adicionais como x64dbg ou IDA Pro para corrigir o dump.

### Erro ao instalar LIEF para 32-bit
**Causa:** O pip pode tentar instalar a versao 64-bit do LIEF.
**Solucao:** Baixe manualmente o wheel `lief-0.13.1-cp39-cp39-win32.whl` do
GitHub do LIEF e instale com `pip install lief-0.13.1-cp39-cp39-win32.whl`.

### Frida nao consegue instrumentar o processo
**Causa:** Antivirus pode estar bloqueando a injecao de codigo.
**Solucao:** Desative temporariamente o antivirus ou adicione excecao para o
diretorio de trabalho. Lembre-se: use em VM.

---

## Resumo rapido

```bash
# Setup completo (32-bit)
py -3.9-32 -m venv env
env\Scripts\activate
pip install lief-0.13.1-cp39-cp39-win32.whl
pip install git+https://github.com/ergrelet/unlicense.git

# Desempacotar
python -m unlicense MeuExe.exe --verbose=True

# Compilar EXE
pip install pyinstaller
pyinstaller unlicense.spec
# Output: dist/unlicense.exe
```
