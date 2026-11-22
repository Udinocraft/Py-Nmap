# 🐍 Py-Nmap

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?logo=linux&logoColor=white)
![Network](https://img.shields.io/badge/Network-TCP%20Connect%20Scan-orange)
![Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library-green)
![Version](https://img.shields.io/badge/Version-2.0.0-purple)

**A Python-based network scanning tool inspired by Nmap, featuring an interactive terminal, command-line interface and network reconnaissance capabilities.**

---

# 🇧🇷 Português (Brasil)

## 📌 Sobre o projeto

O **Py-Nmap** é uma ferramenta de varredura de portas desenvolvida em Python, inspirada no funcionamento e na proposta do Nmap.

O projeto tem como objetivo explorar conceitos de redes de computadores, comunicação TCP, sockets, identificação de serviços e automação de tarefas de reconhecimento de rede.

A versão 2.0 representa uma evolução significativa em relação à versão inicial, com uma arquitetura mais organizada, novos recursos e diferentes formas de interação com a ferramenta.

O Py-Nmap foi desenvolvido como projeto educacional e de estudo em cibersegurança.

## 🎯 Objetivos

- Estudar o funcionamento de conexões TCP e sockets em Python.
- Compreender os estados de portas em uma varredura de rede.
- Explorar resolução DNS e identificação de serviços.
- Aplicar conceitos de programação orientada a objetos.
- Desenvolver uma ferramenta com interface interativa e CLI.
- Praticar organização, documentação e desenvolvimento de projetos de cibersegurança.

## ⚙️ Funcionalidades

| Recurso | Descrição |
|---|---|
| TCP Connect Scan | Realiza varreduras utilizando conexões TCP completas. |
| Interactive Terminal | Interface interativa para executar comandos e configurar varreduras. |
| Command-Line Interface | Permite executar varreduras diretamente pelo terminal. |
| IP and Domain Resolution | Aceita endereços IP e domínios. |
| URL Support | Permite informar URLs como alvos. |
| CIDR Support | Permite trabalhar com redes em notação CIDR, limitado a 256 hosts por entrada. |
| Port States | Identifica portas como `open`, `closed` ou `filtered`. |
| Service Detection | Realiza identificação básica de serviços por meio de banners e assinaturas. |
| DNS Resolution | Realiza resolução de nomes e consultas relacionadas ao alvo. |
| Reverse DNS | Permite obter nomes associados a endereços IP quando disponíveis. |
| Multithreading | Utiliza processamento concorrente para acelerar as varreduras. |
| Export | Exporta resultados nos formatos JSON, CSV e TXT. |
| Scan History | Mantém histórico das varreduras durante a sessão. |
| IPv4 and IPv6 | Suporta resolução de endereços IPv4 e IPv6. |

## 🧰 Tecnologias utilizadas

| Tecnologia | Aplicação |
|---|---|
| Python 3.8+ | Linguagem principal do projeto. |
| `socket` | Comunicação de rede e conexões TCP. |
| `concurrent.futures` | Execução concorrente de tarefas. |
| `ipaddress` | Manipulação de endereços IP e redes CIDR. |
| `argparse` | Processamento de argumentos da CLI. |
| `ssl` | Implementação de conexões com TLS. |
| `json` | Exportação de resultados em JSON. |
| `csv` | Exportação de resultados em CSV. |
| `threading` / concorrência | Organização de tarefas de varredura. |

O projeto utiliza principalmente bibliotecas da própria biblioteca padrão do Python. No Windows, o pacote opcional `pyreadline3` pode ser utilizado para melhorar a experiência de leitura de comandos.

## 🏗️ Arquitetura

A versão 2.0 foi reorganizada em componentes e classes com responsabilidades específicas.

| Classe | Responsabilidade |
|---|---|
| `Color` | Gerenciamento de cores e elementos visuais do terminal. |
| `Target` | Representação e tratamento dos alvos de varredura. |
| `PortResult` | Armazenamento dos resultados individuais de portas. |
| `HostResult` | Organização dos resultados associados a um host. |
| `Settings` | Configurações utilizadas durante as varreduras. |
| `NetworkScanner` | Execução das varreduras e identificação de serviços. |
| `QuietParser` | Tratamento da saída do processamento de argumentos. |
| `TerminalInterface` | Gerenciamento da interface interativa. |

## 📥 Instalação

### 1. Clonar o repositório

```bash
git clone https://github.com/Udinocraft/Py-Nmap.git
```

### 2. Acessar o diretório

```bash
cd Py-Nmap
```

### 3. Executar a ferramenta

```bash
python3 PROJECT/Py-Nmap.py
```

**Requisitos:**

- Python 3.8 ou superior.
- Sistema operacional compatível com Python e sockets.
- Conexão de rede para realizar varreduras em alvos remotos.

## 🚀 Utilização

O Py-Nmap oferece dois modos principais de utilização.

### Terminal interativo

Inicie a ferramenta:

```bash
python3 PROJECT/Py-Nmap.py
```

A interface permite configurar alvos, portas e parâmetros de varredura por meio de comandos próprios.

| Comando | Função |
|---|---|
| `help` | Exibe os comandos disponíveis. |
| `scan` | Inicia uma varredura. |
| `set` | Altera configurações. |
| `show` | Exibe informações e configurações. |
| `target` | Gerencia o alvo. |
| `results` | Exibe os resultados. |
| `export` | Exporta os resultados. |
| `history` | Exibe o histórico da sessão. |
| `ping` | Realiza uma verificação de conectividade. |
| `dns` | Executa consultas relacionadas ao DNS. |
| `service` | Consulta informações de serviços. |
| `config` | Gerencia configurações. |
| `version` | Exibe a versão da ferramenta. |
| `exit` | Encerra a aplicação. |

### Command-Line Interface (CLI)

Também é possível executar varreduras diretamente pelo terminal.

**Exemplo:**

```bash
python3 PROJECT/Py-Nmap.py scanme.nmap.org -p 1-1024 -T 4 -o resultado.json
```

| Parâmetro | Descrição |
|---|---|
| `-p`, `--ports` | Define as portas que serão verificadas. |
| `-F`, `--fast` | Executa uma varredura rápida. |
| `-T`, `--timing` | Define o perfil de temporização, de 0 a 5. |
| `--timeout` | Define o tempo limite das conexões. |
| `--threads` | Define a quantidade de threads. |
| `--no-banner` | Desativa a identificação por banner. |
| `-v`, `--all` | Exibe informações adicionais. |
| `-r`, `--randomize` | Randomiza a ordem das portas. |
| `-o`, `--output` | Define o arquivo de saída. |
| `--no-color` | Desativa as cores do terminal. |

### 📄 Exportação de resultados

Os resultados podem ser exportados em três formatos:

| Formato | Extensão | Utilização |
|---|---|---|
| JSON | `.json` | Armazenamento estruturado de dados. |
| CSV | `.csv` | Organização dos resultados em tabelas. |
| TXT | `.txt` | Relatórios em texto simples. |

## 📊 Evolução do projeto

A versão 2.0 trouxe mudanças importantes em relação à primeira versão.

| Característica | Versão 1.0 | Versão 2.0 |
|---|---|---|
| Arquitetura | 3 classes | 8 classes |
| Interface | Terminal interativo | Terminal interativo e CLI |
| Alvos | IP e domínio | IP, domínio, URL e CIDR |
| Estados de portas | Apenas abertas | Abertas, fechadas e filtradas |
| Concorrência | 50 threads fixas | Até 500 threads configuráveis |
| Exportação | Não disponível | JSON, CSV e TXT |
| Resolução | IPv4 básico | IPv4 e IPv6, com resolução reversa |
| Histórico | Não disponível | Histórico durante a sessão |
| Autocomplete | Não disponível | Suporte à tecla TAB |

## ⚠️ Limitações técnicas

Apesar de ser inspirado no Nmap, o Py-Nmap não pretende substituir a ferramenta original.

Algumas limitações importantes:

- Implementa TCP Connect Scan, não SYN Scan.
- A identificação de serviços utiliza assinaturas e análise de banners, não uma base completa de detecção.
- A entrada CIDR possui limite de 256 hosts.
- O número máximo configurável de threads é 500.
- A identificação de serviços depende das respostas disponibilizadas pelos hosts.
- A verificação TLS não realiza validação de confiança do certificado apresentado pelo servidor.

Essas limitações fazem parte do escopo atual do projeto e ajudam a delimitar suas capacidades.

## 📚 Documentação e relatórios

O repositório também conta com documentação técnica que registra o desenvolvimento e a evolução do projeto.

Os relatórios apresentam aspectos como:

- Arquitetura e funcionamento.
- Conceitos de redes utilizados.
- Estrutura do código.
- Bibliotecas e tecnologias.
- Comparação entre as versões.
- Desafios encontrados durante o desenvolvimento.
- Melhorias implementadas.

## 🤖 Utilização de inteligência artificial

Ferramentas de inteligência artificial foram utilizadas como apoio durante o desenvolvimento e a documentação do projeto.

| Ferramenta | Utilização |
|---|---|
| ChatGPT | Apoio na organização, revisão e documentação. |
| Claude | Apoio na reestruturação e desenvolvimento do código. |
| Grok | Segunda opinião e revisão complementar. |

As ferramentas foram utilizadas como suporte. A direção do projeto, as decisões técnicas, a análise dos resultados e a responsabilidade pelo desenvolvimento permaneceram sob controle do autor.

## 🔐 Uso responsável

O Py-Nmap foi desenvolvido para fins educacionais, testes autorizados e estudos de segurança de redes.

Utilize a ferramenta somente em sistemas próprios ou em ambientes para os quais você possua autorização explícita.

O autor não se responsabiliza pelo uso indevido da ferramenta.

## 👨‍💻 Autor

**Udinocraft**

Projeto desenvolvido como parte dos estudos e experimentações em programação, redes de computadores e cibersegurança.

- GitHub: https://github.com/Udinocraft
- Projeto: https://github.com/Udinocraft/Py-Nmap

---

# 🇬🇧 English (United Kingdom)

## 📌 About the project

**Py-Nmap** is a Python-based port scanning tool inspired by the functionality and purpose of Nmap.

The project aims to explore computer networking concepts, TCP communication, sockets, service identification and automated network reconnaissance.

Version 2.0 represents a significant evolution from the initial release, introducing a more structured architecture, additional features and different ways to interact with the tool.

Py-Nmap was developed as an educational project and as part of cybersecurity studies.

## 🎯 Project objectives

- Study how TCP connections and Python sockets work.
- Understand port states during network scanning.
- Explore DNS resolution and service identification.
- Apply object-oriented programming concepts.
- Develop a tool with both an interactive terminal and a CLI.
- Practise project organisation, documentation and cybersecurity development.

## ⚙️ Features

| Feature | Description |
|---|---|
| TCP Connect Scan | Performs scans using full TCP connections. |
| Interactive Terminal | Provides an interactive interface for commands and scan configuration. |
| Command-Line Interface | Allows scans to be launched directly from the terminal. |
| IP and Domain Resolution | Accepts IP addresses and domain names. |
| URL Support | Allows URLs to be supplied as targets. |
| CIDR Support | Supports CIDR network notation, limited to 256 hosts per input. |
| Port States | Identifies ports as `open`, `closed` or `filtered`. |
| Service Detection | Performs basic service identification through banners and signatures. |
| DNS Resolution | Performs name resolution and target-related queries. |
| Reverse DNS | Retrieves names associated with IP addresses when available. |
| Multithreading | Uses concurrent processing to speed up scans. |
| Export | Exports results in JSON, CSV and TXT formats. |
| Scan History | Maintains scan history during the session. |
| IPv4 and IPv6 | Supports IPv4 and IPv6 address resolution. |

## 🧰 Technologies

| Technology | Purpose |
|---|---|
| Python 3.8+ | Main programming language. |
| `socket` | Network communication and TCP connections. |
| `concurrent.futures` | Concurrent task execution. |
| `ipaddress` | IP address and CIDR network handling. |
| `argparse` | Command-line argument processing. |
| `ssl` | TLS connection handling. |
| `json` | JSON result export. |
| `csv` | CSV result export. |
| `threading` / concurrency | Scan task organisation. |

The project primarily relies on Python's standard library. On Windows, the optional `pyreadline3` package can improve command-line input handling.

## 🏗️ Architecture

Version 2.0 was reorganised into components and classes with specific responsibilities.

| Class | Responsibility |
|---|---|
| `Color` | Terminal colours and visual elements. |
| `Target` | Target representation and handling. |
| `PortResult` | Stores individual port scan results. |
| `HostResult` | Organises results associated with a host. |
| `Settings` | Manages scan settings. |
| `NetworkScanner` | Executes scans and service identification. |
| `QuietParser` | Handles argument parser output. |
| `TerminalInterface` | Manages the interactive interface. |

## 📥 Installation

### 1. Clone the repository

```bash
git clone https://github.com/Udinocraft/Py-Nmap.git
```

### 2. Enter the project directory

```bash
cd Py-Nmap
```

### 3. Run the tool

```bash
python3 PROJECT/Py-Nmap.py
```

**Requirements:**

- Python 3.8 or later.
- An operating system compatible with Python and sockets.
- Network connectivity for scanning remote targets.

## 🚀 Usage

Py-Nmap provides two main ways to use the tool.

### Interactive terminal

Start the application:

```bash
python3 PROJECT/Py-Nmap.py
```

The interface allows users to configure targets, ports and scan parameters through its own commands.

| Command | Function |
|---|---|
| `help` | Displays available commands. |
| `scan` | Starts a scan. |
| `set` | Changes settings. |
| `show` | Displays information and settings. |
| `target` | Manages the target. |
| `results` | Displays scan results. |
| `export` | Exports results. |
| `history` | Displays session history. |
| `ping` | Checks connectivity. |
| `dns` | Performs DNS-related queries. |
| `service` | Retrieves service information. |
| `config` | Manages configuration. |
| `version` | Displays the tool version. |
| `exit` | Closes the application. |

### Command-Line Interface (CLI)

Scans can also be launched directly from the terminal.

**Example:**

```bash
python3 PROJECT/Py-Nmap.py scanme.nmap.org -p 1-1024 -T 4 -o resultado.json
```

| Parameter | Description |
|---|---|
| `-p`, `--ports` | Specifies the ports to scan. |
| `-F`, `--fast` | Performs a fast scan. |
| `-T`, `--timing` | Sets the timing profile, from 0 to 5. |
| `--timeout` | Sets the connection timeout. |
| `--threads` | Sets the number of threads. |
| `--no-banner` | Disables banner identification. |
| `-v`, `--all` | Displays additional information. |
| `-r`, `--randomize` | Randomises the port order. |
| `-o`, `--output` | Specifies the output file. |
| `--no-color` | Disables terminal colours. |

### 📄 Result export

Results can be exported in three formats:

| Format | Extension | Purpose |
|---|---|---|
| JSON | `.json` | Structured data storage. |
| CSV | `.csv` | Organising results in tables. |
| TXT | `.txt` | Plain-text reports. |

## 📊 Project evolution

Version 2.0 introduced significant changes compared with the initial release.

| Feature | Version 1.0 | Version 2.0 |
|---|---|---|
| Architecture | 3 classes | 8 classes |
| Interface | Interactive terminal | Interactive terminal and CLI |
| Targets | IP and domain | IP, domain, URL and CIDR |
| Port states | Open only | Open, closed and filtered |
| Concurrency | 50 fixed threads | Up to 500 configurable threads |
| Export | Not available | JSON, CSV and TXT |
| Resolution | Basic IPv4 | IPv4 and IPv6, with reverse resolution |
| History | Not available | Session history |
| Autocomplete | Not available | TAB key support |

## ⚠️ Technical limitations

Although inspired by Nmap, Py-Nmap is not intended to replace the original tool.

Some important limitations include:

- Implements TCP Connect Scan, not SYN Scan.
- Service identification relies on signatures and banner analysis rather than a comprehensive detection database.
- CIDR input is limited to 256 hosts.
- The maximum configurable number of threads is 500.
- Service identification depends on the responses provided by hosts.
- TLS probing does not validate the trustworthiness of the certificate presented by the server.

These limitations are part of the current project scope and help define its capabilities.

## 📚 Documentation and reports

The repository also includes technical documentation covering the project's development and evolution.

The reports discuss topics such as:

- Architecture and operation.
- Networking concepts.
- Code structure.
- Libraries and technologies.
- Version comparisons.
- Development challenges.
- Implemented improvements.

## 🤖 Use of artificial intelligence

Artificial intelligence tools were used to support the development and documentation process.

| Tool | Purpose |
|---|---|
| ChatGPT | Support with organisation, review and documentation. |
| Claude | Support with code restructuring and development. |
| Grok | Additional feedback and cross-review. |

These tools were used as supporting resources. Project direction, technical decisions, result analysis and responsibility for development remained under the author's control.

## 🔐 Responsible use

Py-Nmap was developed for educational purposes, authorised testing and network security studies.

Only use the tool against systems you own or environments for which you have explicit permission.

The author is not responsible for any misuse of this tool.

## 👨‍💻 Author

**Udinocraft**

A project developed as part of ongoing studies and experimentation in programming, computer networking and cybersecurity.

- GitHub: https://github.com/Udinocraft
- Project: https://github.com/Udinocraft/Py-Nmap

---

<p align="center">
  <sub>Developed by Udinocraft | Learning, building and exploring cybersecurity.</sub>
</p>
