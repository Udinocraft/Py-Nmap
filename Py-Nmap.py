import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional


class TargetResolver:
    """Classe responsável por resolver nomes de domínio para endereços IP."""

    @staticmethod
    def resolve(target: str) -> str:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as e:
            raise ConnectionError(f"Falha ao resolver o host '{target}': {e}")
        except Exception as e:
            raise RuntimeError(f"Erro inesperado na resolução de DNS: {e}")


class NetworkScanner:
    """Classe principal de POO para o Scanner de Portas."""

    def __init__(self, target: str, ports: List[int], timeout: float = 1.0, max_threads: int = 100):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.max_threads = max_threads
        self.resolved_ip = TargetResolver.resolve(target)

    def _grab_banner(self, s: socket.socket, port: int) -> str:
        """Tenta capturar o banner do serviço rodando na porta aberta."""
        try:
            s.settimeout(0.8)
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()

            if not banner and port in [80, 8080, 443]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(1024).decode('utf-8', errors='ignore').split('\n')[0]

            return banner if banner else "Serviço desconhecido / Sem banner"
        except socket.timeout:
            return "Timeout na captura de banner"
        except Exception:
            return "Não foi possível capturar o banner"

    def _scan_port(self, port: int) -> Optional[Dict]:
        """Varre uma única porta utilizando sockets TCP."""
        start_time = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.resolved_ip, port))

                if result == 0:
                    latency = (time.time() - start_time) * 1000
                    banner = self._grab_banner(s, port)
                    return {
                        "port": port,
                        "status": "ABERTA",
                        "latency": round(latency, 2),
                        "banner": banner
                    }
        except Exception:
            pass
        return None

    def run_scan(self) -> List[Dict]:
        """Executa a varredura concorrente utilizando ThreadPoolExecutor."""
        print("-" * 60)
        print(f"[*] Alvo: {self.target} ({self.resolved_ip})")
        print(f"[*] Portas a verificar: {len(self.ports)} | Threads: {self.max_threads} | Timeout: {self.timeout}s")
        print("-" * 60)
        print("[*] Varredura iniciada...\n")

        open_ports = []
        start_global = time.time()

        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_port = {
                    executor.submit(self._scan_port, port): port
                    for port in self.ports
                }

                for future in as_completed(future_to_port):
                    port_result = future.result()
                    if port_result:
                        open_ports.append(port_result)
                        print(f"[+] Porta {port_result['port']:<5} -> ABERTA | "
                              f"Latência: {port_result['latency']}ms | "
                              f"Banner: {port_result['banner']}")
        except KeyboardInterrupt:
            print("\n[!] Varredura interrompida.")
            return []

        duration = time.time() - start_global
        print("-" * 60)
        print(f"[*] Concluído em {duration:.2f}s. Encontradas {len(open_ports)} porta(s) aberta(s).")
        print("-" * 60)

        return sorted(open_ports, key=lambda x: x["port"])


class TerminalInterface:
    """Gerencia o loop do terminal interativo e o menu de ajuda."""

    def __init__(self):
        self.current_target = "scanme.nmap.org"
        self.current_ports = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 8080]
        self.timeout = 1.0
        self.threads = 50
        self.last_results = []

    def show_help(self):
        print("\n" + "=" * 50)
        print("          PY-NMAP TERMINAL - AJUDA")
        print("=" * 50)
        print("  set target <host>       - Define o alvo (IP ou Domínio)")
        print("  set ports <inicio-fim>  - Define o range (ex: set ports 1-1024)")
        print("                            ou lista (ex: set ports 80,443,22)")
        print("  set timeout <segundos>  - Define o tempo limite de espera do socket")
        print("  set threads <qtd>       - Define o número de threads simultâneas")
        print("  show options            - Exibe as configurações atuais")
        print("  scan                    - Executa a varredura no alvo configurado")
        print("  results                 - Mostra o resultado da última varredura")
        print("  clear                   - Limpa a tela")
        print("  help                    - Mostra este menu de ajuda")
        print("  exit                    - Sai do programa")
        print("=" * 50 + "\n")

    def show_options(self):
        print("\n" + "=" * 40)
        print("      CONFIGURAÇÕES ATUAIS")
        print("=" * 40)
        print(f"  Alvo      : {self.current_target}")
        print(f"  Portas    : {len(self.current_ports)} porta(s) configurada(s)")
        print(f"  Timeout   : {self.timeout}s")
        print(f"  Threads   : {self.threads}")
        print("=" * 40 + "\n")

    def parse_ports(self, port_str: str):
        """Converte string de portas em uma lista de inteiros (suporta ranges e vírgulas)."""
        ports = set()
        try:
            parts = port_str.split(',')
            for part in parts:
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports.update(range(start, end + 1))
                else:
                    ports.add(int(part))

            valid_ports = [p for p in ports if 1 <= p <= 65535]
            if not valid_ports:
                raise ValueError("Nenhuma porta válida informada (1-65535).")
            return sorted(list(valid_ports))
        except Exception as e:
            print(f"[-] Erro ao interpretar portas: {e}")
            return None

    def run(self):
        print("\033[32mBem-vindo ao Py-Nmap Terminal! Digite 'help' para ver os comandos.")

        while True:
            try:
                cmd_line = input("pynmap> ").strip()
                if not cmd_line:
                    continue

                parts = cmd_line.split(" ", 1)
                command = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ""

                if command == "exit":
                    print("Saindo...")
                    break
                elif command == "help":
                    self.show_help()
                elif command == "show" and args.lower() == "options":
                    self.show_options()
                elif command == "clear":
                    print("\033[H\033[J", end="")  # Limpa o terminal ANSI
                elif command == "results":
                    if not self.last_results:
                        print("[-] Nenhuma varredura recente encontrada.")
                    else:
                        print("\n[+] Últimos Resultados Salvos:")
                        for r in self.last_results:
                            print(f"    Porta {r['port']} | Status: {r['status']} | Banner: {r['banner']}")
                        print()
                elif command == "scan":
                    try:
                        scanner = NetworkScanner(
                            target=self.current_target,
                            ports=self.current_ports,
                            timeout=self.timeout,
                            max_threads=self.threads
                        )
                        self.last_results = scanner.run_scan()
                    except Exception as e:
                        print(f"[-] Erro ao executar varredura: {e}")
                elif command == "set":
                    sub_parts = args.split(" ", 1)
                    if len(sub_parts) < 2:
                        print("[-] Uso incorreto. Ex: set target 127.0.0.1")
                        continue

                    sub_cmd, sub_val = sub_parts[0].lower(), sub_parts[1]

                    if sub_cmd == "target":
                        self.current_target = sub_val
                        print(f"[+] Alvo alterado para: {self.current_target}")
                    elif sub_cmd == "ports":
                        parsed = self.parse_ports(sub_val)
                        if parsed:
                            self.current_ports = parsed
                            print(f"[+] Portas configuradas: {len(self.current_ports)} portas selecionadas.")
                    elif sub_cmd == "timeout":
                        try:
                            self.timeout = float(sub_val)
                            print(f"[+] Timeout alterado para: {self.timeout}s")
                        except ValueError:
                            print("[-] O valor do timeout deve ser um número.")
                    elif sub_cmd == "threads":
                        try:
                            self.threads = int(sub_val)
                            print(f"[+] Threads alteradas para: {self.threads}")
                        except ValueError:
                            print("[-] O valor de threads deve ser um número inteiro.")
                    else:
                        print(f"[-] Parâmetro desconhecido: '{sub_cmd}'. Use 'show options'.")
                else:
                    print(f"[-] Comando desconhecido: '{command}'. Digite 'help' para ajuda.")

            except KeyboardInterrupt:
                print("\n[!] Use 'exit' para sair do programa.")
            except Exception as e:
                print(f"[-] Erro inesperado: {e}")


if __name__ == "__main__":
    cli = TerminalInterface()
    cli.run()