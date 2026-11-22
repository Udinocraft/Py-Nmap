#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Py-Nmap Terminal
====================
Scanner de portas TCP (connect scan) com terminal interativo e saída no estilo do nmap.

Use apenas em sistemas que você possui ou tem autorização para testar
(ex.: scanme.nmap.org, sua própria rede/laboratório).

Modo interativo:   python pynmap.py
Modo linha de cmd: python pynmap.py scanme.nmap.org -p 1-1024 -T4 -o resultado.json
Requer Python 3.8+
"""
from __future__ import annotations
import argparse
import csv
import errno
import ipaddress
import json
import os
import random
import re
import shlex
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:  # histórico e autocompletar (Linux/macOS; no Windows: pip install pyreadline3)
    import readline  # type: ignore
except ImportError:  # pragma: no cover
    readline = None

VERSION = "2.0.0"
MAX_CIDR_HOSTS = 256
MAX_THREADS = 500
CONFIG_PATH = Path.home() / ".pynmap.json"


# ══════════════════════════════════════════════════════════════════════════════
#  CORES E MENSAGENS
# ══════════════════════════════════════════════════════════════════════════════
class Color:
    """Cores ANSI com reset automático (evita o terminal 'ficar verde' após o programa)."""

    CODES = {
        "reset": "0", "bold": "1", "dim": "2",
        "red": "31", "green": "32", "yellow": "33", "blue": "34",
        "magenta": "35", "cyan": "36", "white": "37", "gray": "90",
    }
    enabled = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    @classmethod
    def paint(cls, text, *styles: str, color: Optional[bool] = None) -> str:
        use = cls.enabled if color is None else color
        if not use or not styles:
            return str(text)
        seq = ";".join(cls.CODES[s] for s in styles)
        return f"\033[{seq}m{text}\033[0m"


if os.name == "nt":  # ativa sequências ANSI no console do Windows
    os.system("")

c = Color.paint


def info(msg: str) -> None:
    print(f"{c('[*]', 'cyan', 'bold')} {msg}")


def good(msg: str) -> None:
    print(f"{c('[+]', 'green', 'bold')} {msg}")


def bad(msg: str) -> None:
    print(f"{c('[-]', 'red', 'bold')} {msg}")


def warn(msg: str) -> None:
    print(f"{c('[!]', 'yellow', 'bold')} {msg}")


def rule(width: int = 70, char: str = "─") -> None:
    print(c(char * width, "gray"))


# ══════════════════════════════════════════════════════════════════════════════
#  DADOS: SERVIÇOS, PORTAS, TIMING
# ══════════════════════════════════════════════════════════════════════════════
COMMON_SERVICES: Dict[int, str] = {
    7: "echo", 9: "discard", 13: "daytime", 20: "ftp-data", 21: "ftp", 22: "ssh",
    23: "telnet", 25: "smtp", 37: "time", 53: "domain", 67: "dhcps", 68: "dhcpc",
    69: "tftp", 79: "finger", 80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 179: "bgp", 194: "irc", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 514: "syslog", 515: "printer", 587: "submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "ms-sql-s", 1521: "oracle", 1723: "pptp", 1883: "mqtt",
    2049: "nfs", 2181: "zookeeper", 2375: "docker", 3000: "http-alt", 3128: "squid-http",
    3306: "mysql", 3389: "ms-wbt-server", 4444: "krb524", 5000: "upnp", 5060: "sip",
    5432: "postgresql", 5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "kubernetes-api", 8000: "http-alt", 8008: "http", 8080: "http-proxy",
    8081: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "cslistener",
    9090: "websm", 9200: "elasticsearch", 9418: "git", 11211: "memcached",
    27017: "mongodb", 50000: "ibm-db2",
}

TOP_100 = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119,
    135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543,
    544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
    1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128,
    3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631,
    5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]

PORT_PRESETS: Dict[str, List[int]] = {
    "top100": TOP_100,
    "common": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080],
    "web": [80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888],
    "db": [1433, 1521, 3306, 5432, 5984, 6379, 9200, 11211, 27017],
    "all": list(range(1, 65536)),
}

# Templates de tempo estilo nmap: (timeout, threads, nome)
TIMING: Dict[int, Tuple[float, int, str]] = {
    0: (4.0, 5, "paranoid"),
    1: (3.0, 10, "sneaky"),
    2: (2.0, 30, "polite"),
    3: (1.0, 100, "normal"),
    4: (0.7, 200, "aggressive"),
    5: (0.4, 400, "insane"),
}

SCHEME_PORTS = {
    "http": 80, "https": 443, "ftp": 21, "ssh": 22, "smtp": 25, "imap": 143,
    "pop3": 110, "mysql": 3306, "postgres": 5432, "postgresql": 5432,
    "redis": 6379, "mongodb": 27017, "rdp": 3389, "vnc": 5900,
}

TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}
HTTP_PORTS = {80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090}
CLOSED_ERRNOS = {errno.ECONNREFUSED, 10061}  # 10061 = WSAECONNREFUSED (Windows)


def service_name(port: int) -> str:
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


# ══════════════════════════════════════════════════════════════════════════════
#  MODELOS
# ══════════════════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class Target:
    host: str
    port: Optional[int] = None  # porta extra vinda de uma URL (ex.: https://site.com:8443)

    def __str__(self) -> str:
        return f"{self.host}:{self.port}" if self.port else self.host


@dataclass
class PortResult:
    port: int
    state: str  # open | closed | filtered
    service: str
    latency: float  # ms
    banner: str = ""
    version: str = ""


@dataclass
class HostResult:
    target: str
    ip: str
    rdns: str
    started: str
    duration: float
    scanned: int
    ports: List[PortResult] = field(default_factory=list)
    interrupted: bool = False

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class Settings:
    targets: List[Target] = field(default_factory=lambda: [Target("scanme.nmap.org")])
    ports: List[int] = field(default_factory=lambda: list(TOP_100))
    timeout: float = 1.0
    threads: int = 100
    banner: bool = True
    show_all: bool = False
    randomize: bool = False


# ══════════════════════════════════════════════════════════════════════════════
#  PARSING DE ALVOS E PORTAS
# ══════════════════════════════════════════════════════════════════════════════
def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse_target(token: str) -> List[Target]:
    """Aceita IP, domínio, URL (https://site.com:8443/path), host:porta e CIDR (192.168.0.0/30)."""
    token = token.strip()
    if not token:
        return []

    if is_ip(token):
        return [Target(token)]

    if "/" in token and "://" not in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            net = None
        if net is not None:
            hosts = list(net.hosts()) or [net.network_address]
            if len(hosts) > MAX_CIDR_HOSTS:
                raise ValueError(f"Rede muito grande ({len(hosts)} hosts). Máximo: {MAX_CIDR_HOSTS}.")
            return [Target(str(h)) for h in hosts]

    url = token if "://" in token else "//" + token
    try:
        parsed = urlparse(url)
        host, port = parsed.hostname, parsed.port
    except ValueError:
        raise ValueError(f"Alvo inválido: '{token}'")

    if port is None and "://" in token:
        port = SCHEME_PORTS.get(parsed.scheme.lower())
    if not host or not re.fullmatch(r"[\w.\-:]+", host):
        raise ValueError(f"Alvo inválido: '{token}'")
    return [Target(host.lower(), port)]


def parse_targets(raw: str) -> List[Target]:
    targets: List[Target] = []
    for token in re.split(r"[,\s]+", raw.strip()):
        for t in parse_target(token):
            if t not in targets:
                targets.append(t)
    if not targets:
        raise ValueError("Nenhum alvo válido informado.")
    return targets


def parse_ports(spec: str) -> List[int]:
    """Suporta: 80 | 80,443 | 1-1024 | 1-100,443 | -1000 | 8000- | top100 | common | web | db | all."""
    spec = spec.strip().lower()
    if not spec:
        raise ValueError("Nenhuma porta informada.")
    ports = set()
    for part in re.split(r"[,\s]+", spec):
        if not part:
            continue
        if part in PORT_PRESETS:
            ports.update(PORT_PRESETS[part])
            continue
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                start = int(a) if a else 1
                end = int(b) if b else 65535
            else:
                start = end = int(part)
        except ValueError:
            raise ValueError(f"Valor de porta inválido: '{part}'")
        if start > end:
            raise ValueError(f"Intervalo invertido: '{part}'")
        if start < 1 or end > 65535:
            raise ValueError(f"Porta fora do intervalo 1-65535: '{part}'")
        ports.update(range(start, end + 1))
    return sorted(ports)


def describe_ports(ports: List[int], limit: int = 60) -> str:
    """Compacta [1,2,3,80] em '1-3,80'."""
    if not ports:
        return "nenhuma"
    ranges, start, prev = [], ports[0], ports[0]
    for p in ports[1:]:
        if p == prev + 1:
            prev = p
            continue
        ranges.append((start, prev))
        start = prev = p
    ranges.append((start, prev))
    text = ",".join(str(a) if a == b else f"{a}-{b}" for a, b in ranges)
    if len(text) > limit:
        text = text[:limit].rsplit(",", 1)[0] + ",..."
    return f"{len(ports)} porta(s): {text}"


def parse_bool(value: str) -> bool:
    v = value.strip().lower()
    if v in ("on", "true", "1", "yes", "y", "sim", "s"):
        return True
    if v in ("off", "false", "0", "no", "n", "nao", "não"):
        return False
    raise ValueError("Use on/off.")


# ══════════════════════════════════════════════════════════════════════════════
#  DNS
# ══════════════════════════════════════════════════════════════════════════════
def resolve_host(host: str) -> Tuple[str, int]:
    """Retorna (ip, família). Prefere IPv4 quando houver os dois."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ConnectionError(f"Falha ao resolver '{host}': {e}")
    infos.sort(key=lambda i: i[0] != socket.AF_INET)
    family, _, _, _, sockaddr = infos[0]
    return sockaddr[0], family


def reverse_dns(ip: str, timeout: float = 2.0) -> str:
    """DNS reverso com timeout (gethostbyaddr não possui timeout próprio)."""
    result: List[str] = []

    def work() -> None:
        try:
            result.append(socket.gethostbyaddr(ip)[0])
        except Exception:
            pass

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    return result[0] if result else ""


# ══════════════════════════════════════════════════════════════════════════════
#  IDENTIFICAÇÃO DE SERVIÇO / BANNER
# ══════════════════════════════════════════════════════════════════════════════
SIGNATURES: List[Tuple[re.Pattern, Callable[[re.Match], str]]] = [
    (re.compile(r"SSH-(\d+\.\d+)-(\S+)"), lambda m: f"{m.group(2)} (protocolo {m.group(1)})"),
    (re.compile(r"^220[ -].*?\b(ProFTPD|vsFTPd|Pure-FTPd|FileZilla Server|Microsoft FTP Service)[ /]*([\w.\-]*)", re.I | re.S),
     lambda m: f"{m.group(1)} {m.group(2)}".strip()),
    (re.compile(r"^220[ -].*?\b(Postfix|Exim|Sendmail|Microsoft ESMTP)[ /]*([\w.\-]*)", re.I | re.S),
     lambda m: f"{m.group(1)} {m.group(2)}".strip()),
    (re.compile(r"^Server:\s*([^\r\n]+)", re.I | re.M), lambda m: m.group(1).strip()),
    (re.compile(r"^\+OK\s+(.+)", re.M), lambda m: m.group(1).strip()[:50]),
]
MYSQL_RE = re.compile(r"\n(\d+\.\d+\.\d+[\w.\-+~]*)\x00")
HTTP_REQ_TMPL = "HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Py-Nmap/{ver}\r\nConnection: close\r\n\r\n"


def clean_text(text: str, limit: int = 100) -> str:
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def detect_version(text: str, port: int) -> str:
    if port == 3306 or "mysql" in text.lower() or "mariadb" in text.lower():
        m = MYSQL_RE.search(text)
        if m:
            return f"MySQL/MariaDB {m.group(1)}"
    for pattern, fmt in SIGNATURES:
        m = pattern.search(text)
        if m:
            return fmt(m)
    return ""


# ══════════════════════════════════════════════════════════════════════════════
#  SCANNER
# ══════════════════════════════════════════════════════════════════════════════
class NetworkScanner:
    """Scanner TCP connect concorrente com detecção de banner/versão."""

    def __init__(self, target: Target, ports: List[int], timeout: float = 1.0,
                 threads: int = 100, grab_banner: bool = True, randomize: bool = False):
        if timeout <= 0:
            raise ValueError("Timeout deve ser maior que zero.")
        if threads < 1:
            raise ValueError("Threads deve ser pelo menos 1.")

        self.target = target
        self.ports = list(ports)
        if target.port and target.port not in self.ports:
            self.ports.append(target.port)
        self.ports = sorted(set(self.ports))
        if randomize:
            random.shuffle(self.ports)

        self.timeout = timeout
        self.threads = min(threads, MAX_THREADS)
        self.grab_banner = grab_banner
        self.banner_timeout = max(0.5, min(timeout * 1.5, 3.0))
        self.ip, self.family = resolve_host(target.host)
        self._stop = threading.Event()
        self._http_req = HTTP_REQ_TMPL.format(host=target.host, ver=VERSION).encode()

    # ---------- captura de banner ----------
    @staticmethod
    def _recv(sock: socket.socket, size: int = 2048) -> bytes:
        try:
            return sock.recv(size)
        except (socket.timeout, OSError):
            return b""

    def _probe_tls(self, sock: socket.socket) -> Tuple[bytes, str]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        wrapped = None
        try:
            sni = None if is_ip(self.target.host) else self.target.host
            wrapped = ctx.wrap_socket(sock, server_hostname=sni)
            version = wrapped.version() or "TLS"
            wrapped.sendall(self._http_req)
            return self._recv(wrapped), version
        finally:
            if wrapped is not None:
                wrapped.close()

    def _identify(self, sock: socket.socket, port: int) -> Tuple[str, str]:
        raw, tls = b"", ""
        try:
            sock.settimeout(self.banner_timeout)
            if port in TLS_PORTS:
                raw, tls = self._probe_tls(sock)
            else:
                if port not in HTTP_PORTS:
                    raw = self._recv(sock)  # serviços que falam primeiro (SSH, FTP, SMTP...)
                if not raw:  # serviço silencioso: tenta uma requisição HTTP (funciona em portas não padrão)
                    sock.sendall(self._http_req)
                    raw = self._recv(sock)
        except (OSError, ssl.SSLError):
            pass

        text = raw.decode("latin-1", errors="ignore")
        version = detect_version(text, port)
        head = text.strip().splitlines()[0] if text.strip() else ""
        sample = head[:80]
        printable = sum(ch.isprintable() for ch in sample)
        banner = clean_text(head) if sample and printable / len(sample) >= 0.7 else ""
        if tls:
            banner = f"{tls} | {banner}" if banner else tls
        return banner, version

    # ---------- varredura de uma porta ----------
    def _probe(self, port: int) -> Optional[PortResult]:
        if self._stop.is_set():
            return None
        sock = socket.socket(self.family, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        start = time.perf_counter()
        try:
            code = sock.connect_ex((self.ip, port))
            rtt = round((time.perf_counter() - start) * 1000, 2)
            if code == 0:
                banner, version = self._identify(sock, port) if self.grab_banner else ("", "")
                return PortResult(port, "open", service_name(port), rtt, banner, version)
            state = "closed" if code in CLOSED_ERRNOS else "filtered"
            return PortResult(port, state, service_name(port), rtt)
        except OSError:
            return PortResult(port, "filtered", service_name(port), 0.0)
        finally:
            sock.close()

    # ---------- execução ----------
    def run(self, show_progress: bool = True) -> HostResult:
        total = len(self.ports)
        results: List[PortResult] = []
        interrupted = False
        progress = show_progress and total > 200 and sys.stderr.isatty()
        step = max(1, total // 100)
        started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        t0 = time.perf_counter()

        executor = ThreadPoolExecutor(max_workers=max(1, min(self.threads, total)))
        futures = [executor.submit(self._probe, p) for p in self.ports]
        done = 0
        try:
            for fut in as_completed(futures):
                done += 1
                try:
                    res = fut.result()
                except Exception:
                    res = None
                if res is not None:
                    results.append(res)
                    if res.state == "open":
                        if progress:
                            sys.stderr.write("\r\033[K")
                        print(f"{c('[+]', 'green', 'bold')} Porta aberta descoberta: "
                              f"{c(f'{res.port}/tcp', 'green')} ({res.service})")
                if progress and done % step == 0:
                    sys.stderr.write(f"\r{c('[*]', 'cyan')} Progresso: {done}/{total} ({done * 100 // total}%)")
                    sys.stderr.flush()
        except KeyboardInterrupt:
            interrupted = True
            self._stop.set()
            for f in futures:
                f.cancel()
        finally:
            executor.shutdown(wait=True)
            if progress:
                sys.stderr.write("\r\033[K")
                sys.stderr.flush()

        return HostResult(
            target=self.target.host, ip=self.ip, rdns=reverse_dns(self.ip),
            started=started, duration=time.perf_counter() - t0, scanned=len(results),
            ports=sorted(results, key=lambda r: r.port), interrupted=interrupted,
        )


# ══════════════════════════════════════════════════════════════════════════════
#  RELATÓRIOS
# ══════════════════════════════════════════════════════════════════════════════
STATE_STYLE = {"open": ("green", "bold"), "closed": ("red",), "filtered": ("yellow",)}


def format_report(h: HostResult, show_all: bool = False, color: Optional[bool] = None) -> List[str]:
    p = lambda text, *styles: c(text, *styles, color=color)  # noqa: E731
    lines: List[str] = []

    title = h.target if h.target == h.ip else f"{h.target} ({h.ip})"
    lines.append(p(f"Relatório de varredura para {title}", "bold", "cyan"))
    if h.rdns and h.rdns.lower() != h.target.lower():
        lines.append(f"Registro rDNS: {h.rdns}")

    responded = [r for r in h.ports if r.state != "filtered"]
    if responded:
        avg = sum(r.latency for r in responded) / len(responded) / 1000
        lines.append(f"{p('Host está ativo', 'green')} ({avg:.3f}s de latência).")
    elif h.ports:
        lines.append(p("Host aparentemente inativo ou todas as portas estão filtradas.", "yellow"))

    opens = [r for r in h.ports if r.state == "open"]
    closed = [r for r in h.ports if r.state == "closed"]
    filtered = [r for r in h.ports if r.state == "filtered"]

    hidden: List[str] = []
    if show_all or len(closed) + len(filtered) <= 25:
        rows = h.ports
    else:
        rows = opens
        if closed:
            hidden.append(f"{len(closed)} porta(s) tcp fechada(s) (conn-refused)")
        if filtered:
            hidden.append(f"{len(filtered)} porta(s) tcp filtrada(s) (sem resposta)")
    if hidden:
        lines.append(p("Não exibidas: ", "gray") + ", ".join(hidden))

    if rows:
        lines.append("")
        header = f"{'PORTA':<10}{'ESTADO':<11}{'SERVIÇO':<16}{'LATÊNCIA':<11}VERSÃO / BANNER"
        lines.append(p(header, "bold"))
        for r in rows:
            detail = r.version or r.banner
            if r.version and r.banner and r.banner != r.version and not r.banner.startswith(("HTTP", "SSH-")):
                detail = f"{r.version} [{r.banner}]"
            state = p(f"{r.state:<11}", *STATE_STYLE[r.state])
            lat = f"{r.latency:.1f}ms" if r.state != "filtered" else "-"
            lines.append(f"{str(r.port) + '/tcp':<10}{state}{r.service:<16}{lat:<11}{detail}")
    elif not opens:
        lines.append(p("Nenhuma porta aberta encontrada.", "yellow"))

    lines.append("")
    status = f"{len(opens)} aberta(s), {len(closed)} fechada(s), {len(filtered)} filtrada(s)"
    lines.append(p(f"Varridas {h.scanned} porta(s) em {h.duration:.2f}s — {status}.", "gray"))
    if h.interrupted:
        lines.append(p("Varredura interrompida pelo usuário (resultado parcial).", "yellow"))
    return lines


def export_results(path: str, results: List[HostResult]) -> None:
    if not results:
        raise ValueError("Não há resultados para exportar. Execute um 'scan' primeiro.")
    out = Path(path).expanduser()
    ext = out.suffix.lower()
    if ext == ".csv":
        with out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["host", "ip", "porta", "estado", "servico", "latencia_ms", "versao", "banner"])
            for h in results:
                for r in h.ports:
                    w.writerow([h.target, h.ip, r.port, r.state, r.service, r.latency, r.version, r.banner])
    elif ext in (".txt", ".log"):
        with out.open("w", encoding="utf-8") as fh:
            for h in results:
                fh.write("\n".join(format_report(h, show_all=True, color=False)) + "\n\n")
    else:
        with out.open("w", encoding="utf-8") as fh:
            json.dump([asdict(h) for h in results], fh, indent=2, ensure_ascii=False)
    good(f"Resultados salvos em: {out}")


# ══════════════════════════════════════════════════════════════════════════════
#  PARSER DE ARGUMENTOS (usado no 'scan' interativo e na linha de comando)
# ══════════════════════════════════════════════════════════════════════════════
class QuietParser(argparse.ArgumentParser):
    """ArgumentParser que lança ValueError em vez de encerrar o programa."""

    def error(self, message: str):  # type: ignore[override]
        raise ValueError(message)


def build_scan_parser() -> QuietParser:
    p = QuietParser(prog="scan", add_help=False)
    p.add_argument("targets", nargs="*", help="alvos (IP, domínio, URL, CIDR)")
    p.add_argument("-p", "--ports", help="ex.: 1-1024 | 80,443 | top100 | all")
    p.add_argument("-F", "--fast", action="store_true", help="varredura rápida (top100)")
    p.add_argument("-T", "--timing", type=int, choices=range(0, 6), help="template de tempo 0-5")
    p.add_argument("--timeout", type=float, help="timeout do socket (s)")
    p.add_argument("--threads", type=int, help="número de threads")
    p.add_argument("--no-banner", action="store_true", help="não captura banners")
    p.add_argument("-v", "--all", action="store_true", help="lista portas fechadas/filtradas também")
    p.add_argument("-r", "--randomize", action="store_true", help="ordem aleatória de portas")
    p.add_argument("-o", "--output", help="salva resultado (.json, .csv, .txt)")
    p.add_argument("--no-color", action="store_true", help="desativa cores")
    return p


def perform_scan(args: argparse.Namespace, settings: Settings) -> List[HostResult]:
    # --- monta a configuração efetiva (sem alterar as configurações salvas) ---
    ports = parse_ports(args.ports) if args.ports else (list(TOP_100) if args.fast else list(settings.ports))
    timeout, threads = settings.timeout, settings.threads
    if args.timing is not None:
        timeout, threads, _ = TIMING[args.timing]
    if args.timeout is not None:
        timeout = args.timeout
    if args.threads is not None:
        threads = args.threads
    if timeout <= 0 or timeout > 60:
        raise ValueError("Timeout deve estar entre 0 e 60 segundos.")
    if threads < 1:
        raise ValueError("Threads deve ser pelo menos 1.")
    threads = min(threads, MAX_THREADS)

    targets = parse_targets(" ".join(args.targets)) if args.targets else list(settings.targets)
    grab = settings.banner and not args.no_banner
    randomize = settings.randomize or args.randomize
    show_all = settings.show_all or args.all

    print()
    print(c(f"Iniciando Py-Nmap {VERSION} (TCP connect scan) em "
            f"{datetime.now():%Y-%m-%d %H:%M:%S}", "bold"))
    info(f"Alvos: {len(targets)} | Portas: {len(ports)} | Threads: {min(threads, MAX_THREADS)} | Timeout: {timeout}s")
    rule()

    results: List[HostResult] = []
    t_global = time.perf_counter()
    for target in targets:
        try:
            scanner = NetworkScanner(target, ports, timeout, threads, grab, randomize)
        except ConnectionError as e:
            bad(str(e))
            continue
        info(f"Varrendo {c(str(target.host), 'bold')} ({scanner.ip}) — {len(scanner.ports)} porta(s)...")
        host = scanner.run()
        results.append(host)
        print()
        for line in format_report(host, show_all):
            print(line)
        rule()
        if host.interrupted:
            break

    total_open = sum(len(h.open_ports) for h in results)
    info(f"{len(results)} host(s) varrido(s) em {time.perf_counter() - t_global:.2f}s | "
         f"{c(str(total_open), 'green', 'bold')} porta(s) aberta(s) no total.")

    if args.output and results:
        export_results(args.output, results)
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  INTERFACE INTERATIVA
# ══════════════════════════════════════════════════════════════════════════════
class TerminalInterface:
    COMMANDS = ["help", "scan", "set", "show", "target", "results", "export", "history",
                "ping", "dns", "service", "config", "clear", "version", "exit"]
    SET_KEYS = ["target", "ports", "timeout", "threads", "timing", "banner", "showall",
                "randomize", "color"]

    def __init__(self) -> None:
        self.settings = Settings()
        self.last_results: List[HostResult] = []
        self.history: List[Dict] = []
        self.handlers: Dict[str, Callable[[str], Optional[bool]]] = {
            "help": self.cmd_help, "scan": self.cmd_scan, "set": self.cmd_set,
            "show": self.cmd_show, "target": self.cmd_target, "results": self.cmd_results,
            "export": self.cmd_export, "history": self.cmd_history, "ping": self.cmd_ping,
            "dns": self.cmd_dns, "service": self.cmd_service, "config": self.cmd_config,
            "clear": self.cmd_clear, "version": self.cmd_version, "exit": self.cmd_exit,
        }
        self.aliases = {"quit": "exit", "q": "exit", "?": "help", "targets": "target",
                        "options": "show", "cls": "clear", "lookup": "service", "resolve": "dns"}

    # ---------- infraestrutura ----------
    def _setup_readline(self) -> None:
        if readline is None:
            return

        def completer(text: str, state: int):
            buf = readline.get_line_buffer().lstrip()
            words = buf.split(" ")
            if len(words) <= 1:
                options = [x for x in self.COMMANDS if x.startswith(text)]
            elif words[0] == "set" and len(words) == 2:
                options = [x for x in self.SET_KEYS if x.startswith(text)]
            elif words[0] == "show" and len(words) == 2:
                options = [x for x in ("options", "targets", "history") if x.startswith(text)]
            elif words[0] == "target" and len(words) == 2:
                options = [x for x in ("add", "remove", "list", "clear") if x.startswith(text)]
            else:
                options = []
            return options[state] if state < len(options) else None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")

    def prompt(self) -> str:
        if not Color.enabled:
            return "pynmap> "
        name, rest = c("pynmap", "red", "bold"), c("> ", "white")
        if readline is not None:  # \001 \002 evitam bugs de largura com readline
            return f"\001\033[1;31m\002pynmap\001\033[0m\002\001\033[37m\002> \001\033[0m\002"
        return name + rest

    def banner(self) -> None:
        art = r"""
   ___        _  _                       
  / _ \_   _ / \| |_ __ ___   __ _ _ __  
 / /_)/ | | / _ \ | '_ ` _ \ / _` | '_ \ 
/ ___/| |_| \_/\ \ | | | | | | (_| | |_) |
\/     \__, \___/_|_| |_| |_|\__,_| .__/ 
       |___/                      |_|    """
        print(c(art, "red", "bold"))
        print(c(f"  Terminal Scanner v{VERSION}  •  digite 'help' para ver os comandos", "gray"))
        print(c("  Use apenas em alvos que você possui ou tem autorização para testar.\n", "yellow"))

    def run(self) -> None:
        self.banner()
        self._setup_readline()
        while True:
            try:
                line = input(self.prompt()).strip()
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                print()
                warn("Use 'exit' para sair do programa.")
                continue
            if not line:
                continue
            try:
                if self.dispatch(line) is False:
                    break
            except (ValueError, ConnectionError) as e:
                bad(str(e))
            except KeyboardInterrupt:
                print()
                warn("Operação interrompida.")
            except Exception as e:  # noqa: BLE001
                bad(f"Erro inesperado: {e!r}")

    def dispatch(self, line: str) -> Optional[bool]:
        parts = line.split(None, 1)
        command = parts[0].lower()
        args = parts[1].strip() if len(parts) > 1 else ""
        command = self.aliases.get(command, command)
        handler = self.handlers.get(command)
        if handler is None:
            bad(f"Comando desconhecido: '{parts[0]}'. Digite 'help' para ajuda.")
            return True
        return handler(args)

    # ---------- comandos ----------
    def cmd_help(self, args: str) -> None:
        def row(cmd: str, desc: str) -> None:
            print(f"  {c(cmd.ljust(34), 'green')} {desc}")

        print()
        print(c(f" PY-NMAP TERMINAL v{VERSION} — AJUDA", "bold", "cyan"))
        rule(78, "═")
        print(c(" Varredura", "bold", "yellow"))
        row("scan", "Varre os alvos/portas configurados")
        row("scan <alvo> [opções]", "Varredura pontual (não altera as configurações)")
        row("   -p <portas>", "ex.: -p 1-1024 | -p 80,443 | -p top100 | -p all")
        row("   -F", "Rápida (top100)        -T <0-5>  Template de tempo")
        row("   --timeout <s> --threads <n>", "Ajuste fino de timeout e threads")
        row("   --no-banner  -v  -r  -o <arq>", "Sem banner | mostra todas | aleatório | exporta")
        row("ping <alvo> [porta]", "TCP ping (padrão porta 80) com estatísticas")
        print(c("\n Alvos (aceita IP, domínio, URL, host:porta e CIDR)", "bold", "yellow"))
        row("target add <url|ip|cidr> ...", "Adiciona alvos (ex.: https://site.com:8443/x)")
        row("target list|remove <n|host>|clear", "Lista, remove ou limpa alvos")
        row("set target <alvo>[,alvo...]", "Substitui a lista de alvos")
        print(c("\n Configurações", "bold", "yellow"))
        row("set ports <spec>", "1-1024 | 22,80,443 | top100 | common | web | db | all")
        row("set timeout <segundos>", "Tempo limite do socket")
        row("set threads <qtd>", f"Threads simultâneas (máx. {MAX_THREADS})")
        row("set timing <0-5>", "Template estilo nmap (T0 paranoid … T5 insane)")
        row("set banner on|off", "Captura de banner/versão")
        row("set showall on|off", "Exibe portas fechadas/filtradas")
        row("set randomize on|off", "Ordem aleatória das portas")
        row("set color on|off", "Liga/desliga cores")
        row("show options|targets|history", "Exibe configurações, alvos ou histórico")
        row("config save|load [arquivo]", f"Salva/carrega configuração (padrão: {CONFIG_PATH.name})")
        print(c("\n Resultados e utilidades", "bold", "yellow"))
        row("results [all]", "Mostra o resultado da última varredura")
        row("export <arquivo>", "Exporta (.json, .csv ou .txt)")
        row("history", "Histórico de varreduras da sessão")
        row("dns <host>", "Resolve nome → IP e DNS reverso")
        row("service <porta|nome>", "Consulta porta ↔ serviço (ex.: service 443)")
        row("clear | version | help | exit", "Utilidades")
        rule(78, "═")
        print()

    def cmd_scan(self, args: str) -> None:
        tokens = shlex.split(args, posix=(os.name != "nt"))
        ns = build_scan_parser().parse_args(tokens)
        if ns.no_color:
            Color.enabled = False
        results = perform_scan(ns, self.settings)
        if results:
            self.last_results = results
            for h in results:
                self.history.append({
                    "hora": h.started, "alvo": h.target, "ip": h.ip,
                    "portas": h.scanned, "abertas": len(h.open_ports),
                    "duracao": round(h.duration, 2),
                })

    def cmd_set(self, args: str) -> None:
        sub = args.split(None, 1)
        if len(sub) < 2:
            raise ValueError("Uso: set <target|ports|timeout|threads|timing|banner|showall|randomize|color> <valor>")
        key, value = sub[0].lower(), sub[1].strip()
        s = self.settings

        if key in ("target", "targets"):
            s.targets = parse_targets(value)
            good(f"Alvo(s): {', '.join(str(t) for t in s.targets)}")
        elif key == "ports":
            s.ports = parse_ports(value)
            good(f"Portas: {describe_ports(s.ports)}")
        elif key == "timeout":
            try:
                v = float(value)
            except ValueError:
                raise ValueError("O timeout deve ser um número (ex.: 1.5).")
            if not 0 < v <= 60:
                raise ValueError("Timeout deve estar entre 0 e 60 segundos.")
            s.timeout = v
            good(f"Timeout: {v}s")
        elif key == "threads":
            try:
                v = int(value)
            except ValueError:
                raise ValueError("Threads deve ser um número inteiro.")
            if v < 1:
                raise ValueError("Threads deve ser pelo menos 1.")
            if v > MAX_THREADS:
                warn(f"Limitado a {MAX_THREADS} threads (evita estourar o limite de descritores do SO).")
                v = MAX_THREADS
            s.threads = v
            good(f"Threads: {v}")
        elif key == "timing":
            try:
                n = int(value.lower().lstrip("t"))
                s.timeout, s.threads, name = TIMING[n]
            except (ValueError, KeyError):
                raise ValueError("Timing deve ser de 0 a 5 (ex.: set timing 4).")
            good(f"Timing T{n} ({name}): timeout={s.timeout}s, threads={s.threads}")
        elif key == "banner":
            s.banner = parse_bool(value)
            good(f"Captura de banner: {'ligada' if s.banner else 'desligada'}")
        elif key in ("showall", "closed"):
            s.show_all = parse_bool(value)
            good(f"Exibir todas as portas: {'sim' if s.show_all else 'não'}")
        elif key == "randomize":
            s.randomize = parse_bool(value)
            good(f"Ordem aleatória: {'sim' if s.randomize else 'não'}")
        elif key == "color":
            Color.enabled = parse_bool(value)
            good(f"Cores: {'ligadas' if Color.enabled else 'desligadas'}")
        else:
            raise ValueError(f"Parâmetro desconhecido: '{key}'. Use 'help'.")

    def cmd_show(self, args: str) -> None:
        what = args.lower() or "options"
        s = self.settings
        if what == "options":
            print()
            print(c(" CONFIGURAÇÕES ATUAIS", "bold", "cyan"))
            rule(60)
            rows = [
                ("Alvos", ", ".join(str(t) for t in s.targets)),
                ("Portas", describe_ports(s.ports)),
                ("Timeout", f"{s.timeout}s"),
                ("Threads", str(s.threads)),
                ("Banner", "ligado" if s.banner else "desligado"),
                ("Mostrar todas", "sim" if s.show_all else "não"),
                ("Aleatório", "sim" if s.randomize else "não"),
                ("Cores", "ligadas" if Color.enabled else "desligadas"),
            ]
            for k, v in rows:
                print(f"  {c(k.ljust(14), 'yellow')}: {v}")
            rule(60)
            print()
        elif what == "targets":
            self.cmd_target("list")
        elif what == "history":
            self.cmd_history("")
        else:
            raise ValueError("Uso: show options | targets | history")

    def cmd_target(self, args: str) -> None:
        parts = args.split(None, 1)
        action = parts[0].lower() if parts else "list"
        value = parts[1].strip() if len(parts) > 1 else ""
        s = self.settings

        if action == "list":
            if not s.targets:
                warn("Nenhum alvo configurado. Use 'target add <alvo>'.")
                return
            print()
            for i, t in enumerate(s.targets, 1):
                extra = c(f"  (porta extra: {t.port})", "gray") if t.port else ""
                print(f"  {c(str(i).rjust(2), 'cyan')}. {t.host}{extra}")
            print()
        elif action in ("add", "+"):
            if not value:
                raise ValueError("Uso: target add <url|ip|domínio|cidr> [...]")
            added = 0
            for t in parse_targets(value):
                if t not in s.targets:
                    s.targets.append(t)
                    added += 1
            good(f"{added} alvo(s) adicionado(s). Total: {len(s.targets)}")
        elif action in ("remove", "rm", "del"):
            if not value:
                raise ValueError("Uso: target remove <número|host>")
            if value.isdigit() and 1 <= int(value) <= len(s.targets):
                removed = s.targets.pop(int(value) - 1)
            else:
                matches = [t for t in s.targets if t.host == value.lower() or str(t) == value.lower()]
                if not matches:
                    raise ValueError(f"Alvo não encontrado: '{value}'")
                removed = matches[0]
                s.targets.remove(removed)
            good(f"Removido: {removed}")
        elif action == "clear":
            s.targets.clear()
            good("Lista de alvos limpa.")
        else:
            raise ValueError("Uso: target add|remove|list|clear")

    def cmd_results(self, args: str) -> None:
        if not self.last_results:
            warn("Nenhuma varredura recente encontrada.")
            return
        show_all = args.lower() in ("all", "-v") or self.settings.show_all
        for h in self.last_results:
            print()
            for line in format_report(h, show_all):
                print(line)
        print()

    def cmd_export(self, args: str) -> None:
        if not args:
            raise ValueError("Uso: export <arquivo.json|.csv|.txt>")
        export_results(args.strip("\"'"), self.last_results)

    def cmd_history(self, args: str) -> None:
        if not self.history:
            warn("Nenhuma varredura nesta sessão.")
            return
        print()
        print(c(f"{'#':<4}{'HORA':<21}{'ALVO':<28}{'PORTAS':<8}{'ABERTAS':<9}DURAÇÃO", "bold"))
        for i, h in enumerate(self.history, 1):
            print(f"{i:<4}{h['hora']:<21}{h['alvo'][:26]:<28}{h['portas']:<8}"
                  f"{c(str(h['abertas']).ljust(9), 'green')}{h['duracao']}s")
        print()

    def cmd_ping(self, args: str) -> None:
        parts = args.split()
        if not parts:
            raise ValueError("Uso: ping <alvo> [porta]")
        target = parse_target(parts[0])[0]
        port = int(parts[1]) if len(parts) > 1 else (target.port or 80)
        if not 1 <= port <= 65535:
            raise ValueError("Porta fora do intervalo 1-65535.")
        ip, family = resolve_host(target.host)
        info(f"TCP ping em {target.host} ({ip}) porta {port}")
        rtts: List[float] = []
        for seq in range(1, 5):
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            t0 = time.perf_counter()
            try:
                code = sock.connect_ex((ip, port))
                ms = (time.perf_counter() - t0) * 1000
                if code == 0:
                    rtts.append(ms)
                    print(f"  seq={seq} {c('aberta', 'green')}  tempo={ms:.1f}ms")
                elif code in CLOSED_ERRNOS:
                    rtts.append(ms)
                    print(f"  seq={seq} {c('fechada (host ativo)', 'red')}  tempo={ms:.1f}ms")
                else:
                    print(f"  seq={seq} {c('sem resposta', 'yellow')}")
            except OSError as e:
                print(f"  seq={seq} {c('erro', 'yellow')}: {e}")
            finally:
                sock.close()
            time.sleep(0.4)
        if rtts:
            good(f"min/méd/máx = {min(rtts):.1f}/{sum(rtts) / len(rtts):.1f}/{max(rtts):.1f} ms")
        else:
            warn("Nenhuma resposta recebida.")

    def cmd_dns(self, args: str) -> None:
        if not args:
            raise ValueError("Uso: dns <host>")
        target = parse_target(args.split()[0])[0]
        try:
            infos = socket.getaddrinfo(target.host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise ConnectionError(f"Falha ao resolver '{target.host}': {e}")
        seen = []
        for fam, *_rest, sockaddr in infos:
            ip = sockaddr[0]
            if ip not in seen:
                seen.append(ip)
                kind = "IPv6" if fam == socket.AF_INET6 else "IPv4"
                rdns = reverse_dns(ip)
                print(f"  {c(kind, 'cyan')}  {ip:<40} {c(rdns or '(sem rDNS)', 'gray')}")

    def cmd_service(self, args: str) -> None:
        if not args:
            raise ValueError("Uso: service <porta|nome>")
        q = args.strip().lower()
        if q.isdigit():
            port = int(q)
            if not 1 <= port <= 65535:
                raise ValueError("Porta fora do intervalo 1-65535.")
            print(f"  {port}/tcp → {c(service_name(port), 'green')}")
            return
        matches = sorted(p for p, n in COMMON_SERVICES.items() if q in n)
        if not matches:
            try:
                matches = [socket.getservbyname(q, "tcp")]
            except OSError:
                warn(f"Nenhum serviço encontrado para '{q}'.")
                return
        for p in matches:
            print(f"  {q if q in COMMON_SERVICES.get(p, '') else service_name(p)} → {c(f'{p}/tcp', 'green')}")

    def cmd_config(self, args: str) -> None:
        parts = args.split(None, 1)
        if not parts or parts[0] not in ("save", "load"):
            raise ValueError("Uso: config save|load [arquivo]")
        path = Path(parts[1].strip("\"'")).expanduser() if len(parts) > 1 else CONFIG_PATH
        s = self.settings
        if parts[0] == "save":
            data = {
                "targets": [str(t) for t in s.targets], "ports": s.ports, "timeout": s.timeout,
                "threads": s.threads, "banner": s.banner, "show_all": s.show_all,
                "randomize": s.randomize,
            }
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            good(f"Configuração salva em {path}")
        else:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as e:
                raise ValueError(f"Não foi possível carregar '{path}': {e}")
            s.targets = parse_targets(" ".join(data.get("targets", []))) if data.get("targets") else s.targets
            s.ports = [p for p in data.get("ports", s.ports) if isinstance(p, int) and 1 <= p <= 65535] or s.ports
            s.timeout = float(data.get("timeout", s.timeout))
            s.threads = min(int(data.get("threads", s.threads)), MAX_THREADS)
            s.banner = bool(data.get("banner", s.banner))
            s.show_all = bool(data.get("show_all", s.show_all))
            s.randomize = bool(data.get("randomize", s.randomize))
            good(f"Configuração carregada de {path}")

    def cmd_clear(self, args: str) -> None:
        print("\033[H\033[J", end="")

    def cmd_version(self, args: str) -> None:
        info(f"Py-Nmap Terminal v{VERSION} | Python {sys.version.split()[0]}")

    def cmd_exit(self, args: str) -> bool:
        print(c("Saindo... até a próxima!", "gray"))
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRADA
# ══════════════════════════════════════════════════════════════════════════════
def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        TerminalInterface().run()
        return 0

    if argv[0] in ("-h", "--help", "help"):
        TerminalInterface().cmd_help("")
        return 0
    if argv[0] in ("-V", "--version"):
        print(f"Py-Nmap Terminal v{VERSION}")
        return 0

    try:
        ns = build_scan_parser().parse_args(argv)
        if ns.no_color:
            Color.enabled = False
        if not ns.targets:
            raise ValueError("Informe ao menos um alvo. Ex.: pynmap.py scanme.nmap.org -p 1-1024")
        results = perform_scan(ns, Settings())
        return 130 if any(h.interrupted for h in results) else (0 if results else 1)
    except (ValueError, ConnectionError) as e:
        bad(str(e))
        return 1
    except KeyboardInterrupt:
        print()
        warn("Interrompido.")
        return 130


if __name__ == "__main__":
    sys.exit(main())