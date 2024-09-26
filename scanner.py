import concurrent.futures
import datetime
import socket
import subprocess

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from lxml import etree

from typing import Any

origins = [
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:8000",
]

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Function to run a command and capture its output


def run_command(test_name: str, cmd: str, desc: str) -> dict[str, Any]:
    try:
        # Run the command, capture output and error
        result = subprocess.run(
            cmd, shell=True, text=True, capture_output=True)
        return {"test_name": test_name, "output": result.stdout,
                "error": result.stderr, "returncode": result.returncode,
                "desc": desc}
    except Exception as e:
        return {"test_name": test_name, "error": str(e), "returncode": -1}


@app.get("/api")
async def handle_get_request(addr: str) -> list[dict[str, str]]:
    try:
        socket.gethostbyname(addr)
    except socket.error:
        return [{"ERRO": "Endereço não é valido"}]
        # raise ValueError("Endereço não é valido")

    # List of commands with associated test names
    tests = {
        "11211 TCP/UDP - Memcached": ["nmap -p 11211 -sV --script memcached-info -Pn",
                                      "Não há motivo para manter esse serviço acessível na internet. \
                Neste caso, é recomendado restringir o acesso somente a própria maquina."],
        "427 TCP/UDP - SLP": ["nmap -p 427 -Pn",
                              "Serviço muito sujeito a DoS (Denial of Service). É comum o serviço \
                ser oferecido não intencionalmente, podendo ser complemente desabilitado nesses casos. \
                Se não for o caso, ainda pode ser configurado firewall para bloquear \
                tcp/udp na 427, resolvendo o problema."],
        "161 UDP - SNMP": ["sudo nmap -sU -sV --script 'snmp-info,snmp-netstat,snmp-sysdescr' -p 161 -Pn",
                           "O serviço é utilizado em redes locais, domésticas. É comum estar disponível \
                para a internet não intencionalmente. É recomendado configurar o serviço ou firewall \
                para restringir sua disponibilidade à rede local. (Obs.: algumas ver. sofrem de RCE)"],
        "1900 UDP - SSDP": ["sudo nmap -sU -p 1900 --script=upnp-info -Pn",
                            "Serviço muito sujeito a DDoS. Não é boa prática disponibilizá-lo para a internet, \
                a menos que seja um objetivo. É recomendado configurar o servico ou firewall para \
                restrigir o acesso. (Obs.: um ataque usando UPnP - Universal Plug and Play - \
                pode revelar muitas informações sobre o host do serviço.)"],
        "3306 TCP - MySQL": ["nmap -p 3306 -Pn -sV --script=mysql-info -T4",
                             "Não é boa prática de segurança deixar um banco de dados acessível amplamente. \
                É recomendado limitar dentro do possível."],
        "123 UDP - NTP": ["sudo nmap -sU -p 123 --script 'ntp* and not (dos or brute)' -Pn",
                          "Não pode ser desabilitado quando o objetivo for de fato \
                servir a sincronização na rede local. No caso do servidor em questão, precisa \
                ser atualizado. A versão disponível é antiga e vulnerável ao exploit listado."],  # TODO: fix this
        "53 UDP - DNS": ["sudo nmap -p 53 --script dns-recursion -Pn -sV -sU",
                         "Muitas vezes pode ser desabilitado, mas não quando o objetivo for de fato \
                fazer resoluções de nomes de domínio na rede local. De toda forma, não precisa \
                estar disponível para toda a internet, podendo ser configurado ou bloqueado com firewall"],
        "6379 TCP - Redis": ["nmap -sV -p 6379 --script redis-info -Pn",
                             "Tem algumas vulnerabilidades graves nas últimas versões. De toda forma, em geral, \
                não faz sentido que fique esposto para internet. Deve ser retirado de disponibilidade \
                para fora via configuração do Redis mesmo, ou firewall."],
        "445 TCP - SMB": ["nmap -sV -p 445 -Pn",
                          "Não deve estar aberto para internet, funcionando apenas na rede local. \
                As portas não devem estar visíveis para toda a internet, seja a partir de uma \
                configuração do Samba ou do firewall."],
        "137 UDP - NetBIOS": ["sudo nmap -sU -sV -p 137 --script nbstat -Pn",
                              "Não deve estar aberto para internet, funcionando apenas na rede local. \
                Não deve estar aberto para internet, funcionando apenas na rede local. \
                As portas não devem estar visíveis para toda a internet, seja a partir de \
                uma configuração do Samba ou do firewall."],
    }

    # Run the tests in parallel and collect the results
    results = []
    futures = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Submit each test to be executed in parallel
        for test_name, [cmd, desc] in tests.items():
            future = executor.submit(
                run_command, test_name, cmd + ' ' + addr + ' -oX -', desc)
            futures.append(future)

        # Collect the results as they complete
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)

    # NOTE: checkar se as portas estão abertas antes de notificar qualquer coisa
    vulns: list[dict[str, str]] = []
    # Print the final report
    for result in results:
        # print(f"Test Name: {result['test_name']}")
        # print(f"Command: {result['command']}")
        # print(f"Output: {result['output']}")
        # print(f"Error: {result['error']}")
        # print(f"Return Code: {result['returncode']}")
        # print("-" * 40)
        # print(result['output'])
        result['output'] = etree.fromstring(bytes(result['output'], 'utf8'))
        out = result['output']
        is_up = out.find('host').find('status').get('state') == "up"
        if not is_up:
            continue
        report = ""
        port = result['test_name']
        if (port == '11211 TCP/UDP - Memcached' or
            result['test_name'] == '427 TCP/UDP - SLP' or
            result['test_name'] == '161 UDP - SNMP' or
            result['test_name'] == '1900 UDP - SSDP' or
            result['test_name'] == '3306 TCP - MySQL' or
                result['test_name'] == '123 UDP - NTP'):
            report = report + "Em geral, esta porta não precisa estar disponível para a internet, \
                a menos de situações muito específicas. É recomendado desabilitar o serviço ou \
                configurar um bloqueio no firewall. "
        elif test_name == '53 UDP - DNS':
            res = subprocess.run("dig @" + addr + "example.com",
                                 shell=True, text=True, capture_output=True)
            if len(res.stdout) > 1:
                report = report + "Esse servidor DNS está respondendo para a internet. \
                    Grande potencial de DoS!"

        report = report + result['desc'] + ' '

        script = out.find('host').find('ports').find('port').find('script')
        if script != None:
            report = report + f"Importante: o serviço é vulnerável a um script nmap ({script.get('id')}) \
                que pode vazar informações relevantes sobre a máquina. PERIGOSO"

        # if result['test_name'] == '3306 TCP - MySQL' and

        vulns.append({"date": f"{datetime.datetime.now()}",
                      "addr": addr, "port": port, "report": report})

    return vulns
