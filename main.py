from fastapi import FastAPI
import socket

import subprocess
import concurrent.futures
import datetime

from lxml import etree

from fastapi.middleware.cors import CORSMiddleware

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
def run_command(test_name, cmd, desc):
    try:
        # Run the command, capture output and error
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
        return {"test_name": test_name, "output": result.stdout,
                "error": result.stderr, "returncode": result.returncode,
                "desc": desc}
    except Exception as e:
        return {"test_name": test_name, "error": str(e), "returncode": -1}

@app.get("/api")
async def handle_get_request(addr: str):
    try:
        socket.gethostbyname(addr)
    except socket.error:
        return {"ERRO": "Endereço não é valido"}

    # List of commands with associated test names
    tests = {
        "11211 TCP/UDP - Memcached" : [ "nmap -p 11211 -sV --script memcached-info -Pn",
                "Não há motivo para manter esse serviço acessível na internet. \
                É recomendado restringir o acesso somente a própria maquina."],
        "427 TCP/UDP - SLP": [ "nmap -p 427 -Pn", 
                "Serviço muito sujeito a DoS (Denial of Service). É comum o serviço \
                ser oferecido não intencionalmente, podendo ser complemente desabilitado nesses casos. \
                Se não for o caso, ainda pode ser configurado firewall para bloquear \
                tcp/udp na 427, resolvendo o problema."],
        "161 UDP - SNMP": [ "sudo nmap -sU -sV --script 'snmp-info,snmp-netstat,snmp-sysdescr' -p 161 -Pn",
                "O serviço é utilizado em redes locais, domésticas. É comum estar disponível \
                para a internet não intencionalmente. É recomendado configurar o serviço ou firewall \
                para restringir sua disponibilidade à rede local. (Obs.: algumas ver. sofrem de RCE)"],
        "1900 UDP - SSDP": [ "sudo nmap -sU -p 1900 --script=upnp-info -Pn",
                "Serviço muito sujeito a DDoS. Não é boa prática disponibilizá-lo para a internet, \
                a menos que seja um objetivo. É recomendado configurar o servico ou firewall para \
                restrigir o acesso. (Obs.: um ataque usando UPnP - Universal Plug and Play - \
                pode revelar muitas informações sobre o host do serviço."],
        "3306 TCP - MySQL": [ "nmap -p 3306 -Pn -sV --script=mysql-info -T4",
                "Não é boa prática de segurança deixar um banco de dados acessível amplamente. \
                É recomendado limitar dentro do possível."],
        "123 UDP - NTP": [ "sudo nmap -sU -p 123 --script 'ntp* and not (dos or brute)' -Pn",
                "Muitas vezes pode ser desabilitado, mas não quando o objetivo for de fato \
                servir a sincronização na rede local. No caso do servidor em questão, precisa \
                ser atualizado. A versão disponível é antiga e vulnerável ao exploit listado."],
    }
    
    # Run the tests in parallel and collect the results
    results = []
    futures = []
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Submit each test to be executed in parallel
        for test_name, [cmd, desc] in tests.items():
            future = executor.submit(run_command, test_name, cmd + ' ' + addr + ' -oX -', desc)
            futures.append(future)
        
        # Collect the results as they complete
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
    
    vulns=[]
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
        if not is_up: continue
        if (result['test_name'] == '11211 TCP/UDP - Memcached' or
              result['test_name'] == '427 TCP/UDP - SLP' or
              result['test_name'] == '161 UDP - SNMP' or
              result['test_name'] == '1900 UDP - SSDP' or
              result['test_name'] == '3306 TCP - MySQL' or
              result['test_name'] == '123 UDP - NTP'):
            pass

        script = out.find('host').find('ports').find('port').find('script')
        if script != None:
            print(etree.tostring(script))
        
        port = result['test_name']
        report = "Em geral, esta porta não precisa estar disponível para a internet, \
            a menos de situações muito específicas. É recomendado desabilitar o serviço ou \
            configurar um bloqueio no firewall. " + result['desc']

        vulns.append({"date": f"{datetime.datetime.now()}", 
                      "addr": addr, "port": port, "report": report})

    return vulns

