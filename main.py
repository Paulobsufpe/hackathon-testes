from fastapi import FastAPI
import socket

import subprocess
import concurrent.futures

from lxml import etree

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

app = FastAPI()

@app.get("/api")
async def handle_get_request(addr: str):
    try:
        socket.gethostbyname(addr)
    except socket.error:
        return {"ERRO": "Endereço não é valido"}

    # List of commands with associated test names
    tests = {
        "11211 TCP/UDP - Memcached" : [ "nmap -p 11211 -sV --script memcached-info 200.130.38.131 -Pn -oX -",
                "Não deve nunca estar aberta, simples assim. Pode resultar até em RCE (remote code execution)."],
        "427 TCP/UDP - SLP": [ "nmap 200.130.38.131 -p 427 -Pn -oX -", 
                "DoS. Em geral, é comum o serviço sem oferecido não intencionalmente - \
                podendo ser complemente desabilitado nesses casos. Se não for o caso, \
                ainda pode ser configurado firewall para bloquear tcp/udp na 427, resolvendo o problema."],
        "161 UDP - SNMP": [ "sudo nmap -sU -sV --script 'snmp-info,snmp-netstat,snmp-sysdescr' 200.130.38.131 -p 161 -Pn -oX -",
                "Não deve estar aberta..."],
        "1900 UDP - SSDP": [ "sudo nmap -sU -p 1900 --script=upnp-info 200.130.38.131 -Pn -oX -",
                "Não deve estar aberta..."],
        "3306 TCP - MySQL": [ "nmap -p 3306 200.130.38.131 -Pn -oX -",
                "Não deve estar aberta!..."],
        "123 UDP - NTP": [ "sudo nmap -sU -p 123 --script 'ntp* and not (dos or brute)' 200.130.38.131 -Pn -oX -",
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
            future = executor.submit(run_command, test_name, cmd, desc)
            futures.append(future)
        
        # Collect the results as they complete
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
    
    # Print the final report
    for result in results:
        # print(f"Test Name: {result['test_name']}")
        # print(f"Command: {result['command']}")
        # print(f"Output: {result['output']}")
        # print(f"Error: {result['error']}")
        # print(f"Return Code: {result['returncode']}")
        # print("-" * 40)
        print(result['output'])
        result['output'] = etree.fromstring(bytes(result['output'], 'utf8'))
        out = result['output']
        if out.find('host').find('status').get('state') == "up" and \
            (result['test_name'] == '11211 TCP/UDP - Memcached' or
             result['test_name'] == '427 TCP/UDP - SLP' or
             result['test_name'] == '161 UDP - SNMP' or
             result['test_name'] == '1900 UDP - SSDP' or
             result['test_name'] == '3306 TCP - MySQL' or
             result['test_name'] == '123 UDP - NTP'):
        
            print(f"{result['test_name'].split(' ')[1]} => {result['desc']}")
        
    
    return {addr: "Parameters received successfully!"}

