from fastapi import FastAPI
import socket

import subprocess
import concurrent.futures

from lxml import etree

# Function to run a command and capture its output
def run_command(test_name, cmd):
    try:
        # Run the command, capture output and error
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
        return {"test_name": test_name, "command": cmd, "output": result.stdout,
                "error": result.stderr, "returncode": result.returncode}
    except Exception as e:
        return {"test_name": test_name, "command": cmd, "error": str(e), "returncode": -1}

app = FastAPI()

@app.get("/api")
async def handle_get_request(addr: str):
    try:
        socket.gethostbyname(addr)
    except socket.error:
        return {"ERRO": "Endereço não é valido"}

    # List of commands with associated test names
    tests = {
        "11211 TCP/UDP - Memcached" : "",
        "427 TCP/UDP - SLP": "nmap 200.130.38.131 -p 427 -Pn -oX -",
        "161 UDP - SNMP": "",
        "1900 UDP - SSDP": "",
        "3306 TCP - MySQL": "",
        "123 UDP - NTP": "",
    }
    
    # Run the tests in parallel and collect the results
    results = []
    futures = []
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Submit each test to be executed in parallel
        for test_name, cmd in tests.items():
            future = executor.submit(run_command, test_name, cmd)
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
        result['output'] = etree.fromstring(bytes(result['output'], 'utf8'))
        out = result['output']
        if out.find('host').find('status').get('state') == "up" and 
            (result['test_name'] == '11211 TCP/UDP - Memcached' or
             result['test_name'] == '427 TCP/UDP - SLP' or
             result['test_name'] == '161 UDP - SNMP' or
             result['test_name'] == '1900 UDP - SSDP' or
             result['test_name'] == '3306 TCP - MySQL' or
             result['test_name'] == '123 UDP - NTP'):

            print('nice!')
        
    
    return {addr: "Parameters received successfully!"}

