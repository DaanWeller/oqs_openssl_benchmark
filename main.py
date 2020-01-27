import os
import time
import argparse
from configparser import ConfigParser
import subprocess


wd = ''
resultsdir = ''
openssl = ''

kems = []
sigs = []

export_options = ''

def main():
    initialize()

    for sig in sigs:
        create_certificate_authority(sig)
        create_server_keypair_CArequest(sig)
        create_signed_certificate(sig)
        for kem in kems:
            benchmark_key_exchange(sig, kem)

def initialize():
    wd = os.getcwd()
    resultsdir = f'{wd}/results'

    parse_arguments()

def parse_arguments():
    parser = argparse.ArgumentParser(description="This script is used to benchmark the new Post-Quantum cryptography algorithms implemented by the Open Quantum Safe project using hyperfine.")
    parser.add_argument('config_path', help='path to config file')
    args = parser.parse_args()

    parse_config(args.config_path)

def parse_config(config_path):
    config = ConfigParser(delimiters=('='))
    config.read(config_path)
    
    global resultsdir, openssl, server_ip, server_port, kems, sigs

    resultsdir  = config.get('main', 'results_dir')
    openssl     = config.get('main', 'openssl_app')
    server_ip   = config.get('main', 'server_ip')
    server_port = config.get('main', 'server_port')
    kems        = [kem.strip() for kem in config.get('main', 'kems').splitlines()]
    sigs        = [sig.strip() for sig in config.get('main', 'signatures').splitlines()]
    #export_options = [e.strip() for e in config.get('main', 'export_options').splitlines()]

def run_hyperfine(command, options):   
    hyperfine_command = f'hyperfine {options} \'{command}\''
    print('running hyperfine')
    subprocess.run(hyperfine_command, shell=True, check=True)
    print('hyperfine run completed')

def run_heaptrack(command, options):
    heaptrack_command = f'heaptrack {options} {command}'
    subprocess.run(heaptrack_command, shell=True, check=True)

def create_certificate_authority(signature_algorithm):
    global resultsdir, openssl
    s = signature_algorithm # make the command more readable?
    output_folder = f'{resultsdir}/{s}'
    os.makedirs(output_folder, exist_ok=True)
    command = (f'{openssl} ' 
               f'req -x509 -new -newkey {s} ' 
               f'-keyout {output_folder}/{s}_CA.key ' 
               f'-out {output_folder}/{s}_CA.crt ' 
               f'-nodes -subj "/CN={s}_test CA" -days 365 ' 
               f'-config {openssl}.cnf')
    options = f'--export-json {output_folder}/{s}_create_CA.json'

    run_hyperfine(command, options)

def create_server_keypair_CArequest(signature_algorithm):
    global resultsdir, openssl
    s = signature_algorithm 
    output_folder = f'{resultsdir}/{s}'
    os.makedirs(output_folder, exist_ok=True)
    command = (f'{openssl} ' 
               f'req -new -newkey {s} ' 
               f'-keyout {output_folder}/{s}_srv.key ' 
               f'-out {output_folder}/{s}_srv.csr ' 
               f'-nodes -subj "/CN={s}_test server" ' 
               f'-config {openssl}.cnf')
    options = f'--export-json {output_folder}/{s}_server_keypair_CArequest.json'

    run_hyperfine(command, options)

def create_signed_certificate(signature_algorithm):
    global resultsdir, openssl
    s = signature_algorithm 
    output_folder = f'{resultsdir}/{s}'
    os.makedirs(output_folder, exist_ok=True)
    command = (f'{openssl} ' 
               f'x509 -req ' 
               f'-in {output_folder}/{s}_srv.csr ' 
               f'-out {output_folder}/{s}_srv.crt ' 
               f'-CA {output_folder}/{s}_CA.crt -CAkey {output_folder}/{s}_CA.key '
               f'-CAcreateserial -days 365')
    options = f'--export-json {output_folder}/{s}_CAsign.json'

    run_hyperfine(command, options)
    
def benchmark_key_exchange(s, kem):
    global resultsdir, openssl, server_ip, server_port
    output_folder = f'{resultsdir}/{s}'
    runs = 100

    # copy over server key and certificate to remote server home folder
    subprocess.run(f'scp {output_folder}/{s}_srv.key {output_folder}/{s}_srv.crt {server_ip}:~/', shell=True, check=True)
    # build server command
    server_command = f'{openssl} s_server -cert {s}_srv.crt -key {s}_srv.key -www -tls1_3 -naccept {runs}'
    ssh_command = f'ssh -f {server_ip} \"{server_command}\"'
    # run server
    print("\n\nrunning server!!")
    print(ssh_command)
    server_proc = subprocess.run(ssh_command, shell=True)
    time.sleep(3)

    # run benchmark test
    command = f'{openssl} s_client -curves {kem} -CAfile {output_folder}/{s}_CA.crt -connect {server_ip}:{server_port}'
    options = f'--runs {runs} --export-json {output_folder}/{s}_{kem}.json'
    run_hyperfine(command, options)
    
    # stop server
    #server_proc.kill()

if __name__ == '__main__':
    main()

