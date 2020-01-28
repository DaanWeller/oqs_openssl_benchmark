#!/usr/bin/env python3

import os
import time
import argparse
from configparser import ConfigParser
from barry import bot_token, bot_chatID # <-- barry.py contains our bot token and bot_chatID
import subprocess
import requests


wd = ''
resultsdir = ''
openssl = ''

kems = []
sigs = []
nonpqc_sigs = []

export_options = ''

def main():
    global sigs, kems, nonpqc_sigs
    initialize()
    
    telegram_bot_sendtext('---------------------------------------')
    telegram_bot_sendtext('begin testing!')

    amount_sig = len(sigs) + len(nonpqc_sigs)
    amount_kem = len(kems)
    amount_total = amount_sig * amount_kem
    nr_sig = 0
    nr_kem = 0
    nr_total = 0

    for nonpqc_sig in nonpqc_sigs:
        nr_total += 1
        nr_sig += 1

        sig = nonpqc_sig
        
        telegram_bot_sendtext(f'Now computing KEMs for {sig} \[ {nr_sig} / {amount_sig} ] - \[ {nr_total} / {amount_total} ]')
        create_certificate_authority(sig)
        create_server_keypair_CArequest(sig)
        create_signed_certificate(sig)
        for kem in kems:
            tcpdump_start(sig, kem)
            benchmark_key_exchange(sig, kem)
            tcpdump_stop()
            nr_kem += 1
            nr_total += 1
            telegram_bot_sendtext(f'{sig} {kem} completed! \[ {nr_sig} / {amount_sig} ] - \[ {nr_kem} / {amount_kem} ] - \[ {nr_total} / {amount_total} ]')
        telegram_bot_sendtext(f'Done with all tests for {sig}!')
        nr_kem = 0


    telegram_bot_sendtext(f'I found {amount_sig} different signatures and {amount_kem} different key exchange algorithms.')
    telegram_bot_sendtext(f'Therefore, there is a total of {amount_total} combinations.')

    for sig in sigs:
        nr_sig += 1
        telegram_bot_sendtext(f'Now computing KEMs for {sig} \[ {nr_sig} / {amount_sig} ] - \[ {nr_total} / {amount_total} ]')
        create_certificate_authority(sig)
        create_server_keypair_CArequest(sig)
        create_signed_certificate(sig)
        
        for kem in kems:
            tcpdump_start(sig, kem)           
            benchmark_key_exchange(sig, kem)
            tcpdump_stop()
            nr_kem += 1
            nr_total += 1
            telegram_bot_sendtext(f'{sig} {kem} completed! \[ {nr_sig} / {amount_sig} ] - \[ {nr_kem} / {amount_kem} ] - \[ {nr_total} / {amount_total} ]')
        telegram_bot_sendtext(f'Done with all tests for {sig}!')
        nr_kem = 0
    telegram_bot_sendtext('The whole test is completed! \o/')
        

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
    
    global resultsdir, openssl, server_ip, server_port, kems, sigs, nonpqc_sigs

    resultsdir  = config.get('main', 'results_dir')
    openssl     = config.get('main', 'openssl_app')
    server_ip   = config.get('main', 'server_ip')
    server_port = config.get('main', 'server_port')
    kems        = [kem.strip() for kem in config.get('main', 'kems').splitlines()]
    sigs        = [sig.strip() for sig in config.get('main', 'signatures').splitlines()]
    nonpqc_sigs = [nonpqcsig.strip() for nonpqcsig in config.get('main', 'nonpqc_sigs').splitlines()]
    #export_options = [e.strip() for e in config.get('main', 'export_options').splitlines()]

def run_hyperfine(command, options):   
    hyperfine_command = f'hyperfine {options} \'{command}\''
    subprocess.run(hyperfine_command, shell=True, check=True, executable='/bin/bash')

def run_heaptrack(command, options):
    heaptrack_command = f'heaptrack {options} {command}'
    subprocess.run(heaptrack_command, shell=True, check=True)

def create_certificate_authority(signature_algorithm):
    global resultsdir, openssl, nonpqc_sigs 
    s = signature_algorithm # make the command more readable?
    output_folder = f'{resultsdir}/{s}'

    os.makedirs(output_folder, exist_ok=True)
    
    if s in nonpqc_sig:
        command = (f'./scripts/create_certificate_authority.sh {s} {resultsdir} {openssl}') 

    else:
        command = (f'{openssl} ' 
                   f'req -x509 -new -newkey {p} ' 
                   f'-keyout {output_folder}/{s}_CA.key ' 
                   f'-out {output_folder}/{s}_CA.crt ' 
                   f'-nodes -subj "/CN={s}_test CA" -days 365 ' 
                   f'-config {openssl}.cnf')

    options = f'--show-output --export-json {output_folder}/{s}_create_CA.json'

    run_hyperfine(command, options)

def create_server_keypair_CArequest(signature_algorithm):
    global resultsdir, openssl, nonpqc_sigs
    s = signature_algorithm 
    p = check_nonpqc(s)
    output_folder = f'{resultsdir}/{s}'
    os.makedirs(output_folder, exist_ok=True)

    if s in nonpqc_sig:
        command = (f'./scripts/create_server_keypair_CArequest.sh {s} {resultsdir} {openssl}')
    else:
        command = (f'{openssl} ' 
                   f'req -new -newkey {p} ' 
                   f'-keyout {output_folder}/{s}_srv.key ' 
                   f'-out {output_folder}/{s}_srv.csr ' 
                   f'-nodes -subj "/CN={s}_test server" ' 
                   f'-config {openssl}.cnf')
    options = f'--export-json {output_folder}/{s}_server_keypair_CArequest.json'

    run_hyperfine(command, options)

def create_client(signature_algorithm):
    global resultsdir, openssl, nonpqc_sigs
    s = signature_algorithm 
    output_folder= f'{resultsdir}/{s}'
    os.makedirs(output_folder, exist_ok=True)


    if s in nonpqc_sig:
        command = (f'./scripts/create_client.sh {s} {resultsdir} {openssl}')
    else:
        command = (f'{openssl} ' 
                   f'req -new -newkey {p} ' 
                   f'-keyout {output_folder}/{s}_client.key ' 
                   f'-out {output_folder}/{s}_client.csr ' 
                   f'-nodes -subj "/CN={s}_test client" ' 
                   f'-config {openssl}.cnf')

    subprocess.run(command, shell=True) 

    command = (f'{openssl} ' 
               f'x509 -req ' 
               f'-in {output_folder}/{s}_client.csr ' 
               f'-out {output_folder}/{s}_client.crt ' 
               f'-CA {output_folder}/{s}_CA.crt -CAkey {output_folder}/{s}_CA.key '
               f'-CAcreateserial -days 365')
 
    subprocess.run(command, shell=True) 

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
    global resultsdir, openssl, server_ip, server_port, amount_kem 
    output_folder = f'{resultsdir}/{s}'
    runs = 100

    # copy over server key and certificate to remote server home folder
    subprocess.run(f'scp {output_folder}/{s}_srv.key {output_folder}/{s}_srv.crt {server_ip}:~/', shell=True, check=True)
    
    # build tcpdump command
        # on sofia
    
    # build server command
    server_command = f'{openssl} s_server -cert {s}_srv.crt -key {s}_srv.key -www -tls1_3 -naccept {runs}'
    ssh_command = f'ssh -f {server_ip} \"{server_command}\"'
    # run server
    print("\n\nrunning server!!")
    print(ssh_command)
    server_proc = subprocess.run(ssh_command, shell=True)
    time.sleep(3)

    create_client(s)

    # run benchmark test {output_folder}/{s}_client.crt 
    command = (f'{openssl} s_client '
               f'-curves {kem} '
               f'-CAfile {output_folder}/{s}_CA.crt '
               f'-key {output_folder}/{s}_client.key '
               f'-cert {output_folder}/{s}_client.crt '
               f'-connect {server_ip}:{server_port}')
    options = f'--runs {runs} --export-json {output_folder}/{s}_{kem}.json'
    run_hyperfine(command, options)
    
    # stop server
    stop_server = 'ps -ef | grep s_server | grep -v grep | awk \'{print $2}\' | xargs -r kill -9' 
    ssh_command = f'ssh -f {server_ip} \"{stop_server}\"'
    server_proc = subprocess.run(ssh_command, shell=True)

def tcpdump_start(s, kem):
    global resultsdir
    output_folder = f'{resultsdir}/{s}'
    tcpdump_command = f'tcpdump -i eth0 \'host 145.100.105.244 && host 145.100.106.82\' -w {output_folder}/{s}_{kem}.pcap &'
    subprocess.run(tcpdump_command, shell=True, check=True)

def tcpdump_stop():
    subprocess.run("ps -ef | grep tcpdump | grep -v grep | awk \'{print $2}\' | xargs -r kill -9", shell=True, check=True)

def telegram_bot_sendtext(bot_message):
    
    send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + bot_chatID + '&parse_mode=Markdown&text=' + bot_message

    response = requests.get(send_text)

    return response.json()

if __name__ == '__main__':
    main()

