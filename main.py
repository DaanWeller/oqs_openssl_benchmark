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
hybrid_kems = []
hybrid_sigs = []

export_options = ''

def main():
    global sigs, kems, nonpqc_sigs, hybrid_sigs, hybrid_kems
    initialize()
    
    start_time = time.time()

    telegram_bot_sendtext('---------------------------------------')
    telegram_bot_sendtext('Begin testing!')
    telegram_bot_sendtext(f'Results are put in {resultsdir}')

    amount_sig = len(sigs) + len(nonpqc_sigs) + len(hybrid_sigs)
    amount_kem = len(kems)
    amount_total = amount_sig * amount_kem
    nr_sig = 0
    nr_kem = 0
    nr_total = 0

    telegram_bot_sendtext(f'I found {amount_sig} different signatures and {amount_kem} different key exchange algorithms.')
    telegram_bot_sendtext(f'Therefore, there is a total of {amount_total} combinations.')

    for sig in hybrid_sigs:
        nr_sig += 1
        telegram_bot_sendtext(f'Now computing KEMs for {sig} \[ {nr_sig} / {amount_sig} ] - \[ {nr_total} / {amount_total} ]')
        create_certificate_authority(sig)
        create_server_keypair_CArequest(sig)
        create_signed_certificate(sig)
        for kem in hybrid_kems:
            nr_kem += 1
            nr_total += 1
            tcpdump_start(sig, kem)
            benchmark_key_exchange(sig, kem)
            tcpdump_stop()
            telegram_bot_sendtext(f'{sig} {kem} completed! \[ {nr_sig} / {amount_sig} ] - \[ {nr_kem} / {amount_kem} ] - \[ {nr_total} / {amount_total} ]')
        telegram_bot_sendtext(f'Done with all tests for {sig}!')
        copy_results(f'{sig}')
        nr_kem = 0

    for sig in sigs:
        nr_sig += 1
        telegram_bot_sendtext(f'Now computing KEMs for {sig} \[ {nr_sig} / {amount_sig} ] - \[ {nr_total} / {amount_total} ]')
        create_certificate_authority(sig)
        create_server_keypair_CArequest(sig)
        create_signed_certificate(sig)
        for kem in kems:
            nr_kem +=1
            nr_total += 1
            tcpdump_start(sig, kem)
            benchmark_key_exchange(sig, kem)
            tcpdump_stop()
            telegram_bot_sendtext(f'{sig} {kem} completed! \[ {nr_sig} / {amount_sig} ] - \[ {nr_kem} / {amount_kem} ] - \[ {nr_total} / {amount_total} ]')
        telegram_bot_sendtext(f'Done with all tests for {sig}!')
        copy_results(f'{sig}')
        nr_kem = 0

    for nonpqc_sig in nonpqc_sigs:
        nr_sig += 1
        sig = nonpqc_sig
        telegram_bot_sendtext(f'Now computing KEMs for {sig} \[ {nr_sig} / {amount_sig} ] - \[ {nr_total} / {amount_total} ]')
        create_certificate_authority(sig)
        create_server_keypair_CArequest(sig)
        create_signed_certificate(sig)
        for kem in kems:
            nr_kem += 1
            nr_total += 1
            tcpdump_start(sig, kem)
            benchmark_key_exchange(sig, kem)
            tcpdump_stop()
            telegram_bot_sendtext(f'{sig} {kem} completed! \[ {nr_sig} / {amount_sig} ] - \[ {nr_kem} / {amount_kem} ] - \[ {nr_total} / {amount_total} ]')
        telegram_bot_sendtext(f'Done with all tests for {sig}!')
        copy_results(f'{sig}')
        nr_kem = 0


#    telegram_bot_sendtext(f'I found {amount_sig} different signatures and {amount_kem} different key exchange algorithms.')
#    telegram_bot_sendtext(f'Therefore, there is a total of {amount_total} combinations.')
#
#    for sig in sigs:
#        nr_sig += 1
#        telegram_bot_sendtext(f'Now computing KEMs for {sig} \[ {nr_sig} / {amount_sig} ] - \[ {nr_total} / {amount_total} ]')
#        create_certificate_authority(sig)
#        create_server_keypair_CArequest(sig)
#        create_signed_certificate(sig)
#        
#        for kem in kems:
#            tcpdump_start(sig, kem)           
#            benchmark_key_exchange(sig, kem)
#            tcpdump_stop()
#            nr_kem += 1
#            nr_total += 1
#            telegram_bot_sendtext(f'{sig} {kem} completed! \[ {nr_sig} / {amount_sig} ] - \[ {nr_kem} / {amount_kem} ] - \[ {nr_total} / {amount_total} ]')
#        telegram_bot_sendtext(f'Done with all tests for {sig}!')
#        nr_kem = 0
#    telegram_bot_sendtext('The whole test is completed! \o/')
        
    end_time = time.time()
    
    elapsed_time = end_time - start_time
    elapsed_time = elapsed_time / 60

    telegram_bot_sendtext(f'Done with everything! \o/')
    telegram_bot_sendtext(f'Begin time was {start_time}.')
    telegram_bot_sendtext(f'End time was {end_time}.')
    telegram_bot_sendtext(f'Time elapsed: {elapsed_time} minutes')

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
    
    global resultsdir, openssl, server_ip, server_port, kems, sigs, nonpqc_sigs, hybrid_kems, hybrid_sigs

    resultsdir      = config.get('main', 'results_dir')
    openssl         = config.get('main', 'openssl_app')
    server_ip       = config.get('main', 'server_ip')
    server_port     = config.get('main', 'server_port')
    result_user     = config.get('main', 'result_user')
    result_server   = config.get('main', 'result_server')
    result_srv_dir  = config.get('main', 'result_srv_dir')
    kems            = [kem.strip() for kem in config.get('main', 'kems').splitlines()]
    sigs            = [sig.strip() for sig in config.get('main', 'signatures').splitlines()]
    hybrid_kems     = [kem.strip() for kem in config.get('main', 'hybrid_kems').splitlines()]
    hybrid_sigs     = [sig.strip() for sig in config.get('main', 'hybrid_sigs').splitlines()]

def run_hyperfine(command, options):
    hyperfine_command = f'hyperfine {options} \'{command}\''
    subprocess.run(hyperfine_command, shell=True, check=True, executable='/bin/bash')

def run_heaptrack(command, output_filename):
    heaptrack_filepath_command = f'heaptrack {command} | grep \'heaptrack --analyze\' | awk \'NF>1{{print $NF}}\' | tr -d \\"' 
    heaptrack_filepath_proc = subprocess.check_output(heaptrack_filepath_command, shell=True)

    heaptrack_filepath = heaptrack_filepath_proc.decode("utf-8").strip()
    
    heaptrack_analyze_command = f'heaptrack --analyze {heaptrack_filepath} | grep \'peak heap\' | awk \'NF>1{{print $NF}}\'' # double braces to escape brace characters used by awk
    heaptrack_analyze_proc = subprocess.check_output(heaptrack_analyze_command, shell=True)

    peak_heap_memory = heaptrack_analyze_proc.decode("utf-8").strip()
    telegram_bot_sendtext(f'Peak memory measured: {peak_heap_memory}')

    with open(f'{output_filename}.peakmem', 'w') as f:
        f.write(peak_heap_memory)

    os.rename(heaptrack_filepath, f'{output_filename}.gz')

# note: this does not work with normal curves (nonpqc)
# Generate key for CA
# /home/dweller/rp2/openssl/apps/openssl genpkey -algorithm dilithium2 -out dilithium2_CA.key

# crt generation for CA using a key previously generated
# /home/dweller/rp2/openssl/apps/openssl req -x509 -new -key dilithium2_CA.key -out dilithium2_CA.crt -nodes -subj "/CN=oqstest CA" -days 365 -config /home/dweller/rp2/openssl/apps/openssl.cnf

def create_certificate_authority(signature_algorithm):
    global resultsdir, openssl, nonpqc_sigs 
    s = signature_algorithm # make the command more readable?
    output_folder = f'{resultsdir}/{s}'
    output_file = f'{output_folder}/{s}_create_CA'

    os.makedirs(output_folder, exist_ok=True)
    
    if s in nonpqc_sigs:
        print(f'{s} is seen as a nonpqc')
        command = (f'./scripts/create_certificate_authority.sh {s} {resultsdir} {openssl}') 
    else:
        print(f'{s} is seen as a pqc')
        command = (f'{openssl} ' 
                   f'req -x509 -new -newkey {s} ' 
                   f'-keyout {output_folder}/{s}_CA.key ' 
                   f'-out {output_folder}/{s}_CA.crt ' 
                   f'-nodes -subj "/CN={s}_test CA" -days 365 ' 
                   f'-config {openssl}.cnf')

    options = f'--min-runs 100 --export-json {output_file}.json'

    run_hyperfine(command, options)
    run_heaptrack(command, output_file)

def create_server_keypair_CArequest(signature_algorithm):
    global resultsdir, openssl, nonpqc_sigs
    s = signature_algorithm 
    output_folder = f'{resultsdir}/{s}'
    output_file = f'{output_folder}/{s}_server_keypair_CArequest'

    os.makedirs(output_folder, exist_ok=True)

    if s in nonpqc_sigs:
        command = (f'./scripts/create_server_keypair_CArequest.sh {s} {resultsdir} {openssl}')
    else:
        command = (f'{openssl} ' 
                   f'req -new -newkey {s} ' 
                   f'-keyout {output_folder}/{s}_srv.key ' 
                   f'-out {output_folder}/{s}_srv.csr ' 
                   f'-nodes -subj "/CN={s}_test server" ' 
                   f'-config {openssl}.cnf')
    options = f'--min-runs 100 --export-json {output_file}.json'

    run_hyperfine(command, options)
    run_heaptrack(command, output_file)

def create_client(signature_algorithm):
    global resultsdir, openssl, nonpqc_sigs
    s = signature_algorithm 
    output_folder= f'{resultsdir}/{s}'

    os.makedirs(output_folder, exist_ok=True)

    if s in nonpqc_sigs:
        command = (f'./scripts/create_client.sh {s} {resultsdir} {openssl}')
    else:
        command = (f'{openssl} ' 
                   f'req -new -newkey {s} ' 
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
    output_file = f'{output_folder}/{s}_CAsign'

    os.makedirs(output_folder, exist_ok=True)

    command = (f'{openssl} ' 
               f'x509 -req ' 
               f'-in {output_folder}/{s}_srv.csr ' 
               f'-out {output_folder}/{s}_srv.crt ' 
               f'-CA {output_folder}/{s}_CA.crt -CAkey {output_folder}/{s}_CA.key '
               f'-CAcreateserial -days 365')
    options = f'--min-runs 100 --export-json {output_file}.json'

    run_hyperfine(command, options)
    run_heaptrack(command, output_file)
    
def benchmark_key_exchange(s, kem):
    global resultsdir, openssl, server_ip, server_port, amount_kem 
    output_folder = f'{resultsdir}/{s}'
    runs = 101

    # copy over server key and certificate to remote server home folder
    subprocess.run(f'scp {output_folder}/{s}_srv.key {output_folder}/{s}_srv.crt {server_ip}:~/', shell=True, check=True)
    
    # build server command
    server_command = f'{openssl} s_server -cert {s}_srv.crt -key {s}_srv.key -www -tls1_3 -naccept {runs}' # plus one for the memory test
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
               f'-connect {server_ip}:{server_port} </dev/null')
    options = f'--runs {runs} --export-json {output_folder}/{s}_{kem}.json'
    run_hyperfine(command, options)
    
    heaptrack_outfile = f'{output_folder}/{s}_{kem}.peakmem'
    run_heaptrack(command, heaptrack_outfile)
    
    # stop server
    stop_server = 'ps -ef | grep s_server | grep -v grep | awk \'{print $2}\' | xargs -r kill -9' 
    ssh_command = f'ssh -f {server_ip} \"{stop_server}\"'
    subprocess.run(ssh_command, shell=True)

def tcpdump_start(s, kem):
    global resultsdir
    output_folder = f'{resultsdir}/{s}'
    tcpdump_command = f'tcpdump -i eth0 \'host 145.100.105.244 && host 145.100.106.82\' -w {output_folder}/{s}_{kem}.pcap &'
    subprocess.run(tcpdump_command, shell=True, check=True)

def tcpdump_stop():
    subprocess.run("ps -ef | grep tcpdump | grep -v grep | awk \'{print $2}\' | xargs -r kill -9", shell=True, check=True)

def copy_results(sigdir):
    subprocess.run(f'scp -r {sigdir} {result_server}:{result_srv_dir}', shell=True, check=True)

def telegram_bot_sendtext(bot_message):
    bot_message = bot_message.replace("_", "\_")
    send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + bot_chatID + '&parse_mode=Markdown&text=' + bot_message

    response = requests.get(send_text)

    return response.json()

if __name__ == '__main__':
    main()

