#!/bin/bash

s=$1
resultsdir=$2
output_folder=$resultsdir/$s
openssl=$3

$openssl req -x509 -new -newkey ec:<($openssl ecparam -name $s) -keyout $output_folder/$s\_CA.key -out $output_folder/$s\_CA.crt -nodes -subj "/CN=$s\_test CA" -days 365 -config $openssl.cnf

