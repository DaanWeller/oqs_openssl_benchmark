#!/bin/bash

s=$1
resultsdir=$2
output_folder = $resultsdir/$s
openssl=$3

$openssl req -new -newkey ec:<($openssl ecparam -name $s) -keyout $output_folder/$s\_client.key -out $output_folder/$s\_client.csr -nodes -subj "/CN=$s\_test client" -config $openssl.cnf

