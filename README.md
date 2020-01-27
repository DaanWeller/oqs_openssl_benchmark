 * per signature algorithm s:
   * create new CA with signature algorithm
   * create new server keypair 
   * create new certificate request for the CA
   * create new certificate signed by the CA
   * run the server with the newly created signed certificate
   * for each key exchange algorithm n:
     * run benchmark test on TLS client requesting nth key exchange algorithm
