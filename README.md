# RSA Engine

Aims to be compatible with OpenSSL on any *nix system. It can encrypt, decrypt (with public/private) and also sign and verify certificates. 

## Dependencies
GMP Library

## Usage
Generate RSA Keys: [binary name] genrsa , defaults to creating public key in id_rsa.pub, private key in id_rsa
Encrypt: [binary name] e [keyfile] [inputfile] [outputfile] [optional -priv] , defaults to using public key
Decrypt: [binary name] d [keyfile] [inputfile] [outputfile] [optional -pub], defaults to using private key
