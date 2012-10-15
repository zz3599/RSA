# RSA Engine

Aims to be compatible with OpenSSL on any *nix system. It can generate keys, encrypt, decrypt (with public/private) files, and certificates.

## Dependencies
GMP Library

## Compiling 
`gcc rsaengine.c -o rsaengine -L/usr/local/lib/ -lgmp -L/usr/lib -lcrypto -g -O0`

## Usage
Generate RSA Keys: 
`[binary name] genrsa` , defaults to creating public key in id\_rsa.pub, private key in id\_rsa

Encrypt: 
`[binary name] e [keyfile] [inputfile] [outputfile] [optional -priv]` , defaults to using public key

Decrypt: 
`[binary name] d [keyfile] [inputfile] [outputfile] [optional -pub]`, defaults to using private key

Certificates: 
`[binary name] cert [keyfile] [optional, input file]`
	   
