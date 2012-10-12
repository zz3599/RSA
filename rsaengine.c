#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#define MAXPRIMESIZE 512 //random primes of size 512 bits, mod size of 1024 bits
#define MODSIZE (MAXPRIMESIZE*2)
#define E 65537 // public exponent
#define BLOCKSIZE (MODSIZE/8) //the block size for block encryption

typedef struct public_key {
  mpz_t e; //public exponent, e
  mpz_t n; //modulus, n
} public_key;

typedef struct private_key{
  mpz_t d; //private exponent, d
  mpz_t e; //public exponent, e
  mpz_t n; //modulus, n
  mpz_t p; //prime 1
  mpz_t q; //prime 2
  mpz_t exp1; //exponent 1, d mod (p-1)
  mpz_t exp2; //exponent 2, d mod (q-1)
  mpz_t coeff; //coefficient (inverse of q) mod p
} private_key;

//base64 table
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
//deocding table, constructed when needed
static char *decoding_table = NULL;

void generateRSAkeys(public_key*, private_key*);
void randomPrime(mpz_t, int, gmp_randstate_t);
void writePrivate(private_key*, char*);
void writePublic(public_key*, char*);
void writeString(FILE*, char*, size_t, int);
void base64_encode(int*, char*, int);
void base64_decode(char*, unsigned char*, int);
int fromhex(char p1, char p2){
  int c1 =  (unsigned char)p1 - 48;
  int c2 = (unsigned char)p2 - 48;  
  if(c1 > 9) c1 -= 39;
  if(c2 > 9) c2 -= 39;
  return c1*16 + c2;
}
void genrsa();
void encrypt(char*, char*, char*);
//this will do the heavy duty encrypting for both public and private exponents, writing to the filename
int pub_encrypt(char* message, char* filename, int message_sz, mpz_t exponent, mpz_t modulus);


void decrypt(char*, char*, char*);


int extractmodulus(char*, mpz_t m);
int extractprivate(char* keyname, mpz_t d);
void build_decoding_table();
void base64_cleanup();

int main(int argc, char** argv){
  //genrsa - generates keys
  //e - encrypt, with keyfile and inputfile , outputfile
  //d - decrypt, with keyfile and inputfile , outputfile
  //
  if(argc < 2) printf("usage: %s [option]\n", argv[0]);
  else {
    if(strcmp(argv[1], "genrsa") == 0){
      genrsa();
    } else if(strcmp(argv[1], "e") == 0){
      if(argc < 5) printf("encrypt usage: %s e [keyfile] [inputfile] [outputfile]\n", argv[0]);
      else 
        encrypt(argv[2], argv[3], argv[4]);
    } else if(strcmp(argv[1], "d") == 0){
      if(argc < 5) printf("decrypt usage: %s d [keyfile] [inputfile] [outputfile]\n", argv[0]);
      else decrypt(argv[2], argv[3], argv[4]);
    } 
    else {
      printf("Unrecognized command: %s\n", argv[1]);
    }
  }
  return 0;
}

void genrsa(){
  private_key* privatekey = (private_key*) malloc(sizeof(private_key));
  mpz_init(privatekey->d); mpz_init(privatekey->e);  mpz_init(privatekey->n); mpz_init(privatekey->p);  mpz_init(privatekey->p); mpz_init(privatekey->exp1);
  mpz_init(privatekey->exp2); mpz_init(privatekey->coeff);
  public_key* publickey = (public_key*) malloc(sizeof(public_key));
  mpz_init(publickey->e); mpz_init(publickey->n);
  generateRSAkeys(publickey, privatekey);
  gmp_printf("Generated rsa artifacts:\nd: %Zd\ne: %Zd\nmod: %Zd\nexp1: %Zd\nexp2: %Zd\ncoeff: %Zd\n", privatekey->d, privatekey->e, privatekey->n, privatekey->exp1, privatekey->exp2, privatekey->coeff);
  writePrivate(privatekey, "id_rsa"); 
  writePublic(publickey, "id_rsa.pub");
  free(privatekey);
  free(publickey);
}

void encrypt(char* keyfile, char* inputfile, char* output){
  //public exponent is known
  mpz_t mod; mpz_init(mod);
  //extract modulus from the keyfile
  int gotmod = extractmodulus(keyfile, mod);
  if(gotmod == -1){
    printf("Failed in getting mod\n");
    return;
  }
  gmp_printf("Mod is %Zd\n", mod);
  mpz_t e, d; mpz_init(e); mpz_init(d);
  mpz_set_ui(e, E);
  base64_cleanup();
  //get the file data
  FILE* input = fopen(inputfile, "r");
  fseek(input, 0, SEEK_END);
  int input_sz = ftell(input);
  rewind(input);
  char* filecontents = (char*)malloc(input_sz);
  fread(filecontents, 1, input_sz, input);
  printf("\n\nFile contents: %s\nsize: %d\n", filecontents, input_sz);
  pub_encrypt(filecontents, output, input_sz, e, mod);
}

//should always be less than 117 bytes
int pub_encrypt(char* message, char* filename, int message_sz, mpz_t exponent, mpz_t modulus){
  if(message_sz > BLOCKSIZE-11){
    return -1;
  }
  int i,j, n, random;
  unsigned char* cipher = (unsigned char*)malloc(BLOCKSIZE);
  cipher[0] = 0x00;
  cipher[1] = 0x02;
  n = BLOCKSIZE - 3 - message_sz;

  for(i = 2; i < n + 2; i++){
    random = rand() % 256; //it cannot be zero otherwise the message becomes ambiguous
    while(random == 0) random = rand() % 256;
    cipher[i] = random;
  }
  cipher[i++] = 0x00;
  for(j = i; i < BLOCKSIZE; i++){
    cipher[i] = message[i-j];
  }
  for(i = 0; i < BLOCKSIZE; i++){
    printf("%.2x ", cipher[i]);
  }
  mpz_t m; mpz_init(m);
  mpz_import(m, BLOCKSIZE, 1, sizeof(char), 0, 0, cipher);
  gmp_printf("\nm=%Zx\n", m);
  //raise to exponent mod n
  mpz_powm(m, m, exponent, modulus);
  size_t cipher_sz; 
  unsigned char* ciphertext =  (unsigned char*)mpz_export(NULL, &cipher_sz, 1, sizeof(char), 0, 0, m);
  FILE* file = fopen(filename, "w+");
  fprintf(file, "%s", ciphertext);
  for(i = 0; i < cipher_sz; i++){
    printf("%.2x ", ciphertext[i]); 
  } 
  printf("\ncipher sz: %d\n", (int)cipher_sz);
  fclose(file);
  return 0;
}

void decrypt(char* key, char* input, char* output){
  FILE* inputfile = fopen(input, "r");
  int i; 
  if(inputfile == NULL){
    printf("input file invalid\n");
    return;
  }
  fseek(inputfile, 0, SEEK_END);
  int input_sz = ftell(inputfile);
  rewind(inputfile);
  char* filecontents = (char*) malloc(input_sz);
  fread(filecontents, 1, input_sz, inputfile);
  mpz_t mod, exp; mpz_init(mod); mpz_init(exp);
  int gotmod = extractmodulus(key, mod);
  if(gotmod == -1){
    printf("Key file does not have mod\n");
    return;
  }
  int gotexponent = extractprivate(key, exp);
  if(gotexponent == -1){
    printf("Key file does not have a private exponent\n");
    return;
  }
  mpz_t Y; mpz_init(Y);
  
  mpz_import(Y, input_sz, 1, sizeof(char), 0, 0, filecontents);//convert the file contents into a bignum representation
  gmp_printf("Mod: %Zx\nExponent: %Zx\n\n\nSize: %d\n", mod, exp, input_sz); 
  mpz_powm(Y, Y, exp, mod);//m^c mod n
  size_t decoded_size;
  unsigned char* decoded = (unsigned char*) mpz_export(NULL, &decoded_size, 1, sizeof(char), 0, 0, Y);//get back to a byte stream
  
  //verify the parameters
  if(decoded[0] != 0x02){
    printf("Improperly encoded file\n");
    return;
  }
  unsigned char* originaltext = NULL;
  for(i = 1; i < decoded_size; i++){
    if(decoded[i] == 0x00){//we start parsing the data after this byte
      int j = i + 1;
      originaltext = (unsigned char*) malloc(decoded_size - j);
      for(; j < decoded_size; j++){
	originaltext[j- (i+1)] = decoded[j];	
      }
    }
    //    printf("%.2x (%d) ", decoded[i], (int)decoded_size);
  }
  printf("\nOriginal text: %s\n", originaltext);
}


//write out the private key to a file
void writePrivate(private_key* privatekey, char* filename){
  char* fname = "temp.txt";
  FILE* file = fopen(fname, "w+");
  size_t count, totalsize, mod_sz, pub_sz, priv_sz, p_sz, q_sz, exp1_sz, exp2_sz, coeff_sz;
  totalsize = mod_sz = pub_sz = priv_sz = p_sz = q_sz = exp1_sz = exp2_sz = coeff_sz = 0;
  //mod
  gmp_printf("\n\nMod: %Zx\n", privatekey->n);
  char* mod = (char*) mpz_export(NULL, &mod_sz, 1, sizeof(char), 1, 0, privatekey->n); 
  //public exponent
  char* pub = (char*) mpz_export(NULL, &pub_sz, 1, sizeof(char), 1, 0, privatekey->e); 
  //private exponent
  char* priv = (char*) mpz_export(NULL, &priv_sz, 1, sizeof(char), 1, 0, privatekey->d); 
  //prime 1
  char* p = (char*) mpz_export(NULL, &p_sz, 1, sizeof(char), 1, 0, privatekey->p); 
  //prime 2 
  char* q = (char*) mpz_export(NULL, &q_sz, 1, sizeof(char), 1, 0, privatekey->q); 
  //exponent 1
  char* exp1 = (char*) mpz_export(NULL, &exp1_sz, 1, sizeof(char), 1, 0, privatekey->exp1); 
  //exponent 2
  char* exp2 = (char*) mpz_export(NULL, &exp2_sz, 1, sizeof(char), 1, 0, privatekey->exp2); 
  //coefficient
  char* coeff = (char*) mpz_export(NULL, &coeff_sz, 1, sizeof(char), 1, 0, privatekey->coeff); 
  //total size
  totalsize =  3 + (mod_sz + 4) + (pub_sz + 2) + (priv_sz + 4) + (p_sz + 3) +  (q_sz + 3) + (exp1_sz + 3) + (exp2_sz + 2) + (coeff_sz + 3);
  //write

  fprintf(file,  "3082%.4x02010002%.2x%.2x",   (unsigned int)totalsize,   (unsigned int)mod_sz+1,  (unsigned int) mod_sz+1);
  writeString(file, mod,   (unsigned int)mod_sz, 1);
  fprintf(file, "02%.2x",   (unsigned int)pub_sz);
  writeString(file, pub,   (unsigned int)pub_sz, 0);
  fprintf(file, "02%.2x%.2x",  (unsigned int) priv_sz+1,   (unsigned int)priv_sz+1);
  writeString(file, priv,   (unsigned int)priv_sz, 1);
  fprintf(file, "02%.2x",   (unsigned int)p_sz+1);
  writeString(file, p,   (unsigned int)p_sz, 1);
  fprintf(file, "02%.2x",   (unsigned int)q_sz+1);
  writeString(file, q,   (unsigned int)q_sz, 1);
  fprintf(file, "02%.2x",   (unsigned int)exp1_sz+1);
  writeString(file, exp1,   (unsigned int)exp1_sz, 1);
  fprintf(file, "02%.2x",   (unsigned int)exp2_sz);
  writeString(file, exp2,   (unsigned int)exp2_sz, 0);
  fprintf(file, "02%.2x",   (unsigned int)coeff_sz+1);
  writeString(file, coeff,   (unsigned int)coeff_sz, 1);
  fclose(file);
  //now convert the file to base64
  file = fopen(fname, "r");
  FILE* keyfile = fopen(filename, "w+");
  char buffer[7],  encoded[5];  
  int toencode[3];
  int i;

  fprintf(keyfile, "-----BEGIN RSA PRIVATE KEY-----\n");
  int counter = 0; 
  while(fgets(buffer, 7, file) != NULL){
    for(i = 0; i < 3 && buffer[2*i] != '\0'; i++){
      toencode[i] = fromhex(buffer[i*2], buffer[i*2+1]);
    }
    base64_encode(toencode, encoded, i);
    //printf("%s to  %s\n", buffer, encoded);
    fprintf(keyfile, "%s", encoded);
    counter++;
    if(counter % 16 == 0)
      fprintf(keyfile, "\n");
  }
  fprintf(keyfile, "\n-----END RSA PRIVATE KEY-----\n");
  fclose(file);
  remove(fname);
  fclose(keyfile);
  free(mod); free(pub); free(priv); free(p); free(q); free(exp1); free(exp2); free(coeff);
}

//write out the string to filename
void writeString(FILE* file, char* towrite, size_t size, int usenull){
  int i = 0; 
  //  printf("\nSize of print: %d\n", size);
  char buffer[10];
  if(usenull) fprintf(file, "00");//this is for all the values
  while(i < size){
    sprintf(buffer, "%.2x", (unsigned char) * (towrite+i));
    fprintf(file, "%.2x", (unsigned char) *(towrite+i));
    i++;
  }
}

//write out the public key to a file
void writePublic(public_key* publickey, char* filename){
  char* fname = "temp";
  FILE* file = fopen(fname, "w+");
  size_t count;
  char* print = "30819f300d06092a864886f70d010101050003818d00308189028181";
  fprintf(file, "%s", print);
  //mod
  gmp_printf("\n\nMod: %Zx\n", publickey->n);
  print  = (char*) mpz_export(NULL, &count, 1, sizeof(char), 1, 0, publickey->n); 
  writeString(file, print, count, 1);  
  //public exponent
  print = (char*) mpz_export(NULL, &count, 1, sizeof(char), 1, 0, publickey->e); 
  fprintf(file, "02%.2x",   (unsigned int)count);
  writeString(file, print, count, 0);
  fclose(file);
  //base 64 conversion
  file = fopen(fname, "r");
  FILE* keyfile = fopen(filename, "w+");
  char buffer[7],  encoded[5];  
  int toencode[3];
  int i, counter = 0;
  fprintf(keyfile, "-----BEGIN PUBLIC KEY-----\n");  
  while(fgets(buffer, 7, file) != NULL){
    for(i = 0; i < 3 && buffer[2*i] != '\0'; i++){
      toencode[i] = fromhex(buffer[i*2], buffer[i*2+1]);
      //printf("%d ", toencode[i]);
    }
    base64_encode(toencode, encoded, i);
    //printf("%s to  %s\n", buffer, encoded);
    fprintf(keyfile, "%s", encoded);
    counter++;
    if(counter % 16 == 0)
      fprintf(keyfile, "\n");

  }
  fprintf(keyfile, "\n-----END PUBLIC KEY-----\n");
  fclose(file);
  remove(fname);
  fclose(keyfile);
}

//decode
void base64_decode(char *data, unsigned char* decoded_data, int inputlength){
  int outputsize = inputlength/4 * 3;
  if (data[inputlength-1] == '=') outputsize--;
  if (data[inputlength-2] == '=') outputsize--;
  int i, j;

  for (i = 0, j = 0; i < inputlength;) {
    uint32_t sextet_a = (unsigned char)data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
    uint32_t sextet_b = (unsigned char)data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
    uint32_t sextet_c = (unsigned char)data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
    uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

    uint32_t triple = (sextet_a << 18)
      + (sextet_b << 12)
      + (sextet_c << 6)
      + (sextet_d);
    triple &= 0x00ffffff;
    
    if (j < outputsize) decoded_data[j++] = (unsigned char)((triple >> 16) & 0x000000FF);
    if (j < outputsize) decoded_data[j++] = (unsigned char)((triple >> 8) & 0x000000FF);
    if (j < outputsize) decoded_data[j++] = (unsigned char)((triple) & 0x000000FF);
    //     printf("%c%c%c%c -> %x -> %.2x %.2x %.2x\n", data[i-4], data[i-3], data[i-2], data[i-1], triple, decoded_data[j-3], decoded_data[j-2], decoded_data[j-1]);
    
  }
  //  decoded_data[j] = '\0';

}
//build decoding table
void build_decoding_table() {
  decoding_table = malloc(256);
  int i;
  for (i = 0; i < 0x40; i++)
    decoding_table[encoding_table[i]] = i;
}

//free the decoding table
void base64_cleanup() {
  if(decoding_table)
    free(decoding_table);
}

//encode
void base64_encode(int *data, char* tofill, int numbytes){
  int i = 0;
  int j = 0;
  uint32_t octet_a = i < numbytes ? data[i++] : 0;
  uint32_t octet_b = i < numbytes ? data[i++] : 0;
  uint32_t octet_c = i < numbytes ? data[i++] : 0;
  uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
  
  tofill[0] = encoding_table[(triple >> 18) & 0x3F];
  tofill[1] = encoding_table[(triple >> 12) & 0x3F];
  tofill[2] = encoding_table[(triple >> 6) & 0x3F];
  tofill[3] = encoding_table[(triple) & 0x3F];  
  tofill[4] = '\0';
  if(numbytes == 2)
    tofill[3] = '=';
  if(numbytes == 1)
    tofill[2] = tofill[3] = '=';
}

void generateRSAkeys(public_key* publickey, private_key* privatekey){
  //first seed the randomstate variable to the current time
  gmp_randstate_t r_state;
  gmp_randinit_default (r_state);
  gmp_randseed_ui(r_state, time(0));
  mpz_t p, q, n, e, d; 
  mpz_init(p); mpz_init(q); mpz_init(n); mpz_init(e); mpz_init(d);
  do {
    randomPrime(p, MAXPRIMESIZE, r_state);
    randomPrime(q, MAXPRIMESIZE, r_state);
    //n = p*q  
    mpz_mul(n, p, q);
    printf("SIZE of n in bits: %d, p: %d, q: %d\n", (int)mpz_sizeinbase(n, 2), (int)mpz_sizeinbase(p, 2), (int)mpz_sizeinbase(q, 2));
  } while(mpz_sizeinbase(n,2) != 1024);
  
  mpz_t p1, q1, theta;
  mpz_init(p1); mpz_init(q1); mpz_init(theta); 
  mpz_sub_ui(p1, p, 1);
  mpz_sub_ui(q1, q, 1);
  //theta = (p-1)* (q-1)
  mpz_mul(theta, p1, q1);
  //calculate e, a prime in itself, coprimal with theta
  mpz_set_ui(e, E);
  //now get d s.t. e*d = 1 (mod theta)
  mpz_invert(d, e, theta);

  //set the public key
  mpz_set(publickey->n, n); mpz_set(publickey->e, e);
  //set the private key
  mpz_set(privatekey->e, e); mpz_set(privatekey->n, n); mpz_set(privatekey->d, d);
  mpz_set(privatekey->p, p); mpz_set(privatekey->q, q);
  mpz_mod(privatekey->exp1, d, p1);
  mpz_mod(privatekey->exp2, d, q1);
  mpz_invert(privatekey->coeff, q, p);
  //erase p and q
  mpz_clear(p); mpz_clear(q);
}


//stores a prime number  with length digits in prime
void randomPrime(mpz_t prime, int length, gmp_randstate_t rstate){
  //make sure generated prime is has exactly (length) number of digits
  mpz_t max, min;
  mpz_init(max);  mpz_init(min);
  mpz_ui_pow_ui(max, 2, length);
  mpz_ui_pow_ui(min, 2, length-1);
  
  mpz_t random;
  mpz_init(random);
  mpz_urandomm(random, rstate, max);
  while(mpz_cmp(random, min) < 0){
    mpz_urandomm(random, rstate, max);
  }
  //gets first prime greater than random
  mpz_nextprime(prime, random);
  mpz_clear(max);
  mpz_clear(min);
}

int extractmodulus(char* keyfile, mpz_t mod){
  FILE* key; 
  int i;
  if( (key = fopen(keyfile, "r")) == NULL){
    printf("Invalid file names\n");
    return -1;
  }
  if (decoding_table == NULL) build_decoding_table();
  char* line = NULL; ssize_t read = -1; size_t len = 0;    
  unsigned char* decoded;
  int found = 0, mpz_index = 0; 
  unsigned char _mpzimportbuffer[128];
  for(i = 0; (read = getline(&line, &len, key)) != -1; i++){
    if(i == 0 || line[0] == '-') continue;
    printf("%s (%d)-> ", line, (int)read);
    int decode_sz = read / 4 * 3;
    decoded = (unsigned char*) malloc(decode_sz);
    base64_decode(line, decoded, read-1);
    //next to search the hex string for the boundaries of the modulus
    int j; 
    char decodehex[2*decode_sz + 1];
    char* decodehex_index = decodehex;
    char temp[3];

    for(j = 0; j < decode_sz; j++){
      // printf("%.2x",  decoded[j]);
      sprintf(temp, "%.2x", decoded[j]);
      decodehex[2*j] = temp[0]; 
      decodehex[2*j + 1] = temp[1];
    }
    decodehex[2*decode_sz] = '\0';
    printf("%s\n\n", decodehex);
    
    if(!found){
      char* _modheader = strstr(decodehex, "028181");
      if(_modheader){
        _modheader += 8; //skip next 4 bytes
        found = 1;
        printf("\nFound 028181 -> %c%c%c\n\n", *(_modheader),  *(_modheader+1),  *(_modheader+2));
        while(*_modheader != '\0'){
          unsigned char c1 = (unsigned char)*_modheader;
          _modheader++;
          unsigned char c2 = (unsigned char)*_modheader;
          _modheader++;
          _mpzimportbuffer[mpz_index++] = fromhex(c1, c2);

        }
      }
    } else {//already found modulus header, start filling
      char* _endheader = strstr(decodehex, "0203010001");
      if(_endheader){//we found the end, remember to break
        while(decodehex_index != _endheader){
          unsigned char c1 = (unsigned char)*decodehex_index;
          decodehex_index++;
          unsigned char c2 = (unsigned char)*decodehex_index;
          decodehex_index++;
          _mpzimportbuffer[mpz_index++] = fromhex(c1, c2);
        }        
	break;//break out we've found our modulus
      } else { 
        while(*decodehex_index != '\0'){
          unsigned char c1 = (unsigned char)*decodehex_index;
          decodehex_index++;
          unsigned char c2 = (unsigned char)*decodehex_index;
          decodehex_index++;
          _mpzimportbuffer[mpz_index++] = fromhex(c1, c2);
        }
      }
    }
  }

  //now do conversion to bignum
  //  mpz_t mod; mpz_init(mod); 
  mpz_import(mod, 128, 1, 1, 0, 0, _mpzimportbuffer);
  gmp_printf("\nMod is(hex): %Zx\n\n", mod);
  fclose(key);

}

int extractprivate(char* keyname, mpz_t d){
  FILE* keyfile = fopen(keyname, "r");
  int i; 
  if(keyfile == NULL){
    printf("No such file, %s\n", keyname);
    return -1;
  }
  if(decoding_table == NULL) build_decoding_table();
  char* line = NULL; 
  ssize_t read = -1; size_t len = 0;
  unsigned char* decoded; //the base64-decoded into integer byte buffer
  //this is to keep track in the reading buffer for the private exponent
  int found = 0, mpz_index = 0, header_count = 0; //only if header count is already 1 do we start parsing
  unsigned char _mpzimportbuffer[128]; //size of the private exponent is 128 bytes, 0-255 in value
  for(i = 0; (read = getline(&line, &len, keyfile)) != -1; i++){
    if(i == 0 || line[0] == '-') continue;
    int decode_sz = read / 4 * 3;
    decoded = (unsigned char*)malloc(decode_sz); 
    base64_decode(line, decoded, read-1); //skip the new line char
    //convert to a stream of size decode*2 as hex values, so we can scan for the headers
    int j; 
    char decodehex[2*decode_sz + 1];//the one we will use for searching hex values
    char temp[3]; //store the temporary hex vaue buffer
    for(j = 0; j < decode_sz; j++){
      sprintf(temp, "%.2x", decoded[j]);
      decodehex[2*j] = temp[0];
      decodehex[2*j + 1] = temp[1];
    }
    decodehex[2*decode_sz] = '\0';
    printf("Decoded hex string: %s\n\n", decodehex);//diagnostic
    char* decodehex_index = decodehex; //for easier looping
    //now that we have converted buffer, let's search for the patterns
    if(!found){
      char* _expheader = strstr(decodehex, "028181");
      if(_expheader){
	header_count++;
	if(header_count == 2){
	  _expheader += 8; //move up 4 bytes to skip the header and the null byte
	  printf("Found the beginning of private: %c %c %c\n", *_expheader, *(_expheader+1), *(_expheader+2));
	  found = 1; 
	  while(*_expheader != '\0'){
	    unsigned char c1 = (unsigned char)*_expheader; 
	    _expheader++;
	    unsigned char c2 = (unsigned char)*_expheader; 
	    _expheader++;
	    _mpzimportbuffer[mpz_index++] = fromhex(c1, c2);
	  }
	}
      }
    } else { //already found the header, so check to see if we need to stop eventually
      char* _endheader = strstr(decodehex, "024100");//024100 is the header for the end of the string 
      if(_endheader){
	while(decodehex_index != _endheader){//there is an end header, so...
	  unsigned char c1 = (unsigned char) *decodehex_index;
	  decodehex_index++;
	  unsigned char c2 = (unsigned char) *decodehex_index;
	  decodehex_index++;
	  _mpzimportbuffer[mpz_index++] = fromhex(c1, c2);
	}
	break;//break out once we are done with the last one
      } else { //no end header found, so just go to the end of the line
	while(*decodehex_index != '\0'){
	  unsigned char c1 = (unsigned char) *decodehex_index;
	  decodehex_index++;
	  unsigned char c2 = (unsigned char) *decodehex_index;
	  decodehex_index++;
	  _mpzimportbuffer[mpz_index++] = fromhex(c1,c2);
	}
      }
    }
  }
  assert(mpz_index == 128);
  //set d to the private exponent
  mpz_import(d, 128, 1, sizeof(char), 0, 0, _mpzimportbuffer);
  gmp_printf("\n\nPrivate key parsed to be: %Zx\n\n", d);
  fclose(keyfile);
  return 0;
}
