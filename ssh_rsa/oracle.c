#include <openssl/bn.h>

#include <openssl/rand.h>
  
#include <openssl/pem.h>
  
#include <openssl/err.h>
  
#include <stdio.h>
  
#include <unistd.h>
  
#include <stdint.h>
  
#include <string.h>
  
#define PRIVATE_KEY_PATH "/challenge/cryptanalyse/ch27/private.key"
  
#define PADD_ERR_STRING "[-] PKCS#1_5 : error"
  
#define DEC_OK_STRING "[+] decryption : ok"
  
typedef struct
{
  

uint8_t * buf;
  

size_t size;


} BUFFER_t;

 
void
puts_and_flush (const char *string)
{
  
 
puts (string);
  
 
fflush (stdout);

 
} 
 
void

buffer_init (BUFFER_t * buf, size_t size)
{
  
 
if ((buf->buf = malloc (size)) == NULL)
    {
      
 
perror ("Malloc failed ");
      
 
exit (EXIT_FAILURE);
    
 
}
  
 
buf->size = size;

 
}


 
void
buffer_free (BUFFER_t * buf)
{
  
 
free (buf->buf);
  
 
buf->buf = NULL;

 
} 
 
void

buffer_dump (BUFFER_t * buf)
{
  
 
size_t i;
  
 
for (i = 0; i < buf->size; i++)
    {
      
 
printf ("%.2X", buf->buf[i]);
    
 
}
  
 
printf ("\n");
  
 
fflush (stdout);

 
}


 
int
decrypt_buffer (RSA * rsa, const BUFFER_t * b_cipher, BUFFER_t * b_plain)
{
  
 
int size;
  
 
buffer_init (b_plain, RSA_size (rsa));
  
 
size =
    RSA_private_decrypt (b_cipher->size, b_cipher->buf, b_plain->buf, rsa,
			 RSA_PKCS1_PADDING);
  
 
if (size < 0)
    {
      
 
puts_and_flush (PADD_ERR_STRING);
      
 
buffer_free (b_plain);
      
 
return 0;
    
 
}
  
 
b_plain->size = size;
  
 
return 1;

 
}


 
int
encrypt_buffer (RSA * rsa, const BUFFER_t * b_plain, BUFFER_t * b_cipher)
{
  
 
buffer_init (b_cipher, RSA_size (rsa));
  
 
if (RSA_public_encrypt
	 (b_plain->size, b_plain->buf, b_cipher->buf, rsa,
	  RSA_PKCS1_PADDING) < 0)
    {
      
 
buffer_free (b_cipher);
      
 
return 0;
    
 
}
  
 
return 1;

 
}


 
RSA * load_rsa (const char *filename)
{
  
 
RSA * rsa_key = NULL;
  
 
FILE * file;
  
 
if ((file = fopen (filename, "r")) == NULL)
    {
      
 
perror ("fopen failed ");
      
 
exit (EXIT_FAILURE);
    
 
}
  
 
PEM_read_RSAPrivateKey (file, &rsa_key, NULL, NULL);
  
 
if (rsa_key == NULL)
    {
      
 
fprintf (stderr, "Failed to load RSA private key !\n");
      
 
exit (EXIT_FAILURE);
    
 
}
  
 
return rsa_key;

 
}


 
int
main (int argc, char **argv)
{
  
 
RSA * rsa;
  
 
BUFFER_t buf1, buf2;
  
 
int encrypt;
  
 
buffer_init (&buf1, 4096);
  
 
rsa = load_rsa (PRIVATE_KEY_PATH);
  
 
if (argc == 2 && !strcmp (argv[1], "encrypt"))
    {
      
 
encrypt = 1;
    
 
}
  else
    {
      
 
encrypt = 0;
    
 
}
  
 
while ((buf1.size = read (STDIN_FILENO, buf1.buf, 4096)) > 0)
    {
      
 
if (encrypt)
	{
	  
 
if (encrypt_buffer (rsa, &buf1, &buf2))
	    {
	      
 
buffer_dump (&buf2);
	      
 
buffer_free (&buf2);
	    
 
}
	
 
}
      else
	{
	  
 
if (decrypt_buffer (rsa, &buf1, &buf2))
	    {
	      
 
		// buffer_dump(&buf2); # :-)
		
puts_and_flush (DEC_OK_STRING);
	      
 
buffer_free (&buf2);
	    
 
}
	
 
}
    
 
}
  
 
buffer_free (&buf1);
  
 
RSA_free (rsa);
  
 
return 0;

 
}
