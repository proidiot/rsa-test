#ifndef MY_RSA_H
#define MY_RSA_H

#include <openssl/rsa.h>

#define MY_OAEP_PADDING_RATIO 0.25
#define MY_OAEP_PADDING_ADDITIONAL_BYTES 0

typedef RSA* MY_PRIV_KEY;

typedef RSA* THEIR_PUB_KEY;

typedef struct MY_BLOB_STRUCT {
	size_t len;
	unsigned char data[];
} * MY_BLOB;

typedef MY_BLOB MY_ENCRYPTED_BLOB;
typedef MY_BLOB MY_DECRYPTED_BLOB;

typedef struct MY_SIGNED_BLOB_STRUCT {
	size_t siglen;
	size_t bloblen;
	unsigned char sigblobcombo[];
} * MY_SIGNED_BLOB;

MY_PRIV_KEY get_my_priv_key(const char* privfile);

THEIR_PUB_KEY get_their_pub_key(const char* pubfile);

MY_SIGNED_BLOB my_sign_blob(MY_BLOB blob, MY_PRIV_KEY rkey);

MY_ENCRYPTED_BLOB encrypt_blob(MY_BLOB blob, THEIR_PUB_KEY ukey);

MY_SIGNED_BLOB my_sign_encrypt_blob(MY_DECRYPTED_BLOB blob, MY_PRIV_KEY rkey, THEIR_PUB_KEY ukey);

MY_ENCRYPTED_BLOB my_encrypt_sign_blob(MY_DECRYPTED_BLOB blob, MY_PRIV_KEY rkey, THEIR_PUB_KEY ukey);

int my_check_blob(MY_SIGNED_BLOB sblob, THEIR_PUB_KEY ukey);

MY_DECRYPTED_BLOB my_decrypt_blob(MY_ENCRYPTED_BLOB eblob, MY_PRIV_KEY rkey);

MY_DECRYPTED_BLOB my_check_decrypt_blob(MY_SIGNED_BLOB sblob, MY_PRIV_KEY rkey, THEIR_PUB_KEY ukey);

MY_DECRYPTED_BLOB my_decrypt_check_blob(MY_ENCRYPTED_BLOB eblob, MY_PRIV_KEY rkey, THEIR_PUB_KEY ukey);

char* encode_signed_blob(size_t* enclen, MY_SIGNED_BLOB sblob);

char* encode_encrypted_blob(size_t* enclen, MY_ENCRYPTED_BLOB eblob);

MY_SIGNED_BLOB decode_signed_blob(size_t enclen, char* encsblob);

MY_ENCRYPTED_BLOB decode_encrypted_blob(size_t enclen, char* enceblob);

#endif

