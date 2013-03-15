#include "my-rsa.h"

#include "base64.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <endian.h>

#define sztou32(x) ((uint32_t)(((size_t)(x)) % 4294967296))
#define u32tosz(x) ((size_t)(((uint32_t)(x)) + (size_t)0))
#define min(x,y) (((x)>(y))?(y):(x))

MY_PRIV_KEY get_my_priv_key(const char* privfile)
{
	/*
	EVP_PKEY* privkey = ReadPrivateKey(privfile);
	if (!privkey) {
		return (MY_PRIV_KEY)NULL;
	} else {
		return (MY_PRIV_KEY)(privkey->pkey.rsa);
	}
	*/

	RSA* key;

	FILE* fp = fopen(privfile, "r");
	if (fp == NULL) {
		return (MY_PRIV_KEY)NULL;
	}

	key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (key == NULL) {
		ERR_print_errors_fp(stderr);
		return (MY_PRIV_KEY)NULL;
	} else {
		return (MY_PRIV_KEY)key;
	}
}

THEIR_PUB_KEY get_their_pub_key(const char* pubfile)
{
	/*
	EVP_PKEY* pubkey = ReadPublicKey(pubfile);
	if (!pubkey) {
		return (THEIR_PUB_KEY)NULL;
	} else {
		return (THEIR_PUB_KEY)(pubkey->pkey.rsa);
	}
	*/
	RSA* key;

	FILE* fp = fopen(pubfile, "r");
	if (fp == NULL) {
		return (THEIR_PUB_KEY)NULL;
	}

	key = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);
	if (key == NULL) {
		ERR_print_errors_fp(stderr);
		return (THEIR_PUB_KEY)NULL;
	} else {
		return (THEIR_PUB_KEY)key;
	}
}

MY_SIGNED_BLOB my_sign_blob(MY_BLOB blob, MY_PRIV_KEY rkey)
{
	size_t MY_RSA_SIZ = (size_t)RSA_size((RSA*)rkey);
	MY_SIGNED_BLOB sblob;
	unsigned int tsiglen;
	int ret;

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256_ctx;
	SHA256_Init(&sha256_ctx);
	SHA256_Update(&sha256_ctx, blob->data, blob->len);
	SHA256_Final(hash, &sha256_ctx);

	sblob = (MY_SIGNED_BLOB)malloc(
		sizeof(struct MY_SIGNED_BLOB_STRUCT) + MY_RSA_SIZ + blob->len);
	if (sblob == NULL) {
		return (MY_SIGNED_BLOB)NULL;
	}

	ret = RSA_sign(
		NID_sha256,
		hash,
		SHA256_DIGEST_LENGTH,
		sblob->sigblobcombo,
		&tsiglen,
		(RSA*)rkey);
	sblob->siglen = tsiglen;
	if (ret != 1) {
		free(sblob);
		return (MY_SIGNED_BLOB)NULL;
	} else if (sblob->siglen > MY_RSA_SIZ) {
		MY_SIGNED_BLOB temp = sblob;
		/* Looks like we underestimated how much memory we needed. */
		sblob = (MY_SIGNED_BLOB)malloc(
			sizeof(struct MY_SIGNED_BLOB_STRUCT) + temp->siglen
				+ blob->len);
		if (sblob == NULL) {
			free(temp);
			return (MY_SIGNED_BLOB)NULL;
		}
		sblob->siglen = temp->siglen;
		memmove(
			sblob->sigblobcombo,
			temp->sigblobcombo,
			sblob->siglen);
		free(temp);
	}

	sblob->bloblen = blob->len;
	memcpy(sblob->sigblobcombo + sblob->siglen, blob->data, blob->len);

	return sblob;
}

MY_BLOB blobify_signed_blob(MY_SIGNED_BLOB sblob)
{
	uint32_t siglen;
	uint32_t bloblen;
	MY_BLOB blob = (MY_BLOB)malloc(
		sizeof(struct MY_BLOB_STRUCT) + (2 * sizeof(uint32_t))
			+ sblob->siglen + sblob->bloblen);
	if (blob == NULL) {
		return (MY_BLOB)NULL;
	}
	blob->len = (2 * sizeof(uint32_t)) + sblob->siglen + sblob->bloblen;
	siglen = htobe32(sztou32(sblob->siglen));
	bloblen = htobe32(sztou32(sblob->bloblen));
	memcpy(blob->data, &siglen, sizeof(uint32_t));
	memcpy(blob->data + sizeof(uint32_t), &bloblen, sizeof(uint32_t));
	memcpy(
		blob->data + (2 * sizeof(uint32_t)),
		sblob->sigblobcombo,
		sblob->siglen + sblob->bloblen);
	return blob;
}

MY_SIGNED_BLOB deblobify_signed_blob(size_t len, unsigned char* data)
{
	uint32_t siglen;
	uint32_t bloblen;
	MY_SIGNED_BLOB sblob = (MY_SIGNED_BLOB)malloc(
		sizeof(struct MY_SIGNED_BLOB_STRUCT) + len
			- (2 * sizeof(uint32_t)));
	if (sblob == NULL) {
		return (MY_SIGNED_BLOB)NULL;
	}
	memcpy(&siglen, data, sizeof(uint32_t));
	memcpy(&bloblen, data + sizeof(uint32_t), sizeof(uint32_t));
	sblob->siglen = u32tosz(be32toh(siglen));
	sblob->bloblen = u32tosz(be32toh(bloblen));
	memcpy(
		sblob->sigblobcombo,
		data + (2 * sizeof(uint32_t)),
		sblob->siglen + sblob->bloblen);
	return sblob;
}

MY_ENCRYPTED_BLOB encrypt_blob(MY_BLOB blob, THEIR_PUB_KEY ukey)
{
	size_t MY_RSA_SIZ = RSA_size((RSA*)ukey);
	/* In order to leave room for random padding, we define the usable size
	   to be some amount that is smaller than the RSA size. */
	size_t MY_USABLE_SIZ = MY_RSA_SIZ
		- ceil(MY_RSA_SIZ * MY_OAEP_PADDING_RATIO)
		- MY_OAEP_PADDING_ADDITIONAL_BYTES;
	unsigned int chunks = ceil(blob->len / (1.0 * MY_USABLE_SIZ));
	size_t MY_ENCRYPTED_SIZ = chunks * MY_RSA_SIZ;
	int i = 0;
	MY_ENCRYPTED_BLOB eblob = (MY_ENCRYPTED_BLOB)malloc(
		sizeof(struct MY_BLOB_STRUCT) + MY_ENCRYPTED_SIZ);
	if (eblob == NULL) {
		return (MY_ENCRYPTED_BLOB)NULL;
	}
	for (i = 0; i < chunks; i++) {
		size_t actualsiz = min(
			MY_USABLE_SIZ, 
			blob->len - (i * MY_USABLE_SIZ));
		int ret = RSA_public_encrypt(
			actualsiz, 
			blob->data + (i * MY_USABLE_SIZ),
			eblob->data + (i * MY_RSA_SIZ),
			(RSA*)ukey,
			RSA_PKCS1_OAEP_PADDING);
		if (ret != MY_RSA_SIZ) {
			free(eblob);
			return (MY_ENCRYPTED_BLOB)NULL;
		}
	}
	eblob->len = MY_ENCRYPTED_SIZ;
	return eblob;
}

MY_SIGNED_BLOB my_sign_encrypt_blob(
	MY_BLOB blob,
	MY_PRIV_KEY rkey,
	THEIR_PUB_KEY ukey)
{
	MY_ENCRYPTED_BLOB eblob = encrypt_blob(blob, ukey);

	if (eblob == NULL) {
		return (MY_SIGNED_BLOB)NULL;
	} else if (eblob->len <= 0) {
		free(eblob);
		return (MY_SIGNED_BLOB)NULL;
	} else {
		MY_SIGNED_BLOB sblob = my_sign_blob(eblob, rkey);
		free(eblob);
		return sblob;
	}
}

MY_ENCRYPTED_BLOB my_encrypt_sign_blob(
	MY_BLOB blob,
	MY_PRIV_KEY rkey,
	THEIR_PUB_KEY ukey)
{
	MY_SIGNED_BLOB sblob = my_sign_blob(blob, rkey);
	if (sblob == NULL) {
		return (MY_ENCRYPTED_BLOB)NULL;
	} else if (sblob->siglen <= 0 || sblob->bloblen <= 0) {
		free(sblob);
		return (MY_ENCRYPTED_BLOB)NULL;
	} else {
		MY_DECRYPTED_BLOB dblob = blobify_signed_blob(sblob);
		MY_ENCRYPTED_BLOB eblob;
		free(sblob);
		eblob = encrypt_blob(dblob, ukey);
		free(dblob);
		return eblob;
	}
}

int my_check_blob(MY_SIGNED_BLOB sblob, THEIR_PUB_KEY ukey)
{
	int ret = 0;

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256_ctx;
	SHA256_Init(&sha256_ctx);
	SHA256_Update(
		&sha256_ctx,
		sblob->sigblobcombo + sblob->siglen,
		sblob->bloblen);
	SHA256_Final(hash, &sha256_ctx);

	ret = RSA_verify(
		NID_sha256,
		hash,
		SHA256_DIGEST_LENGTH,
		sblob->sigblobcombo,
		sblob->siglen,
		(RSA*)ukey);

	return ret == 1;
}

MY_DECRYPTED_BLOB my_decrypt_blob_internal(
	size_t ebloblen,
	unsigned char* eblobdata,
	MY_PRIV_KEY rkey)
{
	MY_DECRYPTED_BLOB dblob;
	int i = 0;

	size_t MY_RSA_SIZ = RSA_size((RSA*)rkey);
	if (ebloblen % MY_RSA_SIZ != 0) {
		return (MY_DECRYPTED_BLOB)NULL;
	}

	/* It's hard to say just how much less memory we need without knowing
	   exactly how much padding was used, but as it is not necessary to
	   require an exact amount of padding, we should not do so. */
	dblob = (MY_DECRYPTED_BLOB)malloc(
		sizeof(struct MY_BLOB_STRUCT) + ebloblen);
	if (dblob == NULL) {
		return (MY_DECRYPTED_BLOB)NULL;
	} else {
		dblob->len = 0;
	}

	for (i = 0; i * MY_RSA_SIZ < ebloblen; i++) {
		int ret = RSA_private_decrypt(
			MY_RSA_SIZ,
			eblobdata + (i * MY_RSA_SIZ),
			dblob->data + dblob->len,
			(RSA*)rkey,
			RSA_PKCS1_OAEP_PADDING);
		if (ret <= 0) {
			free(dblob);
			return (MY_DECRYPTED_BLOB)NULL;
		}
		dblob->len += ret;
	}

	dblob = realloc(dblob, sizeof(struct MY_BLOB_STRUCT) + dblob->len);
	return dblob;
}

MY_DECRYPTED_BLOB my_decrypt_blob(MY_ENCRYPTED_BLOB eblob, MY_PRIV_KEY rkey)
{
	return my_decrypt_blob_internal(eblob->len, eblob->data, rkey);
}

MY_DECRYPTED_BLOB my_check_decrypt_blob(
	MY_SIGNED_BLOB sblob,
	MY_PRIV_KEY rkey,
	THEIR_PUB_KEY ukey)
{
	if (!my_check_blob(sblob, ukey)) {
		return (MY_DECRYPTED_BLOB)NULL;
	} else {
		return my_decrypt_blob_internal(
			sblob->bloblen,
			sblob->sigblobcombo + sblob->siglen,
			rkey);
	}
}

MY_DECRYPTED_BLOB my_decrypt_check_blob(
	MY_ENCRYPTED_BLOB eblob,
	MY_PRIV_KEY rkey,
	THEIR_PUB_KEY ukey)
{
	MY_DECRYPTED_BLOB dsblob = my_decrypt_blob(eblob, rkey);
	if (dsblob == NULL) {
		return (MY_DECRYPTED_BLOB)NULL;
	} else if (dsblob->len <= 0) {
		free(dsblob);
		return (MY_DECRYPTED_BLOB)NULL;
	} else {
		MY_SIGNED_BLOB sblob = deblobify_signed_blob(
			dsblob->len,
			dsblob->data);
		free(dsblob);
		if (!my_check_blob(sblob, ukey)) {
			free(sblob);
			return (MY_DECRYPTED_BLOB)NULL;
		} else {
			MY_DECRYPTED_BLOB dblob = (MY_DECRYPTED_BLOB)malloc(
				sizeof(struct MY_BLOB_STRUCT)
					+ sblob->bloblen);
			if (dblob == NULL) {
				free(sblob);
				return (MY_DECRYPTED_BLOB)NULL;
			}
			dblob->len = sblob->bloblen;
			memcpy(
				dblob->data,
				sblob->sigblobcombo + sblob->siglen,
				dblob->len);
			free(sblob);
			return dblob;
		}
	}
}


char* encode_signed_blob(size_t* enclen, MY_SIGNED_BLOB sblob)
{
	MY_BLOB blob = blobify_signed_blob(sblob);
	char* encsblob = base64_encode(enclen, blob->len, blob->data);
	free(blob);
	return encsblob;
}

MY_SIGNED_BLOB decode_signed_blob(size_t enclen, char* encsblob)
{
	size_t len = 0;
	unsigned char* data = base64_decode(&len, enclen, encsblob);
	MY_SIGNED_BLOB sblob = deblobify_signed_blob(len, data);
	free(data);
	return sblob;
}

char* encode_encrypted_blob(size_t* enclen, MY_ENCRYPTED_BLOB eblob)
{
	return base64_encode(enclen, eblob->len, eblob->data);
}

MY_ENCRYPTED_BLOB decode_encrypted_blob(size_t enclen, char* enceblob)
{
	size_t len = 0;
	unsigned char* data = base64_decode(&len, enclen, enceblob);
	MY_ENCRYPTED_BLOB eblob = (MY_ENCRYPTED_BLOB)malloc(
		sizeof(struct MY_BLOB_STRUCT) + len);
	if (eblob == NULL) {
		return (MY_ENCRYPTED_BLOB)NULL;
	}
	eblob->len = len;
	memcpy(eblob->data, data, len);
	free(data);
	return eblob;
}

