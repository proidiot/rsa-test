#include "../../src/my-rsa.h"

#include <stdio.h>
#include <string.h>
#include <dejagnu.h>
#include <stdint.h>

int main()
{
	char* myprivkeyfile = "keys/mine.priv.pem";
	char* mypubkeyfile = "keys/mine.pub.pem";
	char* theirprivkeyfile = "keys/theirs.priv.pem";
	char* theirpubkeyfile = "keys/theirs.pub.pem";
	char* msg1 = "Hello there, my-rsa unit tests!";
	char* msg2 = "Hello, this is a different message.";
	size_t len1 = strlen(msg1) + 1;
	size_t len2 = strlen(msg2) + 1;
	size_t enclen = 0;
	size_t declen = 0;
	size_t i = 0;
	char* encmsg;
	char* decmsg;

	MY_PRIV_KEY myprivkey = get_my_priv_key(myprivkeyfile);
	if (myprivkey == NULL) {
		fail("unable to retrieve my priv key");
		exit(EXIT_FAILURE);
	} else {
		pass("able to retrieve my priv key");
	}
	THEIR_PUB_KEY mypubkey = get_their_pub_key(mypubkeyfile);
	if (mypubkey == NULL) {
		fail("unable to retrieve my pub key");
		exit(EXIT_FAILURE);
	} else {
		pass("able to retrieve my pub key");
	}

	MY_PRIV_KEY theirprivkey = get_my_priv_key(theirprivkeyfile);
	if (theirprivkey == NULL) {
		fail("unable to retrieve their priv key");
		exit(EXIT_FAILURE);
	} else {
		pass("able to retrieve their priv key");
	}
	THEIR_PUB_KEY theirpubkey = get_their_pub_key(theirpubkeyfile);
	if (theirpubkey == NULL) {
		fail("unable to retrieve their pub key");
		exit(EXIT_FAILURE);
	} else {
		pass("able to retrieve their pub key");
	}


	note("Message is: \"%s\"", msg1);

	MY_BLOB blob = (MY_BLOB)malloc(sizeof(struct MY_BLOB_STRUCT) + len1);
	if (blob == NULL) {
		fail("unable to allocate memory for blob");
		exit(EXIT_FAILURE);
	} else {
		pass("blob allocated");
	}
	blob->len = len1;
	memcpy(blob->data, msg1, len1);
	
	MY_SIGNED_BLOB sblob = my_sign_blob(blob, myprivkey);
	if (sblob == NULL) {
		fail("sblob was NULL");
		exit(EXIT_FAILURE);
	} else if (sblob->bloblen != len1) {
		fail("blob len was wrong");
		exit(EXIT_FAILURE);
	} else if (sblob->siglen <= 0) {
		fail("sig len was too small");
		exit(EXIT_FAILURE);
	} else if (strncmp(sblob->sigblobcombo + sblob->siglen, msg1, BUFSIZ) != 0) {
		fail("msg doesn't match: \"%s\"", sblob->sigblobcombo+sblob->siglen);
	} else {
		pass("sblob looks right");
	}


	if (my_check_blob(sblob, mypubkey)) {
		pass("signature check true positive");
	} else {
		fail("signature check false negative");
	}

	if (my_check_blob(sblob, theirpubkey)) {
		fail("signature check false positive");
	} else {
		pass("signature check true negative");
	}

	char* encsblob = encode_signed_blob(&enclen, sblob);
	if (encsblob == NULL) {
		fail("encsblob was NULL");
	} else if (enclen <= 0) {
		fail("encsblob was empty");
	} else if (strnlen(encsblob, BUFSIZ) >= BUFSIZ - 1) {
		fail("encsblob is longer than BUFSIZ (or else not a string)");
	} else {
		pass("encsblob is probably fine");
	}
	MY_SIGNED_BLOB dsblob = decode_signed_blob(enclen, encsblob);
	if (dsblob == NULL) {
		fail("dsblob was NULL");
	} else if (dsblob->siglen <= 0) {
		fail("dsblob's signature was empty");
	} else if (dsblob->bloblen <= 0) {
		fail("dsblob's data was empty");
	} else if (dsblob->siglen != sblob->siglen) {
		fail("dsblob signature length doesn't match sblob's");
	} else if (dsblob->bloblen != sblob->bloblen) {
		fail("dsblob data length doesn't match sblob's");
	} else if (memcmp(dsblob->sigblobcombo, sblob->sigblobcombo, dsblob->siglen + dsblob->bloblen) != 0) {
		note("differences between dsblob and sblob occur at:");
		char prev = '\0';
		for (i = 0; i < sblob->siglen + sblob->bloblen; i++) {
			if (*(sblob->sigblobcombo + i)
					!= *(dsblob->sigblobcombo + i)) {
				note(
					"offset: %d (%d mod 3) prev: %x sblob: %x dsblob: %x",
					(i + (2 * sizeof(uint32_t))),
					(i + (2 * sizeof(uint32_t))) % 3,
					prev,
					(char)(*(sblob->sigblobcombo + i)),
					(char)(*(dsblob->sigblobcombo + i)));
			}
			prev = *(sblob->sigblobcombo + i);
		}
		fail("dsblob data did not match sblob's");
	} else {
		pass("dsblob looks fine");
	}

	MY_ENCRYPTED_BLOB eblob1 = encrypt_blob(blob, mypubkey);
	if (eblob1 == NULL) {
		fail("eblob was NULL");
	} else if (eblob1->len <= blob->len) {
		fail("encrypted length should be longer");
	} else {
		pass("could be fine");
	}

	MY_ENCRYPTED_BLOB eblob2 = encrypt_blob(blob, mypubkey);
	if (eblob2 == NULL) {
		fail("eblob was NULL");
	} else if (eblob2->len <= blob->len) {
		fail("encrypted length should be longer");
	} else if (eblob1->len != eblob2->len) {
		fail("encrypted lengths don't match?");
	} else if (memcmp(eblob1->data, eblob2->data, eblob1->len) == 0) {
		fail("sequential encryptions are identical");
	} else {
		pass("encryption behaves securely as expected");
	}

	char* enceblob = encode_encrypted_blob(&enclen, eblob1);
	if (enceblob == NULL) {
		fail("enceblob was NULL");
	} else if (enclen <= 0) {
		fail("enceblob was empty");
	} else if (strnlen(enceblob, BUFSIZ) >= BUFSIZ - 1) {
		fail("enceblob is longer than BUFSIZ (or else not a string)");
	} else {
		pass("enceblob is probably fine");
	}
	MY_ENCRYPTED_BLOB deblob = decode_encrypted_blob(enclen, enceblob);
	if (deblob == NULL) {
		fail("deblob was NULL");
	} else if (deblob->len <= 0) {
		fail("deblob was empty");
	} else if (deblob->len != eblob1->len) {
		fail("deblob's length does not match eblob1's");
	} else if (memcmp(deblob->data, eblob1->data, eblob1->len) != 0) {
		note("differences between deblob and eblob1 occur at:");
		char prev = '\0';
		for (i = 0; i < eblob1->len; i++) {
			if (*(eblob1->data + i)
					!= *(deblob->data + i)) {
				note(
					"offset: %d (%d mod 3) prev: %x eblob1: %x deblob: %x",
					i, i % 3, prev,
					(char)(*(eblob1->data + i)),
					(char)(*(deblob->data + i)));
			}
			prev = *(eblob1->data + i);
		}
		fail("deblob's data does not match eblob1's");
	} else {
		pass("deblob matches eblob1");
	}


	MY_DECRYPTED_BLOB dblob = my_decrypt_blob(eblob1, myprivkey);
	if (dblob == NULL) {
		fail("dblob was NULL");
	} else if (dblob->len == 0) {
		fail("dblob is empty");
	} else if (strnlen(dblob->data, BUFSIZ) >= BUFSIZ - 1) {
		fail("dblob data may not be legit string");
	} else if (strncmp(dblob->data, blob->data, 2*blob->len) != 0) {
		fail("dblob data doesn't match: \"%s\"", dblob->data);
	} else {
		pass("dblob matches blob");
	}

	MY_DECRYPTED_BLOB gblob = my_decrypt_blob(eblob1, theirprivkey);
	if (gblob == NULL) {
		pass("gblob was NULL");
	} else if (gblob->len == 0) {
		pass("gblob is empty");
	} else if (strnlen(gblob->data, BUFSIZ) >= BUFSIZ - 1) {
		pass("gblob data may not be legit string");
	} else if (strncmp(gblob->data, blob->data, 2*blob->len) != 0) {
		pass("gblob data doesn't match: \"%s\"", dblob->data);
	} else {
		fail("gblob matches blob");
	}

	MY_SIGNED_BLOB seblob = my_sign_encrypt_blob(blob, myprivkey, theirpubkey);
	if (seblob == NULL) {
		fail("seblob was NULL");
	} else if (seblob->siglen <= 0) {
		fail("seblob signature was too short");
	} else if (seblob->bloblen <= blob->len) {
		fail("seblob data was too short");
	} else if (!my_check_blob(seblob, mypubkey)) {
		fail("seblob signature check false negative");
	} else if (my_check_blob(seblob, theirpubkey)) {
		fail("seblob signature check false positive");
	} else {
		pass("seblob looks good so far");
	}

	MY_DECRYPTED_BLOB cdblob = my_check_decrypt_blob(seblob, theirprivkey, mypubkey);
	if (cdblob == NULL) {
		fail("cdblob was NULL");
	} else if (cdblob->len == 0) {
		fail("cdblob is empty");
	} else if (strnlen(cdblob->data, BUFSIZ) >= BUFSIZ - 1) {
		fail("cdblob data may not be legit string");
	} else if (strncmp(cdblob->data, blob->data, 2*blob->len) != 0) {
		fail("cdblob data doesn't match: \"%s\"", cdblob->data);
	} else {
		pass("cdblob matches blob");
	}

	MY_ENCRYPTED_BLOB esblob = my_encrypt_sign_blob(blob, myprivkey, theirpubkey);
	if (esblob == NULL) {
		fail("esblob was NULL");
	} else if (esblob->len <= blob->len) {
		fail("esblob data was too short");
	} else {
		pass("esblob could be fine");
	}

	MY_DECRYPTED_BLOB dcblob = my_decrypt_check_blob(esblob, theirprivkey, mypubkey);
	if (dcblob == NULL) {
		fail("dcblob was NULL");
	} else if (dcblob->len <= 0) {
		fail("dcblob was empty");
	} else if (strnlen(dcblob->data, BUFSIZ) >= BUFSIZ - 1) {
		fail("dcblob data may not be legit string");
	} else if (strncmp(dcblob->data, blob->data, 2*blob->len) != 0) {
		fail("dcblob data doesn't match: \"%s\"", dcblob->data);
	} else {
		pass("dcblob matches blob");
	}


	free(blob);
	free(sblob);
	free(encsblob);
	free(dsblob);
	free(eblob1);
	free(eblob2);
	free(enceblob);
	free(deblob);
	free(dblob);
	free(gblob);
	free(seblob);
	free(cdblob);
	free(esblob);
	free(dcblob);

	totals();
	return 0;
}


