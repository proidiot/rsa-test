#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>

char* base64_encode(size_t* enclen, size_t len, unsigned char* data);

unsigned char* base64_decode(size_t* declen, size_t len, char* data);

#endif

