/*
 * Copyright 2026 ZoeyJF
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef	SHA3_H
#define	SHA3_H

#include <stddef.h>
#include <stdint.h>

struct sha3 {
	uint64_t A[25];
	unsigned nb;		/* number of bytes remaining to fill buffer */
};

typedef struct { struct sha3 C224; } SHA3_224_CTX;
typedef struct { struct sha3 C256; } SHA3_256_CTX;
typedef struct { struct sha3 C384; } SHA3_384_CTX;
typedef struct { struct sha3 C512; } SHA3_512_CTX;
typedef struct { struct sha3 C128; } SHAKE128_CTX;
typedef struct { struct sha3 C256; } SHAKE256_CTX;

#define	SHA3_224_DIGEST_LENGTH	28
#define	SHA3_256_DIGEST_LENGTH	32
#define	SHA3_384_DIGEST_LENGTH	48
#define	SHA3_512_DIGEST_LENGTH	64

void	SHA3_224_Init(SHA3_224_CTX *);
void	SHA3_224_Update(SHA3_224_CTX *, const uint8_t *, size_t);
void	SHA3_224_Final(uint8_t[SHA3_224_DIGEST_LENGTH], SHA3_224_CTX *);

void	SHA3_256_Init(SHA3_256_CTX *);
void	SHA3_256_Update(SHA3_256_CTX *, const uint8_t *, size_t);
void	SHA3_256_Final(uint8_t[SHA3_256_DIGEST_LENGTH], SHA3_256_CTX *);

void	SHA3_384_Init(SHA3_384_CTX *);
void	SHA3_384_Update(SHA3_384_CTX *, const uint8_t *, size_t);
void	SHA3_384_Final(uint8_t[SHA3_384_DIGEST_LENGTH], SHA3_384_CTX *);

void	SHA3_512_Init(SHA3_512_CTX *);
void	SHA3_512_Update(SHA3_512_CTX *, const uint8_t *, size_t);
void	SHA3_512_Final(uint8_t[SHA3_512_DIGEST_LENGTH], SHA3_512_CTX *);

void	SHAKE128_Init(SHAKE128_CTX *);
void	SHAKE128_Update(SHAKE128_CTX *, const uint8_t *, size_t);
void	SHAKE128_Final(uint8_t *, size_t, SHAKE128_CTX *);

void	SHAKE256_Init(SHAKE256_CTX *);
void	SHAKE256_Update(SHAKE256_CTX *, const uint8_t *, size_t);
void	SHAKE256_Final(uint8_t *, size_t, SHAKE256_CTX *);

#define KECCAK_256_Init SHA3_256_Init
#define KECCAK_256_Update SHA3_256_Update
void	KECCAK_256_Final(uint8_t[SHA3_256_DIGEST_LENGTH], SHA3_256_CTX *);

#define KECCAK_384_Init SHA3_384_Init
#define KECCAK_384_Update SHA3_384_Update
void	KECCAK_384_Final(uint8_t[SHA3_384_DIGEST_LENGTH], SHA3_384_CTX *);

#define KECCAK_512_Init SHA3_512_Init
#define KECCAK_512_Update SHA3_512_Update
void	KECCAK_512_Final(uint8_t[SHA3_512_DIGEST_LENGTH], SHA3_512_CTX *);

int	SHA3_Selftest(void);

#endif	/* SHA3_H */
