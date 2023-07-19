/*
Copyright (c) 2017. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#pragma once

#define SHA256_LEN 32

#include <wincrypt.h>
#include <windows.h>

HCRYPTPROV cryptprov;

typedef HCRYPTHASH sha256_ctx;

#define sha256_init(ctx)                                          \
  CryptAcquireContext(                                            \
      &cryptprov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT); \
  CryptCreateHash(cryptprov, CALG_SHA_256, 0, 0, ctx);

#define sha256_update(ctx, data, len) \
  CryptHashData(*ctx, (const BYTE*) data, len, 0)

#define sha256_final(digest, ctx)                         \
  {                                                       \
    DWORD len = SHA256_LEN;                               \
    CryptGetHashParam(*ctx, HP_HASHVAL, digest, &len, 0); \
    CryptDestroyHash(*ctx);                               \
  }
