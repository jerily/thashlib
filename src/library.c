/* Copyright (c) 2026 Neofytos Dimitriou <neo@jerily.cy>
 * SPDX-License-Identifier: MIT
 */
#include "library.h"
#include <limits.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifndef TCL_SIZE_MAX
#undef Tcl_Size
typedef int Tcl_Size;
#define TCL_SIZE_MAX INT_MAX
#define Tcl_GetSizeIntFromObj Tcl_GetIntFromObj
#endif

static int OpenSSLError(Tcl_Interp *interp, const char *operation) {
    unsigned long code = ERR_get_error();
    char detail[256];
    ERR_error_string_n(code, detail, sizeof(detail));
    Tcl_SetObjResult(interp, Tcl_ObjPrintf("%s failed: %s", operation, detail));
    Tcl_SetErrorCode(interp, "THASHLIB", "OPENSSL", NULL);
    ERR_clear_error();
    return TCL_ERROR;
}

/* Convert bytes to a fresh result object; shared by hashes and hex_encode. */
static int BytesResult(Tcl_Interp *interp, const unsigned char *bytes, Tcl_Size length, int hexOutput) {
    if (!hexOutput) {
        Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(bytes, length));
        return TCL_OK;
    }
    if (length > (TCL_SIZE_MAX - 1) / 2) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("hex output exceeds Tcl's size limit", -1));
        Tcl_SetErrorCode(interp, "THASHLIB", "LENGTH", NULL);
        return TCL_ERROR;
    }
    Tcl_Obj *result = Tcl_NewObj();
    Tcl_IncrRefCount(result);
    Tcl_SetObjLength(result, length * 2);
    ERR_clear_error();
    if (length && !OPENSSL_buf2hexstr_ex(Tcl_GetString(result), (size_t)length * 2 + 1,
            NULL, bytes, (size_t)length, '\0')) {
        Tcl_DecrRefCount(result);
        return OpenSSLError(interp, "hex_encode");
    }
    char *hex = Tcl_GetString(result);
    for (Tcl_Size i = 0; i < length * 2; ++i) {
        if (hex[i] >= 'A' && hex[i] <= 'F') hex[i] += 'a' - 'A';
    }
    Tcl_SetObjResult(interp, result);
    Tcl_DecrRefCount(result);
    return TCL_OK;
}

static int DigestCmd(ClientData data, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    int hexOutput = objc == 3 && strcmp(Tcl_GetString(objv[1]), "-hex") == 0;
    if (objc != 2 && !hexOutput) {
        Tcl_WrongNumArgs(interp, 1, objv, "?-hex? bytes");
        return TCL_ERROR;
    }
    Tcl_Size length;
    const unsigned char *bytes = Tcl_GetByteArrayFromObj(objv[objc - 1], &length);
    unsigned char digest[EVP_MAX_MD_SIZE];
    size_t digestLength;
    ERR_clear_error();
    if (!EVP_Q_digest(NULL, (const char *)data, NULL, bytes, (size_t)length, digest, &digestLength)) {
        return OpenSSLError(interp, (const char *)data);
    }
    return BytesResult(interp, digest, (Tcl_Size)digestLength, hexOutput);
}

static int HmacCmd(ClientData data, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)data;
    int hexOutput = objc == 4 && strcmp(Tcl_GetString(objv[1]), "-hex") == 0;
    if (objc != 3 && !hexOutput) {
        Tcl_WrongNumArgs(interp, 1, objv, "?-hex? key bytes");
        return TCL_ERROR;
    }
    Tcl_Size keyLength, length;
    const unsigned char *key = Tcl_GetByteArrayFromObj(objv[objc - 2], &keyLength);
    const unsigned char *bytes = Tcl_GetByteArrayFromObj(objv[objc - 1], &length);
    unsigned char digest[32];
    size_t digestLength;
    ERR_clear_error();
    if (!EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL,
            keyLength ? key : (const unsigned char *)"", (size_t)keyLength,
            bytes, (size_t)length, digest, sizeof(digest), &digestLength)) {
        return OpenSSLError(interp, "HMAC-SHA256");
    }
    int status = BytesResult(interp, digest, (Tcl_Size)digestLength, hexOutput);
    OPENSSL_cleanse(digest, sizeof(digest));
    return status;
}

static int RandomCmd(ClientData data, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)data;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "num_bytes");
        return TCL_ERROR;
    }
    Tcl_Size length;
    if (Tcl_GetSizeIntFromObj(interp, objv[1], &length) != TCL_OK || length < 0) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("num_bytes must be an integer >= 0 within Tcl's size limit", -1));
        Tcl_SetErrorCode(interp, "THASHLIB", "LENGTH", NULL);
        return TCL_ERROR;
    }
    Tcl_Obj *result = Tcl_NewByteArrayObj(NULL, length);
    Tcl_IncrRefCount(result);
    unsigned char *bytes = Tcl_GetByteArrayFromObj(result, NULL);
    ERR_clear_error();
    if (length && RAND_bytes_ex(NULL, bytes, (size_t)length, 0) != 1) {
        OPENSSL_cleanse(bytes, (size_t)length);
        Tcl_DecrRefCount(result);
        return OpenSSLError(interp, "random_bytes");
    }
    Tcl_SetObjResult(interp, result);
    Tcl_DecrRefCount(result);
    return TCL_OK;
}

static int HexEncodeCmd(ClientData data, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)data;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "bytes");
        return TCL_ERROR;
    }
    Tcl_Size length;
    const unsigned char *bytes = Tcl_GetByteArrayFromObj(objv[1], &length);
    return BytesResult(interp, bytes, length, 1);
}

static int HexDecodeCmd(ClientData data, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)data;
    if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "hex_encoded_string");
        return TCL_ERROR;
    }
    Tcl_Size length;
    const char *hex = Tcl_GetStringFromObj(objv[1], &length);
    /* Validate the full Tcl string, including embedded NULs, before passing it
     * to OpenSSL's NUL-terminated string API. */
    int valid = (length % 2 == 0);
    for (Tcl_Size i = 0; valid && i < length; ++i) {
        valid = OPENSSL_hexchar2int((unsigned char)hex[i]) >= 0;
    }
    if (!valid) {
        Tcl_SetObjResult(interp, Tcl_NewStringObj("expected an even number of hexadecimal digits", -1));
        Tcl_SetErrorCode(interp, "THASHLIB", "HEX", NULL);
        return TCL_ERROR;
    }
    Tcl_Obj *result = Tcl_NewByteArrayObj(NULL, length / 2);
    Tcl_IncrRefCount(result);
    unsigned char *bytes = Tcl_GetByteArrayFromObj(result, NULL);
    ERR_clear_error();
    if (length && !OPENSSL_hexstr2buf_ex(bytes, (size_t)length / 2, NULL, hex, '\0')) {
        Tcl_DecrRefCount(result);
        return OpenSSLError(interp, "hex_decode");
    }
    Tcl_SetObjResult(interp, result);
    Tcl_DecrRefCount(result);
    return TCL_OK;
}

static int ConstantTimeEqualCmd(ClientData data, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[]) {
    (void)data;
    if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "bytes1 bytes2");
        return TCL_ERROR;
    }
    Tcl_Size alen, blen;
    const unsigned char *a = Tcl_GetByteArrayFromObj(objv[1], &alen);
    const unsigned char *b = Tcl_GetByteArrayFromObj(objv[2], &blen);
    Tcl_SetObjResult(interp, Tcl_NewBooleanObj(alen == blen &&
        (alen == 0 || CRYPTO_memcmp(a, b, (size_t)alen) == 0)));
    return TCL_OK;
}

int Thashlib_Init(Tcl_Interp *interp) {
#if TCL_MAJOR_VERSION >= 9
    const char *minimum = "9.0";
#else
    const char *minimum = "8.6";
#endif
    if (Tcl_InitStubs(interp, minimum, 0) == NULL) return TCL_ERROR;
    if (Tcl_CreateNamespace(interp, "::thashlib", NULL, NULL) == NULL) return TCL_ERROR;
    Tcl_CreateObjCommand(interp, "::thashlib::sha1", DigestCmd, (ClientData)"SHA1", NULL);
    Tcl_CreateObjCommand(interp, "::thashlib::sha256", DigestCmd, (ClientData)"SHA256", NULL);
    Tcl_CreateObjCommand(interp, "::thashlib::sha384", DigestCmd, (ClientData)"SHA384", NULL);
    Tcl_CreateObjCommand(interp, "::thashlib::sha512", DigestCmd, (ClientData)"SHA512", NULL);
    Tcl_CreateObjCommand(interp, "::thashlib::md5", DigestCmd, (ClientData)"MD5", NULL);
    Tcl_CreateObjCommand(interp, "::thashlib::hmac_sha256", HmacCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::thashlib::random_bytes", RandomCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::thashlib::constant_time_equal", ConstantTimeEqualCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::thashlib::hex_encode", HexEncodeCmd, NULL, NULL);
    Tcl_CreateObjCommand(interp, "::thashlib::hex_decode", HexDecodeCmd, NULL, NULL);
    return Tcl_PkgProvide(interp, "thashlib", THASHLIB_VERSION);
}
