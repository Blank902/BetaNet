/**
 * @file cert_utils.c
 * @brief Certificate utilities for testing TLS server functionality
 */
#ifdef _WIN32
#include <openssl/applink.c>  // Fix for Windows APPLINK issue
#endif

#include "cert_utils.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

/**
 * Generate a self-signed certificate and private key for testing
 */
int cert_generate_self_signed(const char* cert_file, const char* key_file) {
    if (!cert_file || !key_file) return -1;
    
    // Generate RSA key pair
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return -1;
    
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) goto err;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto err;
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
    
    // Create X509 certificate
    X509 *x509 = X509_new();
    if (!x509) goto err;
    
    // Set version, serial number, and validity period
    X509_set_version(x509, 2); // X509v3
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 365 * 24 * 3600); // 1 year
    
    // Set public key
    X509_set_pubkey(x509, pkey);
    
    // Set subject and issuer (same for self-signed)
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"BetaNet Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    
    // Add Subject Alternative Names
    X509_EXTENSION *ext = NULL;
    X509V3_CTX v3ctx;
    X509V3_set_ctx(&v3ctx, x509, x509, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1");
    if (ext) {
        X509_add_ext(x509, ext, -1);
        X509_EXTENSION_free(ext);
    }
    
    // Sign the certificate
    if (!X509_sign(x509, pkey, EVP_sha256())) goto err;
    
    // Write private key to file
    FILE *key_fp = fopen(key_file, "wb");
    if (!key_fp) goto err;
    if (!PEM_write_PrivateKey(key_fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        fclose(key_fp);
        goto err;
    }
    fclose(key_fp);
    
    // Write certificate to file
    FILE *cert_fp = fopen(cert_file, "wb");
    if (!cert_fp) goto err;
    if (!PEM_write_X509(cert_fp, x509)) {
        fclose(cert_fp);
        goto err;
    }
    fclose(cert_fp);
    
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return 0;
    
err:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (x509) X509_free(x509);
    return -1;
}
