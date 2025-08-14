/**
 * @file cert_utils.h
 * @brief Certificate utilities for testing TLS server functionality
 */
#ifndef CERT_UTILS_H
#define CERT_UTILS_H

#include <openssl/ssl.h>
#include <openssl/x509.h>

/**
 * Generate a self-signed certificate and private key for testing
 * @param cert_file Path to write the certificate file
 * @param key_file Path to write the private key file
 * @return 0 on success, -1 on failure
 */
int cert_generate_self_signed(const char* cert_file, const char* key_file);

#endif // CERT_UTILS_H
