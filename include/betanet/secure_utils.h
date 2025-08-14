#ifndef BETANET_SECURE_UTILS_H
#define BETANET_SECURE_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Secure Buffer Operations
// =============================================================================

/**
 * @brief Secure memory copy with bounds checking
 * @param dest Destination buffer
 * @param dest_size Size of destination buffer
 * @param src Source buffer  
 * @param src_size Number of bytes to copy
 * @return 0 on success, -1 on error
 */
int secure_memcpy(void* dest, size_t dest_size, const void* src, size_t src_size);

/**
 * @brief Secure memory set with bounds checking
 * @param dest Destination buffer
 * @param value Value to set (0-255)
 * @param size Number of bytes to set
 * @return 0 on success, -1 on error
 */
int secure_memset(void* dest, int value, size_t size);

/**
 * @brief Secure string copy with bounds checking and null termination
 * @param dest Destination buffer
 * @param dest_size Size of destination buffer (including null terminator)
 * @param src Source string
 * @return 0 on success, -1 on error
 */
int secure_strcpy(char* dest, size_t dest_size, const char* src);

/**
 * @brief Secure bounded string copy with length limit
 * @param dest Destination buffer
 * @param dest_size Size of destination buffer
 * @param src Source string
 * @param max_copy Maximum number of characters to copy (excluding null terminator)
 * @return 0 on success, -1 on error
 */
int secure_strncpy(char* dest, size_t dest_size, const char* src, size_t max_copy);

/**
 * @brief Secure formatted string print with bounds checking
 * @param dest Destination buffer
 * @param dest_size Size of destination buffer
 * @param format Format string
 * @param ... Format arguments
 * @return Number of characters written (excluding null terminator), -1 on error
 */
int secure_snprintf(char* dest, size_t dest_size, const char* format, ...);

/**
 * @brief Secure string concatenation with bounds checking
 * @param dest Destination buffer (must contain valid null-terminated string)
 * @param dest_size Total size of destination buffer
 * @param src Source string to append
 * @return 0 on success, -1 on error
 */
int secure_strcat(char* dest, size_t dest_size, const char* src);

// =============================================================================
// Input Validation
// =============================================================================

/**
 * @brief Validate buffer parameters for safety
 * @param ptr Buffer pointer
 * @param size Buffer size
 * @param min_size Minimum required size
 * @param max_size Maximum allowed size
 * @return true if valid, false otherwise
 */
bool validate_buffer(const void* ptr, size_t size, size_t min_size, size_t max_size);

/**
 * @brief Validate string length and null termination
 * @param str String to validate
 * @param max_len Maximum allowed length (including null terminator)
 * @return true if valid, false otherwise
 */
bool validate_string(const char* str, size_t max_len);

/**
 * @brief Check if string is properly null-terminated within buffer
 * @param buffer Buffer containing string
 * @param buffer_size Size of buffer
 * @return true if properly terminated, false otherwise
 */
bool is_null_terminated(const char* buffer, size_t buffer_size);

// =============================================================================
// Memory Safety Utilities
// =============================================================================

/**
 * @brief Safe buffer structure for bounds-checked operations
 */
typedef struct {
    void* data;          /**< Buffer data pointer */
    size_t size;         /**< Current data size */
    size_t capacity;     /**< Total buffer capacity */
    bool is_valid;       /**< Buffer validity flag */
} secure_buffer_t;

/**
 * @brief Initialize a secure buffer
 * @param buffer Buffer structure to initialize
 * @param data Data pointer
 * @param capacity Buffer capacity
 * @return 0 on success, -1 on error
 */
int secure_buffer_init(secure_buffer_t* buffer, void* data, size_t capacity);

/**
 * @brief Copy data to secure buffer with bounds checking
 * @param buffer Destination buffer
 * @param src Source data
 * @param src_size Size of source data
 * @return 0 on success, -1 on error
 */
int secure_buffer_copy(secure_buffer_t* buffer, const void* src, size_t src_size);

/**
 * @brief Append data to secure buffer with bounds checking
 * @param buffer Destination buffer
 * @param src Source data
 * @param src_size Size of source data
 * @return 0 on success, -1 on error
 */
int secure_buffer_append(secure_buffer_t* buffer, const void* src, size_t src_size);

/**
 * @brief Clear and invalidate secure buffer
 * @param buffer Buffer to clear
 */
void secure_buffer_clear(secure_buffer_t* buffer);

// =============================================================================
// Error Handling
// =============================================================================

/**
 * @brief Security error codes
 */
typedef enum {
    SECURE_ERROR_NONE = 0,
    SECURE_ERROR_NULL_POINTER = -1,
    SECURE_ERROR_BUFFER_TOO_SMALL = -2,
    SECURE_ERROR_INVALID_SIZE = -3,
    SECURE_ERROR_NOT_NULL_TERMINATED = -4,
    SECURE_ERROR_STRING_TOO_LONG = -5,
    SECURE_ERROR_INVALID_FORMAT = -6
} secure_error_t;

/**
 * @brief Get human-readable error message
 * @param error Error code
 * @return Error message string
 */
const char* secure_error_message(secure_error_t error);

// =============================================================================
// Macros for Common Operations
// =============================================================================

/**
 * @brief Safe memory copy with compile-time size checking for arrays
 */
#define SAFE_MEMCPY(dest, src, size) \
    secure_memcpy((dest), sizeof(dest), (src), (size))

/**
 * @brief Safe string copy with compile-time size checking for arrays
 */
#define SAFE_STRCPY(dest, src) \
    secure_strcpy((dest), sizeof(dest), (src))

/**
 * @brief Safe string concatenation with compile-time size checking
 */
#define SAFE_STRCAT(dest, src) \
    secure_strcat((dest), sizeof(dest), (src))

/**
 * @brief Validate pointer and size parameters
 */
#define VALIDATE_PARAMS(ptr, size) \
    do { \
        if (!(ptr) || (size) == 0) return SECURE_ERROR_NULL_POINTER; \
        if ((size) > SECURE_MAX_BUFFER_SIZE) return SECURE_ERROR_INVALID_SIZE; \
    } while(0)

/**
 * @brief Maximum safe buffer size (1MB)
 */
#define SECURE_MAX_BUFFER_SIZE (1024 * 1024)

/**
 * @brief Maximum safe string length (64KB)
 */
#define SECURE_MAX_STRING_LENGTH (64 * 1024)

#ifdef __cplusplus
}
#endif

#endif /* BETANET_SECURE_UTILS_H */
