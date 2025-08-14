#include "betanet/secure_utils.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

// =============================================================================
// Secure Buffer Operations Implementation
// =============================================================================

int secure_memcpy(void* dest, size_t dest_size, const void* src, size_t src_size) {
    // Parameter validation
    if (!dest || !src) {
        return SECURE_ERROR_NULL_POINTER;
    }
    
    if (dest_size == 0 || src_size == 0) {
        return SECURE_ERROR_INVALID_SIZE;
    }
    
    if (src_size > dest_size) {
        return SECURE_ERROR_BUFFER_TOO_SMALL;
    }
    
    if (dest_size > SECURE_MAX_BUFFER_SIZE || src_size > SECURE_MAX_BUFFER_SIZE) {
        return SECURE_ERROR_INVALID_SIZE;
    }
    
    // Check for overlapping buffers
    const char* src_ptr = (const char*)src;
    char* dest_ptr = (char*)dest;
    
    if ((src_ptr >= dest_ptr && src_ptr < dest_ptr + dest_size) ||
        (dest_ptr >= src_ptr && dest_ptr < src_ptr + src_size)) {
        // Use memmove for overlapping buffers
        memmove(dest, src, src_size);
    } else {
        memcpy(dest, src, src_size);
    }
    
    return SECURE_ERROR_NONE;
}

int secure_memset(void* dest, int value, size_t size) {
    // Parameter validation
    if (!dest) {
        return SECURE_ERROR_NULL_POINTER;
    }
    
    if (size == 0) {
        return SECURE_ERROR_NONE;  // Nothing to do
    }
    
    if (size > SECURE_MAX_BUFFER_SIZE) {
        return SECURE_ERROR_INVALID_SIZE;
    }
    
    // Validate value range
    if (value < 0 || value > 255) {
        return SECURE_ERROR_INVALID_SIZE;
    }
    
    memset(dest, value, size);
    return SECURE_ERROR_NONE;
}

int secure_strcpy(char* dest, size_t dest_size, const char* src) {
    // Parameter validation
    if (!dest || !src) {
        return SECURE_ERROR_NULL_POINTER;
    }
    
    if (dest_size == 0) {
        return SECURE_ERROR_INVALID_SIZE;
    }
    
    if (dest_size > SECURE_MAX_STRING_LENGTH) {
        return SECURE_ERROR_INVALID_SIZE;
    }
    
    // Check source string length
    size_t src_len = strnlen(src, dest_size);
    
    // Source string too long (not null-terminated within dest_size)
    if (src_len >= dest_size) {
        return SECURE_ERROR_STRING_TOO_LONG;
    }
    
    // Safe to copy including null terminator
    memcpy(dest, src, src_len + 1);
    
    return SECURE_ERROR_NONE;
}

int secure_strncpy(char* dest, size_t dest_size, const char* src, size_t max_copy) {
    // Parameter validation
    if (!dest || !src) {
        return SECURE_ERROR_NULL_POINTER;
    }
    
    if (dest_size == 0) {
        return SECURE_ERROR_INVALID_SIZE;
    }
    
    if (max_copy >= dest_size) {
        return SECURE_ERROR_BUFFER_TOO_SMALL;
    }
    
    // Find actual copy length (up to max_copy or null terminator)
    size_t copy_len = 0;
    while (copy_len < max_copy && src[copy_len] != '\0') {
        copy_len++;
    }
    
    // Copy the string
    memcpy(dest, src, copy_len);
    
    // Ensure null termination
    dest[copy_len] = '\0';
    
    return SECURE_ERROR_NONE;
}

int secure_snprintf(char* dest, size_t dest_size, const char* format, ...) {
    // Parameter validation
    if (!dest || !format) {
        return SECURE_ERROR_NULL_POINTER;
    }
    
    if (dest_size == 0) {
        return SECURE_ERROR_INVALID_SIZE;
    }
    
    if (dest_size > SECURE_MAX_STRING_LENGTH) {
        return SECURE_ERROR_INVALID_SIZE;
    }
    
    va_list args;
    va_start(args, format);
    
    int result = vsnprintf(dest, dest_size, format, args);
    
    va_end(args);
    
    // Check for formatting error or truncation
    if (result < 0) {
        return SECURE_ERROR_INVALID_FORMAT;
    }
    
    if ((size_t)result >= dest_size) {
        return SECURE_ERROR_BUFFER_TOO_SMALL;
    }
    
    return result;
}

int secure_strcat(char* dest, size_t dest_size, const char* src) {
    // Parameter validation
    if (!dest || !src) {
        return SECURE_ERROR_NULL_POINTER;
    }
    
    if (dest_size == 0) {
        return SECURE_ERROR_INVALID_SIZE;
    }
    
    // Find current length of destination string
    size_t dest_len = strnlen(dest, dest_size);
    
    // Check if destination string is properly null-terminated
    if (dest_len >= dest_size) {
        return SECURE_ERROR_NOT_NULL_TERMINATED;
    }
    
    // Find length of source string
    size_t src_len = strnlen(src, dest_size - dest_len);
    
    // Check if concatenation would fit
    if (dest_len + src_len >= dest_size) {
        return SECURE_ERROR_BUFFER_TOO_SMALL;
    }
    
    // Safe to concatenate
    memcpy(dest + dest_len, src, src_len + 1);
    
    return SECURE_ERROR_NONE;
}

// =============================================================================
// Input Validation Implementation
// =============================================================================

bool validate_buffer(const void* ptr, size_t size, size_t min_size, size_t max_size) {
    if (!ptr) {
        return false;
    }
    
    if (size < min_size || size > max_size) {
        return false;
    }
    
    if (max_size > SECURE_MAX_BUFFER_SIZE) {
        return false;
    }
    
    return true;
}

bool validate_string(const char* str, size_t max_len) {
    if (!str) {
        return false;
    }
    
    if (max_len == 0 || max_len > SECURE_MAX_STRING_LENGTH) {
        return false;
    }
    
    // Check for null termination within max_len
    size_t len = strnlen(str, max_len);
    return len < max_len;
}

bool is_null_terminated(const char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) {
        return false;
    }
    
    // Look for null terminator within buffer
    for (size_t i = 0; i < buffer_size; i++) {
        if (buffer[i] == '\0') {
            return true;
        }
    }
    
    return false;
}

// =============================================================================
// Memory Safety Utilities Implementation
// =============================================================================

int secure_buffer_init(secure_buffer_t* buffer, void* data, size_t capacity) {
    if (!buffer || !data) {
        return SECURE_ERROR_NULL_POINTER;
    }
    
    if (capacity == 0 || capacity > SECURE_MAX_BUFFER_SIZE) {
        return SECURE_ERROR_INVALID_SIZE;
    }
    
    buffer->data = data;
    buffer->size = 0;
    buffer->capacity = capacity;
    buffer->is_valid = true;
    
    return SECURE_ERROR_NONE;
}

int secure_buffer_copy(secure_buffer_t* buffer, const void* src, size_t src_size) {
    if (!buffer || !src) {
        return SECURE_ERROR_NULL_POINTER;
    }
    
    if (!buffer->is_valid) {
        return SECURE_ERROR_INVALID_SIZE;
    }
    
    if (src_size > buffer->capacity) {
        return SECURE_ERROR_BUFFER_TOO_SMALL;
    }
    
    int result = secure_memcpy(buffer->data, buffer->capacity, src, src_size);
    if (result == SECURE_ERROR_NONE) {
        buffer->size = src_size;
    }
    
    return result;
}

int secure_buffer_append(secure_buffer_t* buffer, const void* src, size_t src_size) {
    if (!buffer || !src) {
        return SECURE_ERROR_NULL_POINTER;
    }
    
    if (!buffer->is_valid) {
        return SECURE_ERROR_INVALID_SIZE;
    }
    
    if (buffer->size + src_size > buffer->capacity) {
        return SECURE_ERROR_BUFFER_TOO_SMALL;
    }
    
    char* dest_ptr = (char*)buffer->data + buffer->size;
    int result = secure_memcpy(dest_ptr, buffer->capacity - buffer->size, src, src_size);
    
    if (result == SECURE_ERROR_NONE) {
        buffer->size += src_size;
    }
    
    return result;
}

void secure_buffer_clear(secure_buffer_t* buffer) {
    if (buffer) {
        // Clear sensitive data
        if (buffer->data && buffer->capacity > 0) {
            memset(buffer->data, 0, buffer->capacity);
        }
        
        buffer->data = NULL;
        buffer->size = 0;
        buffer->capacity = 0;
        buffer->is_valid = false;
    }
}

// =============================================================================
// Error Handling Implementation
// =============================================================================

const char* secure_error_message(secure_error_t error) {
    switch (error) {
        case SECURE_ERROR_NONE:
            return "No error";
        case SECURE_ERROR_NULL_POINTER:
            return "Null pointer provided";
        case SECURE_ERROR_BUFFER_TOO_SMALL:
            return "Destination buffer too small";
        case SECURE_ERROR_INVALID_SIZE:
            return "Invalid buffer size";
        case SECURE_ERROR_NOT_NULL_TERMINATED:
            return "String not null-terminated";
        case SECURE_ERROR_STRING_TOO_LONG:
            return "String too long for buffer";
        case SECURE_ERROR_INVALID_FORMAT:
            return "Invalid format string";
        default:
            return "Unknown error";
    }
}
