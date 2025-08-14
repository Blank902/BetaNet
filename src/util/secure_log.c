#include "betanet/secure_log.h"
#include "betanet/secure_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/time.h>
#include <syslog.h>
#include <pthread.h>
#endif

// =============================================================================
// Global State
// =============================================================================

static betanet_log_config_t g_log_config;
static bool g_log_initialized = false;
static char g_last_error[256] = {0};

#ifdef _WIN32
static CRITICAL_SECTION g_log_mutex;
#else
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

// =============================================================================
// Internal Helper Functions
// =============================================================================

static void log_lock(void) {
#ifdef _WIN32
    EnterCriticalSection(&g_log_mutex);
#else
    pthread_mutex_lock(&g_log_mutex);
#endif
}

static void log_unlock(void) {
#ifdef _WIN32
    LeaveCriticalSection(&g_log_mutex);
#else
    pthread_mutex_unlock(&g_log_mutex);
#endif
}

static const char* level_to_string(betanet_log_level_t level) {
    switch (level) {
        case BETANET_LOG_LEVEL_ERROR: return "ERROR";
        case BETANET_LOG_LEVEL_WARN:  return "WARN";
        case BETANET_LOG_LEVEL_INFO:  return "INFO";
        case BETANET_LOG_LEVEL_DEBUG: return "DEBUG";
        case BETANET_LOG_LEVEL_TRACE: return "TRACE";
        default: return "UNKNOWN";
    }
}

static const char* level_to_color(betanet_log_level_t level) {
    if (!g_log_config.use_color_output) {
        return "";
    }
    
    switch (level) {
        case BETANET_LOG_LEVEL_ERROR: return "\033[1;31m"; // Bold Red
        case BETANET_LOG_LEVEL_WARN:  return "\033[1;33m"; // Bold Yellow
        case BETANET_LOG_LEVEL_INFO:  return "\033[1;32m"; // Bold Green
        case BETANET_LOG_LEVEL_DEBUG: return "\033[1;36m"; // Bold Cyan
        case BETANET_LOG_LEVEL_TRACE: return "\033[1;37m"; // Bold White
        default: return "";
    }
}

static const char* color_reset(void) {
    return g_log_config.use_color_output ? "\033[0m" : "";
}

static uint64_t get_timestamp_ms(void) {
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t timestamp = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return timestamp / 10000; // Convert to milliseconds
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

static uint32_t get_thread_id(void) {
#ifdef _WIN32
    return (uint32_t)GetCurrentThreadId();
#else
    return (uint32_t)pthread_self();
#endif
}

static void set_last_error(const char* error_msg) {
    secure_strcpy(g_last_error, sizeof(g_last_error), error_msg);
}

// =============================================================================
// Core Implementation
// =============================================================================

betanet_log_config_t betanet_log_get_default_config(void) {
    betanet_log_config_t config = {0};
    
    config.min_level = BETANET_LOG_LEVEL_INFO;
    config.output_targets = BETANET_LOG_OUTPUT_CONSOLE;
    config.include_timestamp = true;
    config.include_thread_id = false;
    config.include_source_location = true;
    config.use_color_output = true;
    config.sanitize_sensitive_data = true;
    config.max_file_size = 10 * 1024 * 1024; // 10MB
    config.max_file_count = 5;
    
    secure_strcpy(config.log_file_path, sizeof(config.log_file_path), "betanet.log");
    
    return config;
}

int betanet_log_init(const betanet_log_config_t* config) {
    log_lock();
    
    if (g_log_initialized) {
        log_unlock();
        return 0; // Already initialized
    }
    
    // Use default config if none provided
    if (config) {
        g_log_config = *config;
    } else {
        g_log_config = betanet_log_get_default_config();
    }
    
    // Initialize platform-specific resources
#ifdef _WIN32
    InitializeCriticalSection(&g_log_mutex);
#endif
    
    // Open syslog if needed
#ifndef _WIN32
    if (g_log_config.output_targets & BETANET_LOG_OUTPUT_SYSLOG) {
        openlog("betanet", LOG_PID | LOG_CONS, LOG_USER);
    }
#endif
    
    g_log_initialized = true;
    log_unlock();
    
    BETANET_LOG_INFO("CORE", "Secure logging system initialized");
    return 0;
}

void betanet_log_shutdown(void) {
    if (!g_log_initialized) {
        return;
    }
    
    log_lock();
    
    BETANET_LOG_INFO("CORE", "Shutting down secure logging system");
    
    // Close syslog if opened
#ifndef _WIN32
    if (g_log_config.output_targets & BETANET_LOG_OUTPUT_SYSLOG) {
        closelog();
    }
#endif
    
    g_log_initialized = false;
    
    log_unlock();
    
    // Cleanup platform-specific resources
#ifdef _WIN32
    DeleteCriticalSection(&g_log_mutex);
#endif
}

int betanet_log_message(betanet_log_level_t level, const char* tag,
                       const char* file, int line,
                       const char* format, ...) {
    
    if (!g_log_initialized || level < g_log_config.min_level) {
        return 0;
    }
    
    if (!format) {
        set_last_error("Format string cannot be NULL");
        return -1;
    }
    
    char message[BETANET_LOG_MAX_MESSAGE_LENGTH];
    char final_message[BETANET_LOG_MAX_MESSAGE_LENGTH + 256];
    
    // Format the main message
    va_list args;
    va_start(args, format);
    int result = vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    if (result < 0) {
        set_last_error("Message formatting failed");
        return -1;
    }
    
    // Build the complete log entry
    char timestamp_str[64] = {0};
    if (g_log_config.include_timestamp) {
        uint64_t timestamp = get_timestamp_ms();
        time_t seconds = timestamp / 1000;
        int milliseconds = timestamp % 1000;
        
        struct tm* tm_info = localtime(&seconds);
        if (tm_info) {
            snprintf(timestamp_str, sizeof(timestamp_str), 
                    "%04d-%02d-%02d %02d:%02d:%02d.%03d ",
                    tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
                    tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec, milliseconds);
        }
    }
    
    char thread_str[32] = {0};
    if (g_log_config.include_thread_id) {
        snprintf(thread_str, sizeof(thread_str), "[%u] ", get_thread_id());
    }
    
    char location_str[256] = {0};
    if (g_log_config.include_source_location && file) {
        const char* filename = strrchr(file, '/');
        if (!filename) filename = strrchr(file, '\\');
        if (!filename) filename = file;
        else filename++; // Skip the slash
        
        snprintf(location_str, sizeof(location_str), " (%s:%d)", filename, line);
    }
    
    const char* tag_str = tag ? tag : "CORE";
    const char* level_str = level_to_string(level);
    const char* color_start = level_to_color(level);
    const char* color_end = color_reset();
    
    // Construct final message
    snprintf(final_message, sizeof(final_message),
            "%s%s%s[%s] %s: %s%s%s",
            timestamp_str, thread_str, color_start, level_str, tag_str, 
            message, location_str, color_end);
    
    log_lock();
    
    // Output to configured targets
    if (g_log_config.output_targets & BETANET_LOG_OUTPUT_CONSOLE) {
        FILE* output = (level == BETANET_LOG_LEVEL_ERROR) ? stderr : stdout;
        fprintf(output, "%s\n", final_message);
        fflush(output);
    }
    
    if (g_log_config.output_targets & BETANET_LOG_OUTPUT_FILE) {
        FILE* log_file = fopen(g_log_config.log_file_path, "a");
        if (log_file) {
            fprintf(log_file, "%s\n", final_message);
            fclose(log_file);
        }
    }
    
#ifdef _WIN32
    if (g_log_config.output_targets & BETANET_LOG_OUTPUT_DEBUG) {
        char debug_message[BETANET_LOG_MAX_MESSAGE_LENGTH + 256];
        snprintf(debug_message, sizeof(debug_message), "%s\n", final_message);
        OutputDebugStringA(debug_message);
    }
#else
    if (g_log_config.output_targets & BETANET_LOG_OUTPUT_SYSLOG) {
        int syslog_priority;
        switch (level) {
            case BETANET_LOG_LEVEL_ERROR: syslog_priority = LOG_ERR; break;
            case BETANET_LOG_LEVEL_WARN:  syslog_priority = LOG_WARNING; break;
            case BETANET_LOG_LEVEL_INFO:  syslog_priority = LOG_INFO; break;
            case BETANET_LOG_LEVEL_DEBUG: syslog_priority = LOG_DEBUG; break;
            case BETANET_LOG_LEVEL_TRACE: syslog_priority = LOG_DEBUG; break;
            default: syslog_priority = LOG_INFO; break;
        }
        syslog(syslog_priority, "[%s] %s: %s%s", level_str, tag_str, message, location_str);
    }
#endif
    
    log_unlock();
    
    return strlen(final_message);
}

void betanet_log_hex_dump(betanet_log_level_t level, const char* tag,
                         const void* data, size_t size, const char* description) {
    
    if (!betanet_log_is_enabled(level) || !data || size == 0) {
        return;
    }
    
    const uint8_t* bytes = (const uint8_t*)data;
    const char* desc = description ? description : "Data";
    
    betanet_log_message(level, tag, __FILE__, __LINE__, 
                       "%s (%zu bytes):", desc, size);
    
    char hex_line[80];
    char ascii_line[20];
    
    for (size_t i = 0; i < size; i += 16) {
        char* hex_ptr = hex_line;
        char* ascii_ptr = ascii_line;
        
        // Format hex bytes
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) {
                hex_ptr += sprintf(hex_ptr, "%02x ", bytes[i + j]);
                *ascii_ptr++ = (bytes[i + j] >= 32 && bytes[i + j] < 127) ? 
                              bytes[i + j] : '.';
            } else {
                hex_ptr += sprintf(hex_ptr, "   ");
                *ascii_ptr++ = ' ';
            }
        }
        *ascii_ptr = '\0';
        
        betanet_log_message(level, tag, __FILE__, __LINE__,
                           "  %04zx: %-48s |%s|", i, hex_line, ascii_line);
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

void betanet_log_set_level(betanet_log_level_t level) {
    log_lock();
    g_log_config.min_level = level;
    log_unlock();
}

betanet_log_level_t betanet_log_get_level(void) {
    return g_log_config.min_level;
}

bool betanet_log_is_enabled(betanet_log_level_t level) {
    return g_log_initialized && (level >= g_log_config.min_level);
}

const char* betanet_log_get_last_error(void) {
    return g_last_error[0] ? g_last_error : NULL;
}

void betanet_log_clear_error(void) {
    g_last_error[0] = '\0';
}

void betanet_log_lock(void) {
    log_lock();
}

void betanet_log_unlock(void) {
    log_unlock();
}

void betanet_log_flush(void) {
    fflush(stdout);
    fflush(stderr);
}

// =============================================================================
// Advanced Functions (Stub Implementations)
// =============================================================================

void betanet_log_performance(const char* tag, const char* operation_name,
                            uint64_t start_time_ms, uint64_t end_time_ms,
                            const char* additional_info) {
    
    uint64_t duration = end_time_ms - start_time_ms;
    const char* info = additional_info ? additional_info : "";
    
    BETANET_LOG_INFO(tag, "Performance: %s completed in %llu ms %s",
                     operation_name, (unsigned long long)duration, info);
}

void betanet_log_security_event(const char* event_type, int severity,
                               const char* description, const char* context) {
    
    betanet_log_level_t level = (severity >= 8) ? BETANET_LOG_LEVEL_ERROR :
                               (severity >= 5) ? BETANET_LOG_LEVEL_WARN :
                                                 BETANET_LOG_LEVEL_INFO;
    
    const char* ctx = context ? context : "";
    
    betanet_log_message(level, BETANET_LOG_TAG_SECURITY, __FILE__, __LINE__,
                       "Security Event [%s] Severity:%d - %s %s",
                       event_type, severity, description, ctx);
}

void betanet_log_connection_event(const char* direction, const char* protocol,
                                 const char* remote_addr, uint16_t local_port,
                                 bool success) {
    
    // Sanitize IP address if configured
    char sanitized_addr[64];
    if (g_log_config.sanitize_sensitive_data && remote_addr) {
        // Basic IP sanitization - replace last octet with xxx
        char* last_dot = strrchr(remote_addr, '.');
        if (last_dot) {
            size_t prefix_len = last_dot - remote_addr + 1;
            if (prefix_len < sizeof(sanitized_addr) - 4) {
                memcpy(sanitized_addr, remote_addr, prefix_len);
                strcpy(sanitized_addr + prefix_len, "xxx");
            } else {
                strcpy(sanitized_addr, "xxx.xxx.xxx.xxx");
            }
        } else {
            strcpy(sanitized_addr, "sanitized");
        }
    } else {
        secure_strcpy(sanitized_addr, sizeof(sanitized_addr), 
                     remote_addr ? remote_addr : "unknown");
    }
    
    betanet_log_level_t level = success ? BETANET_LOG_LEVEL_INFO : BETANET_LOG_LEVEL_WARN;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_TRANSPORT,
                     "Connection %s %s %s:%s:%u - %s",
                     direction, protocol, direction, sanitized_addr, local_port,
                     success ? "SUCCESS" : "FAILED");
}

int betanet_log_rotate_files(void) {
    // Simple rotation implementation
    if (!g_log_initialized || !(g_log_config.output_targets & BETANET_LOG_OUTPUT_FILE)) {
        return 0;
    }
    
    // Check current file size
    FILE* current_file = fopen(g_log_config.log_file_path, "r");
    if (!current_file) {
        return 0; // File doesn't exist yet
    }
    
    fseek(current_file, 0, SEEK_END);
    long file_size = ftell(current_file);
    fclose(current_file);
    
    if (file_size < (long)g_log_config.max_file_size) {
        return 0; // No rotation needed
    }
    
    // Rotate files
    char old_file[512], new_file[512];
    
    for (int i = g_log_config.max_file_count - 1; i > 0; i--) {
        snprintf(old_file, sizeof(old_file), "%s.%d", g_log_config.log_file_path, i - 1);
        snprintf(new_file, sizeof(new_file), "%s.%d", g_log_config.log_file_path, i);
        rename(old_file, new_file);
    }
    
    snprintf(new_file, sizeof(new_file), "%s.0", g_log_config.log_file_path);
    rename(g_log_config.log_file_path, new_file);
    
    return 0;
}
