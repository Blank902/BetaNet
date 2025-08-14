#ifndef BETANET_SECURE_LOG_H
#define BETANET_SECURE_LOG_H

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Secure Logging Configuration
// =============================================================================

/** Maximum log message length */
#define BETANET_LOG_MAX_MESSAGE_LENGTH 2048

/** Maximum log tag length */
#define BETANET_LOG_MAX_TAG_LENGTH 64

/** Maximum log buffer size for batching */
#define BETANET_LOG_BUFFER_SIZE 8192

// =============================================================================
// Log Levels
// =============================================================================

typedef enum {
    BETANET_LOG_LEVEL_OFF = 0,      /**< No logging */
    BETANET_LOG_LEVEL_ERROR = 1,    /**< Error conditions */
    BETANET_LOG_LEVEL_WARN = 2,     /**< Warning conditions */
    BETANET_LOG_LEVEL_INFO = 3,     /**< Informational messages */
    BETANET_LOG_LEVEL_DEBUG = 4,    /**< Debug-level messages */
    BETANET_LOG_LEVEL_TRACE = 5     /**< Trace-level messages */
} betanet_log_level_t;

// =============================================================================
// Log Output Destinations
// =============================================================================

typedef enum {
    BETANET_LOG_OUTPUT_NONE = 0,      /**< No output */
    BETANET_LOG_OUTPUT_CONSOLE = 1,   /**< Standard output/error */
    BETANET_LOG_OUTPUT_FILE = 2,      /**< File output */
    BETANET_LOG_OUTPUT_SYSLOG = 4,    /**< System log (Unix/Linux) */
    BETANET_LOG_OUTPUT_DEBUG = 8      /**< Debug output (Windows) */
} betanet_log_output_t;

// =============================================================================
// Log Configuration Structure
// =============================================================================

typedef struct {
    betanet_log_level_t min_level;          /**< Minimum log level to output */
    betanet_log_output_t output_targets;    /**< Bitfield of output targets */
    bool include_timestamp;                 /**< Include timestamp in messages */
    bool include_thread_id;                 /**< Include thread ID in messages */
    bool include_source_location;           /**< Include file:line in messages */
    bool use_color_output;                  /**< Use color coding in console output */
    bool sanitize_sensitive_data;           /**< Remove/mask sensitive data */
    char log_file_path[256];               /**< Path to log file (if file output enabled) */
    size_t max_file_size;                  /**< Maximum log file size before rotation */
    int max_file_count;                    /**< Maximum number of rotated log files */
} betanet_log_config_t;

// =============================================================================
// Core Logging Functions
// =============================================================================

/**
 * @brief Initialize the secure logging system
 * 
 * @param config Logging configuration (NULL for defaults)
 * @return int 0 on success, negative on error
 */
int betanet_log_init(const betanet_log_config_t* config);

/**
 * @brief Shutdown the logging system and cleanup resources
 */
void betanet_log_shutdown(void);

/**
 * @brief Log a message with specified level and tag
 * 
 * @param level Log level
 * @param tag Component tag (max 64 chars, can be NULL)
 * @param file Source file name (__FILE__)
 * @param line Source line number (__LINE__)
 * @param format Format string (must be literal string, not variable)
 * @param ... Format arguments
 * @return int Number of characters written, negative on error
 */
int betanet_log_message(betanet_log_level_t level, const char* tag,
                       const char* file, int line,
                       const char* format, ...);

/**
 * @brief Log binary data as hex dump
 * 
 * @param level Log level
 * @param tag Component tag
 * @param data Binary data to log
 * @param size Size of data
 * @param description Description of the data
 */
void betanet_log_hex_dump(betanet_log_level_t level, const char* tag,
                         const void* data, size_t size, const char* description);

/**
 * @brief Set the minimum log level
 * 
 * @param level New minimum log level
 */
void betanet_log_set_level(betanet_log_level_t level);

/**
 * @brief Get the current minimum log level
 * 
 * @return betanet_log_level_t Current minimum log level
 */
betanet_log_level_t betanet_log_get_level(void);

/**
 * @brief Check if a log level would be output
 * 
 * @param level Log level to check
 * @return bool true if level would be logged, false otherwise
 */
bool betanet_log_is_enabled(betanet_log_level_t level);

// =============================================================================
// Convenience Macros
// =============================================================================

/** Get default log configuration */
betanet_log_config_t betanet_log_get_default_config(void);

/** Error logging macro */
#define BETANET_LOG_ERROR(tag, format, ...) \
    betanet_log_message(BETANET_LOG_LEVEL_ERROR, (tag), __FILE__, __LINE__, (format), ##__VA_ARGS__)

/** Warning logging macro */
#define BETANET_LOG_WARN(tag, format, ...) \
    betanet_log_message(BETANET_LOG_LEVEL_WARN, (tag), __FILE__, __LINE__, (format), ##__VA_ARGS__)

/** Info logging macro */
#define BETANET_LOG_INFO(tag, format, ...) \
    betanet_log_message(BETANET_LOG_LEVEL_INFO, (tag), __FILE__, __LINE__, (format), ##__VA_ARGS__)

/** Debug logging macro */
#define BETANET_LOG_DEBUG(tag, format, ...) \
    betanet_log_message(BETANET_LOG_LEVEL_DEBUG, (tag), __FILE__, __LINE__, (format), ##__VA_ARGS__)

/** Trace logging macro */
#define BETANET_LOG_TRACE(tag, format, ...) \
    betanet_log_message(BETANET_LOG_LEVEL_TRACE, (tag), __FILE__, __LINE__, (format), ##__VA_ARGS__)

/** Hex dump macro */
#define BETANET_LOG_HEX(level, tag, data, size, desc) \
    betanet_log_hex_dump((level), (tag), (data), (size), (desc))

// =============================================================================
// Component-Specific Log Tags
// =============================================================================

#define BETANET_LOG_TAG_CORE     "CORE"
#define BETANET_LOG_TAG_HTX      "HTX"
#define BETANET_LOG_TAG_NOISE    "NOISE"
#define BETANET_LOG_TAG_PATH     "PATH"
#define BETANET_LOG_TAG_PAY      "PAY"
#define BETANET_LOG_TAG_SHAPE    "SHAPE"
#define BETANET_LOG_TAG_SCION    "SCION"
#define BETANET_LOG_TAG_CRYPTO   "CRYPTO"
#define BETANET_LOG_TAG_TICKET   "TICKET"
#define BETANET_LOG_TAG_CALIB    "CALIB"
#define BETANET_LOG_TAG_HTTP2    "HTTP2"
#define BETANET_LOG_TAG_PERF     "PERF"
#define BETANET_LOG_TAG_SECURITY "SEC"
#define BETANET_LOG_TAG_TRANSPORT "TRANS"

// =============================================================================
// Advanced Logging Features
// =============================================================================

/**
 * @brief Log performance metrics with timing
 * 
 * @param tag Component tag
 * @param operation_name Name of the operation being measured
 * @param start_time_ms Start time in milliseconds
 * @param end_time_ms End time in milliseconds
 * @param additional_info Additional context information
 */
void betanet_log_performance(const char* tag, const char* operation_name,
                            uint64_t start_time_ms, uint64_t end_time_ms,
                            const char* additional_info);

/**
 * @brief Log security-relevant events
 * 
 * @param event_type Type of security event
 * @param severity Security event severity (1-10)
 * @param description Event description
 * @param context Additional context data
 */
void betanet_log_security_event(const char* event_type, int severity,
                               const char* description, const char* context);

/**
 * @brief Log network connection events
 * 
 * @param direction "INCOMING" or "OUTGOING"
 * @param protocol "TCP", "UDP", "QUIC", etc.
 * @param remote_addr Remote address (will be sanitized if needed)
 * @param local_port Local port number
 * @param success true if connection succeeded
 */
void betanet_log_connection_event(const char* direction, const char* protocol,
                                 const char* remote_addr, uint16_t local_port,
                                 bool success);

/**
 * @brief Flush all pending log messages
 * 
 * Forces immediate output of any buffered log messages
 */
void betanet_log_flush(void);

/**
 * @brief Rotate log files (if file logging is enabled)
 * 
 * @return int 0 on success, negative on error
 */
int betanet_log_rotate_files(void);

// =============================================================================
// Error Handling
// =============================================================================

/**
 * @brief Get the last logging error message
 * 
 * @return const char* Error message string, or NULL if no error
 */
const char* betanet_log_get_last_error(void);

/**
 * @brief Clear the last logging error
 */
void betanet_log_clear_error(void);

// =============================================================================
// Thread Safety
// =============================================================================

/**
 * @brief Lock the logging system for thread-safe operations
 * 
 * Use this if you need to ensure atomic logging of multiple messages
 * Remember to call betanet_log_unlock() when done
 */
void betanet_log_lock(void);

/**
 * @brief Unlock the logging system
 */
void betanet_log_unlock(void);

#ifdef __cplusplus
}
#endif

#endif /* BETANET_SECURE_LOG_H */
