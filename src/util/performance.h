#ifndef BETANET_PERFORMANCE_H
#define BETANET_PERFORMANCE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct htx_ctx_s htx_ctx_t;

/**
 * Get current time in milliseconds (utility function)
 */
time_t get_current_time_ms(void);

/**
 * BetaNet Performance Optimization Module
 * =====================================
 * 
 * This module provides performance enhancements for BetaNet:
 * - Connection pooling and reuse
 * - Asynchronous I/O operations
 * - Memory pool management
 * - Enhanced error recovery
 * - Connection timeout management
 * - Performance metrics and monitoring
 */

// =====================
// Connection Pool Management
// =====================

#define BETANET_MAX_POOLED_CONNECTIONS 32
#define BETANET_CONNECTION_TIMEOUT_MS 30000
#define BETANET_CONNECTION_KEEPALIVE_MS 300000

typedef enum {
    POOL_CONN_IDLE = 0,
    POOL_CONN_ACTIVE = 1,
    POOL_CONN_CLOSING = 2,
    POOL_CONN_ERROR = 3
} pool_connection_state_t;

typedef struct pool_connection_s {
    htx_ctx_t* ctx;
    char host[256];
    uint16_t port;
    char alpn[32];
    pool_connection_state_t state;
    time_t last_used;
    time_t created;
    uint32_t use_count;
    uint32_t error_count;
    bool in_use;
} pool_connection_t;

typedef struct connection_pool_s {
    pool_connection_t connections[BETANET_MAX_POOLED_CONNECTIONS];
    uint32_t active_count;
    uint32_t total_connections;
    uint32_t reuse_count;
    uint32_t miss_count;
    time_t last_cleanup;
} connection_pool_t;

/**
 * Initialize the global connection pool
 */
int betanet_pool_init(void);

/**
 * Shutdown and cleanup the connection pool
 */
void betanet_pool_shutdown(void);

/**
 * Get a connection from the pool (or create new one)
 * Returns NULL if unable to provide connection
 */
htx_ctx_t* betanet_pool_get_connection(const char* host, uint16_t port, const char* alpn);

/**
 * Return a connection to the pool for reuse
 */
int betanet_pool_return_connection(htx_ctx_t* ctx);

/**
 * Force cleanup of idle connections
 */
void betanet_pool_cleanup(void);

/**
 * Get pool statistics
 */
void betanet_pool_get_stats(uint32_t* active, uint32_t* total, uint32_t* reuse_rate);

// =====================
// Memory Pool Management
// =====================

#define BETANET_MEMORY_POOL_SIZE 1048576  // 1MB default pool
#define BETANET_MEMORY_BLOCK_SIZE 4096    // 4KB blocks

typedef struct memory_block_s {
    void* ptr;
    size_t size;
    bool in_use;
    struct memory_block_s* next;
} memory_block_t;

typedef struct memory_pool_s {
    void* pool_memory;
    size_t pool_size;
    memory_block_t* free_blocks;
    memory_block_t* used_blocks;
    uint32_t total_blocks;
    uint32_t free_blocks_count;
    uint32_t allocation_count;
    uint32_t deallocation_count;
} memory_pool_t;

/**
 * Initialize memory pool for efficient allocation
 */
int betanet_mempool_init(size_t pool_size);

/**
 * Shutdown and cleanup memory pool
 */
void betanet_mempool_shutdown(void);

/**
 * Allocate memory from pool (faster than malloc for frequent allocations)
 */
void* betanet_mempool_alloc(size_t size);

/**
 * Return memory to pool
 */
void betanet_mempool_free(void* ptr);

/**
 * Get memory pool statistics
 */
void betanet_mempool_get_stats(uint32_t* total_blocks, uint32_t* free_blocks, 
                               uint32_t* allocations, uint32_t* deallocations);

// =====================
// Asynchronous I/O Management
// =====================

typedef enum {
    ASYNC_OP_CONNECT = 0,
    ASYNC_OP_READ = 1,
    ASYNC_OP_WRITE = 2,
    ASYNC_OP_HANDSHAKE = 3
} async_operation_type_t;

typedef enum {
    ASYNC_STATE_PENDING = 0,
    ASYNC_STATE_COMPLETED = 1,
    ASYNC_STATE_ERROR = 2,
    ASYNC_STATE_TIMEOUT = 3
} async_operation_state_t;

typedef struct async_operation_s {
    async_operation_type_t type;
    async_operation_state_t state;
    htx_ctx_t* ctx;
    void* buffer;
    size_t buffer_size;
    size_t bytes_transferred;
    int error_code;
    time_t started;
    time_t timeout;
    void (*callback)(struct async_operation_s* op);
    void* user_data;
} async_operation_t;

/**
 * Initialize asynchronous I/O system
 */
int betanet_async_init(void);

/**
 * Shutdown asynchronous I/O system
 */
void betanet_async_shutdown(void);

/**
 * Start asynchronous connection
 */
int betanet_async_connect(htx_ctx_t* ctx, const char* host, uint16_t port, 
                          const char* alpn, void (*callback)(async_operation_t*), 
                          void* user_data);

/**
 * Start asynchronous read operation
 */
int betanet_async_read(htx_ctx_t* ctx, void* buffer, size_t size,
                       void (*callback)(async_operation_t*), void* user_data);

/**
 * Start asynchronous write operation
 */
int betanet_async_write(htx_ctx_t* ctx, const void* buffer, size_t size,
                        void (*callback)(async_operation_t*), void* user_data);

/**
 * Process pending asynchronous operations
 * Returns number of operations processed
 */
int betanet_async_process(int timeout_ms);

// =====================
// Enhanced Error Recovery
// =====================

typedef enum {
    ERROR_RECOVERY_NONE = 0,
    ERROR_RECOVERY_RETRY = 1,
    ERROR_RECOVERY_RECONNECT = 2,
    ERROR_RECOVERY_FALLBACK = 3,
    ERROR_RECOVERY_ABORT = 4
} error_recovery_action_t;

typedef struct error_context_s {
    int error_code;
    int retry_count;
    time_t first_error;
    time_t last_error;
    char error_description[256];
    htx_ctx_t* failed_ctx;
} error_context_t;

/**
 * Enhanced error recovery with intelligent retry logic
 */
error_recovery_action_t betanet_handle_error(error_context_t* error_ctx);

/**
 * Implement connection retry with exponential backoff
 */
int betanet_retry_connection(htx_ctx_t* ctx, const char* host, uint16_t port, 
                             const char* alpn, int max_retries);

/**
 * Connection health check
 */
bool betanet_connection_is_healthy(htx_ctx_t* ctx);

/**
 * Attempt connection repair
 */
int betanet_repair_connection(htx_ctx_t* ctx);

// =====================
// Performance Metrics
// =====================

typedef struct performance_metrics_s {
    // Connection metrics
    uint64_t total_connections;
    uint64_t successful_connections;
    uint64_t failed_connections;
    uint64_t connection_reuses;
    
    // Timing metrics
    double avg_connection_time_ms;
    double avg_handshake_time_ms;
    double avg_request_time_ms;
    
    // Throughput metrics
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t messages_sent;
    uint64_t messages_received;
    
    // Error metrics
    uint64_t total_errors;
    uint64_t recoverable_errors;
    uint64_t critical_errors;
    uint64_t timeouts;
    
    // Resource metrics
    uint32_t active_connections;
    uint32_t pooled_connections;
    uint32_t memory_usage_bytes;
    
    time_t start_time;
    time_t last_update;
} performance_metrics_t;

/**
 * Initialize performance metrics collection
 */
int betanet_metrics_init(void);

/**
 * Get current performance metrics
 */
const performance_metrics_t* betanet_metrics_get(void);

/**
 * Record connection event
 */
void betanet_metrics_record_connection(bool successful, double duration_ms);

/**
 * Record data transfer
 */
void betanet_metrics_record_transfer(size_t bytes_sent, size_t bytes_received);

/**
 * Record error event
 */
void betanet_metrics_record_error(int error_code, bool recoverable);

/**
 * Reset metrics
 */
void betanet_metrics_reset(void);

/**
 * Print performance report
 */
void betanet_metrics_print_report(void);

// =====================
// Timeout Management
// =====================

typedef struct timeout_manager_s {
    time_t connect_timeout;
    time_t handshake_timeout;
    time_t read_timeout;
    time_t write_timeout;
    time_t keepalive_timeout;
} timeout_manager_t;

/**
 * Set connection timeouts
 */
void betanet_set_timeouts(time_t connect_ms, time_t handshake_ms, 
                          time_t read_ms, time_t write_ms, time_t keepalive_ms);

/**
 * Get current timeout settings
 */
const timeout_manager_t* betanet_get_timeouts(void);

/**
 * Check if operation has timed out
 */
bool betanet_check_timeout(time_t start_time, time_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif // BETANET_PERFORMANCE_H
