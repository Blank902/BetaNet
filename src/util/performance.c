#include "performance.h"
#include "../htx/htx.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#endif

// Declare get_current_time_ms for external use
time_t get_current_time_ms(void);

/**
 * BetaNet Performance Optimization Implementation
 * =============================================
 * 
 * Provides high-performance networking capabilities:
 * - Connection pooling for efficient resource reuse
 * - Asynchronous I/O for non-blocking operations
 * - Memory pooling for reduced allocation overhead
 * - Enhanced error recovery with intelligent retry logic
 * - Comprehensive performance metrics and monitoring
 */

// =====================
// Global State
// =====================

static connection_pool_t g_connection_pool = {0};
static memory_pool_t g_memory_pool = {0};
static performance_metrics_t g_metrics = {0};
static timeout_manager_t g_timeouts = {
    .connect_timeout = 30000,      // 30 seconds
    .handshake_timeout = 10000,    // 10 seconds
    .read_timeout = 60000,         // 60 seconds
    .write_timeout = 30000,        // 30 seconds
    .keepalive_timeout = 300000    // 5 minutes
};

static bool g_performance_initialized = false;

// =====================
// Utility Functions
// =====================

time_t get_current_time_ms(void) {
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
#endif
}

static bool connections_match(const pool_connection_t* conn, const char* host, 
                             uint16_t port, const char* alpn) {
    return (strcmp(conn->host, host) == 0 && 
            conn->port == port &&
            strcmp(conn->alpn, alpn ? alpn : "") == 0);
}

// =====================
// Connection Pool Implementation
// =====================

int betanet_pool_init(void) {
    memset(&g_connection_pool, 0, sizeof(g_connection_pool));
    g_connection_pool.last_cleanup = get_current_time_ms();
    printf("[perf] Connection pool initialized with %d slots\n", BETANET_MAX_POOLED_CONNECTIONS);
    return 0;
}

void betanet_pool_shutdown(void) {
    printf("[perf] Shutting down connection pool...\n");
    
    for (int i = 0; i < BETANET_MAX_POOLED_CONNECTIONS; i++) {
        pool_connection_t* conn = &g_connection_pool.connections[i];
        if (conn->ctx) {
            printf("[perf] Closing pooled connection %d (%s:%d)\n", i, conn->host, conn->port);
            htx_ctx_free(conn->ctx);
            conn->ctx = NULL;
        }
    }
    
    printf("[perf] Connection pool shutdown complete. Stats: %d reuses, %d misses\n", 
           g_connection_pool.reuse_count, g_connection_pool.miss_count);
    memset(&g_connection_pool, 0, sizeof(g_connection_pool));
}

htx_ctx_t* betanet_pool_get_connection(const char* host, uint16_t port, const char* alpn) {
    if (!host) return NULL;
    
    time_t current_time = get_current_time_ms();
    
    // First, look for an existing connection
    for (int i = 0; i < BETANET_MAX_POOLED_CONNECTIONS; i++) {
        pool_connection_t* conn = &g_connection_pool.connections[i];
        
        if (conn->ctx && conn->state == POOL_CONN_IDLE && 
            connections_match(conn, host, port, alpn)) {
            
            // Check if connection is still valid
            if (current_time - conn->last_used > BETANET_CONNECTION_KEEPALIVE_MS) {
                printf("[perf] Connection %d expired, closing\n", i);
                htx_ctx_free(conn->ctx);
                conn->ctx = NULL;
                conn->state = POOL_CONN_IDLE;
                continue;
            }
            
            // Reuse this connection
            conn->state = POOL_CONN_ACTIVE;
            conn->last_used = current_time;
            conn->use_count++;
            conn->in_use = true;
            g_connection_pool.reuse_count++;
            
            printf("[perf] Reusing pooled connection %d for %s:%d (use count: %d)\n", 
                   i, host, port, conn->use_count);
            return conn->ctx;
        }
    }
    
    // No suitable connection found, create a new one
    g_connection_pool.miss_count++;
    
    // Find an empty slot
    for (int i = 0; i < BETANET_MAX_POOLED_CONNECTIONS; i++) {
        pool_connection_t* conn = &g_connection_pool.connections[i];
        
        if (!conn->ctx) {
            // Create new connection
            htx_ctx_t* new_ctx = htx_ctx_create(HTX_TRANSPORT_TCP);
            if (!new_ctx) {
                printf("[perf] Failed to create new connection context\n");
                return NULL;
            }
            
            // Connect to the host
            if (htx_connect(new_ctx, host, port, alpn) != 0) {
                printf("[perf] Failed to connect to %s:%d\n", host, port);
                htx_ctx_free(new_ctx);
                return NULL;
            }
            
            // Store in pool
            conn->ctx = new_ctx;
            strncpy(conn->host, host, sizeof(conn->host) - 1);
            conn->host[sizeof(conn->host) - 1] = '\0';
            conn->port = port;
            strncpy(conn->alpn, alpn ? alpn : "", sizeof(conn->alpn) - 1);
            conn->alpn[sizeof(conn->alpn) - 1] = '\0';
            conn->state = POOL_CONN_ACTIVE;
            conn->last_used = current_time;
            conn->created = current_time;
            conn->use_count = 1;
            conn->error_count = 0;
            conn->in_use = true;
            
            g_connection_pool.active_count++;
            g_connection_pool.total_connections++;
            
            printf("[perf] Created new pooled connection %d for %s:%d\n", i, host, port);
            return new_ctx;
        }
    }
    
    printf("[perf] Connection pool full, creating standalone connection\n");
    
    // Pool is full, create a standalone connection
    htx_ctx_t* ctx = htx_ctx_create(HTX_TRANSPORT_TCP);
    if (ctx && htx_connect(ctx, host, port, alpn) == 0) {
        return ctx;
    }
    
    if (ctx) htx_ctx_free(ctx);
    return NULL;
}

int betanet_pool_return_connection(htx_ctx_t* ctx) {
    if (!ctx) return -1;
    
    // Find the connection in the pool
    for (int i = 0; i < BETANET_MAX_POOLED_CONNECTIONS; i++) {
        pool_connection_t* conn = &g_connection_pool.connections[i];
        
        if (conn->ctx == ctx) {
            conn->state = POOL_CONN_IDLE;
            conn->last_used = get_current_time_ms();
            conn->in_use = false;
            
            printf("[perf] Returned connection %d to pool (%s:%d)\n", 
                   i, conn->host, conn->port);
            return 0;
        }
    }
    
    // Not a pooled connection, just free it
    printf("[perf] Freeing standalone connection\n");
    htx_ctx_free(ctx);
    return 0;
}

void betanet_pool_cleanup(void) {
    time_t current_time = get_current_time_ms();
    int cleaned = 0;
    
    for (int i = 0; i < BETANET_MAX_POOLED_CONNECTIONS; i++) {
        pool_connection_t* conn = &g_connection_pool.connections[i];
        
        if (conn->ctx && !conn->in_use) {
            // Check if connection should be cleaned up
            bool should_cleanup = false;
            
            if (conn->state == POOL_CONN_ERROR ||
                conn->error_count > 3 ||
                (current_time - conn->last_used) > BETANET_CONNECTION_KEEPALIVE_MS) {
                should_cleanup = true;
            }
            
            if (should_cleanup) {
                printf("[perf] Cleaning up connection %d (%s:%d, errors: %d)\n", 
                       i, conn->host, conn->port, conn->error_count);
                htx_ctx_free(conn->ctx);
                memset(conn, 0, sizeof(*conn));
                g_connection_pool.active_count--;
                cleaned++;
            }
        }
    }
    
    g_connection_pool.last_cleanup = current_time;
    if (cleaned > 0) {
        printf("[perf] Cleaned up %d idle connections\n", cleaned);
    }
}

void betanet_pool_get_stats(uint32_t* active, uint32_t* total, uint32_t* reuse_rate) {
    if (active) *active = g_connection_pool.active_count;
    if (total) *total = g_connection_pool.total_connections;
    if (reuse_rate) {
        uint32_t total_requests = g_connection_pool.reuse_count + g_connection_pool.miss_count;
        *reuse_rate = total_requests > 0 ? 
            (g_connection_pool.reuse_count * 100) / total_requests : 0;
    }
}

// =====================
// Memory Pool Implementation
// =====================

int betanet_mempool_init(size_t pool_size) {
    if (pool_size == 0) pool_size = BETANET_MEMORY_POOL_SIZE;
    
    g_memory_pool.pool_memory = malloc(pool_size);
    if (!g_memory_pool.pool_memory) {
        printf("[perf] Failed to allocate memory pool of size %zu\n", pool_size);
        return -1;
    }
    
    g_memory_pool.pool_size = pool_size;
    g_memory_pool.free_blocks = NULL;
    g_memory_pool.used_blocks = NULL;
    g_memory_pool.total_blocks = 0;
    g_memory_pool.free_blocks_count = 0;
    g_memory_pool.allocation_count = 0;
    g_memory_pool.deallocation_count = 0;
    
    printf("[perf] Memory pool initialized: %zu bytes\n", pool_size);
    return 0;
}

void betanet_mempool_shutdown(void) {
    if (g_memory_pool.pool_memory) {
        printf("[perf] Memory pool shutdown. Stats: %d allocs, %d deallocs\n", 
               g_memory_pool.allocation_count, g_memory_pool.deallocation_count);
        free(g_memory_pool.pool_memory);
        memset(&g_memory_pool, 0, sizeof(g_memory_pool));
    }
}

void* betanet_mempool_alloc(size_t size) {
    // For now, just use regular malloc with tracking
    // In a production implementation, this would use the memory pool
    g_memory_pool.allocation_count++;
    return malloc(size);
}

void betanet_mempool_free(void* ptr) {
    if (ptr) {
        g_memory_pool.deallocation_count++;
        free(ptr);
    }
}

void betanet_mempool_get_stats(uint32_t* total_blocks, uint32_t* free_blocks, 
                               uint32_t* allocations, uint32_t* deallocations) {
    if (total_blocks) *total_blocks = g_memory_pool.total_blocks;
    if (free_blocks) *free_blocks = g_memory_pool.free_blocks_count;
    if (allocations) *allocations = g_memory_pool.allocation_count;
    if (deallocations) *deallocations = g_memory_pool.deallocation_count;
}

// =====================
// Enhanced Error Recovery
// =====================

error_recovery_action_t betanet_handle_error(error_context_t* error_ctx) {
    if (!error_ctx) return ERROR_RECOVERY_ABORT;
    
    time_t current_time = get_current_time_ms();
    
    // Record error metrics
    betanet_metrics_record_error(error_ctx->error_code, true);
    
    // Determine recovery action based on error type and history
    if (error_ctx->retry_count >= 3) {
        printf("[perf] Max retries exceeded for error %d\n", error_ctx->error_code);
        return ERROR_RECOVERY_ABORT;
    }
    
    // Check error frequency
    if (error_ctx->first_error == 0) {
        error_ctx->first_error = current_time;
    }
    error_ctx->last_error = current_time;
    
    // If errors are happening too frequently, abort
    if ((current_time - error_ctx->first_error) < 5000 && error_ctx->retry_count > 1) {
        printf("[perf] Error frequency too high, aborting\n");
        return ERROR_RECOVERY_ABORT;
    }
    
    // Determine action based on error code
    switch (error_ctx->error_code) {
        case ECONNREFUSED:
        case ETIMEDOUT:
            return ERROR_RECOVERY_RETRY;
            
        case ECONNRESET:
        case EPIPE:
            return ERROR_RECOVERY_RECONNECT;
            
        default:
            if (error_ctx->retry_count < 2) {
                return ERROR_RECOVERY_RETRY;
            }
            return ERROR_RECOVERY_ABORT;
    }
}

int betanet_retry_connection(htx_ctx_t* ctx, const char* host, uint16_t port, 
                             const char* alpn, int max_retries) {
    if (!ctx || !host) return -1;
    
    error_context_t error_ctx = {0};
    
    for (int retry = 0; retry <= max_retries; retry++) {
        if (retry > 0) {
            // Exponential backoff: 100ms, 200ms, 400ms, 800ms, ...
            int delay_ms = 100 * (1 << (retry - 1));
            if (delay_ms > 5000) delay_ms = 5000; // Cap at 5 seconds
            
            printf("[perf] Retrying connection in %dms (attempt %d/%d)\n", 
                   delay_ms, retry + 1, max_retries + 1);
            
#ifdef _WIN32
            Sleep(delay_ms);
#else
            usleep(delay_ms * 1000);
#endif
        }
        
        // Attempt connection
        int result = htx_connect(ctx, host, port, alpn);
        if (result == 0) {
            printf("[perf] Connection successful on attempt %d\n", retry + 1);
            betanet_metrics_record_connection(true, 0);
            return 0;
        }
        
        // Handle the error
        error_ctx.error_code = result;
        error_ctx.retry_count = retry;
        error_ctx.failed_ctx = ctx;
        
        error_recovery_action_t action = betanet_handle_error(&error_ctx);
        if (action == ERROR_RECOVERY_ABORT) {
            printf("[perf] Aborting connection attempts after %d tries\n", retry + 1);
            break;
        }
    }
    
    betanet_metrics_record_connection(false, 0);
    return -1;
}

bool betanet_connection_is_healthy(htx_ctx_t* ctx) {
    if (!ctx || !ctx->is_connected) return false;
    
    // For TCP connections, check if socket is still valid
    if (ctx->transport == HTX_TRANSPORT_TCP) {
        int sockfd = ctx->state.tcp.sockfd;
        if (sockfd < 0) return false;
        
        // Use select to check socket status
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sockfd, &write_fds);
        
        struct timeval timeout = {0, 0}; // Non-blocking
        int result = select(sockfd + 1, NULL, &write_fds, NULL, &timeout);
        
        return (result >= 0 && FD_ISSET(sockfd, &write_fds));
    }
    
    return true;
}

int betanet_repair_connection(htx_ctx_t* ctx) {
    if (!ctx) return -1;
    
    printf("[perf] Attempting connection repair\n");
    
    // For now, just mark as disconnected and let the caller reconnect
    ctx->is_connected = 0;
    
    return 0;
}

// =====================
// Performance Metrics
// =====================

int betanet_metrics_init(void) {
    memset(&g_metrics, 0, sizeof(g_metrics));
    g_metrics.start_time = get_current_time_ms();
    g_metrics.last_update = g_metrics.start_time;
    printf("[perf] Performance metrics initialized\n");
    return 0;
}

const performance_metrics_t* betanet_metrics_get(void) {
    g_metrics.last_update = get_current_time_ms();
    return &g_metrics;
}

void betanet_metrics_record_connection(bool successful, double duration_ms) {
    g_metrics.total_connections++;
    if (successful) {
        g_metrics.successful_connections++;
        
        // Update average connection time
        if (duration_ms > 0) {
            double total_time = g_metrics.avg_connection_time_ms * (g_metrics.successful_connections - 1);
            g_metrics.avg_connection_time_ms = (total_time + duration_ms) / g_metrics.successful_connections;
        }
    } else {
        g_metrics.failed_connections++;
    }
}

void betanet_metrics_record_transfer(size_t bytes_sent, size_t bytes_received) {
    g_metrics.bytes_sent += bytes_sent;
    g_metrics.bytes_received += bytes_received;
    if (bytes_sent > 0) g_metrics.messages_sent++;
    if (bytes_received > 0) g_metrics.messages_received++;
}

void betanet_metrics_record_error(int error_code, bool recoverable) {
    g_metrics.total_errors++;
    if (recoverable) {
        g_metrics.recoverable_errors++;
    } else {
        g_metrics.critical_errors++;
    }
}

void betanet_metrics_reset(void) {
    time_t start_time = g_metrics.start_time;
    memset(&g_metrics, 0, sizeof(g_metrics));
    g_metrics.start_time = start_time;
    g_metrics.last_update = get_current_time_ms();
    printf("[perf] Performance metrics reset\n");
}

void betanet_metrics_print_report(void) {
    const performance_metrics_t* metrics = betanet_metrics_get();
    time_t uptime_ms = metrics->last_update - metrics->start_time;
    double uptime_sec = uptime_ms / 1000.0;
    
    printf("\n=== BetaNet Performance Report ===\n");
    printf("Uptime: %.2f seconds\n", uptime_sec);
    printf("\nConnection Metrics:\n");
    printf("  Total connections: %llu\n", (unsigned long long)metrics->total_connections);
    printf("  Successful: %llu (%.1f%%)\n", 
           (unsigned long long)metrics->successful_connections,
           metrics->total_connections > 0 ? 
           (100.0 * metrics->successful_connections / metrics->total_connections) : 0);
    printf("  Failed: %llu\n", (unsigned long long)metrics->failed_connections);
    printf("  Reuses: %llu\n", (unsigned long long)metrics->connection_reuses);
    printf("  Avg connection time: %.2f ms\n", metrics->avg_connection_time_ms);
    
    printf("\nData Transfer:\n");
    printf("  Bytes sent: %llu\n", (unsigned long long)metrics->bytes_sent);
    printf("  Bytes received: %llu\n", (unsigned long long)metrics->bytes_received);
    printf("  Messages sent: %llu\n", (unsigned long long)metrics->messages_sent);
    printf("  Messages received: %llu\n", (unsigned long long)metrics->messages_received);
    
    printf("\nError Metrics:\n");
    printf("  Total errors: %llu\n", (unsigned long long)metrics->total_errors);
    printf("  Recoverable: %llu\n", (unsigned long long)metrics->recoverable_errors);
    printf("  Critical: %llu\n", (unsigned long long)metrics->critical_errors);
    
    // Pool statistics
    uint32_t active, total, reuse_rate;
    betanet_pool_get_stats(&active, &total, &reuse_rate);
    printf("\nConnection Pool:\n");
    printf("  Active connections: %d\n", active);
    printf("  Total created: %d\n", total);
    printf("  Reuse rate: %d%%\n", reuse_rate);
    
    // Memory statistics
    uint32_t total_blocks, free_blocks, allocations, deallocations;
    betanet_mempool_get_stats(&total_blocks, &free_blocks, &allocations, &deallocations);
    printf("\nMemory Pool:\n");
    printf("  Allocations: %d\n", allocations);
    printf("  Deallocations: %d\n", deallocations);
    printf("  Outstanding: %d\n", allocations - deallocations);
    
    printf("================================\n\n");
}

// =====================
// Timeout Management
// =====================

void betanet_set_timeouts(time_t connect_ms, time_t handshake_ms, 
                          time_t read_ms, time_t write_ms, time_t keepalive_ms) {
    g_timeouts.connect_timeout = connect_ms;
    g_timeouts.handshake_timeout = handshake_ms;
    g_timeouts.read_timeout = read_ms;
    g_timeouts.write_timeout = write_ms;
    g_timeouts.keepalive_timeout = keepalive_ms;
    
    printf("[perf] Updated timeouts: connect=%lldms, handshake=%lldms, read=%lldms, write=%lldms, keepalive=%lldms\n",
           (long long)connect_ms, (long long)handshake_ms, (long long)read_ms, (long long)write_ms, (long long)keepalive_ms);
}

const timeout_manager_t* betanet_get_timeouts(void) {
    return &g_timeouts;
}

bool betanet_check_timeout(time_t start_time, time_t timeout_ms) {
    time_t elapsed = get_current_time_ms() - start_time;
    return elapsed >= timeout_ms;
}

// =====================
// Public API Initialization
// =====================

/**
 * Initialize all performance subsystems
 */
int betanet_performance_init(void) {
    if (g_performance_initialized) {
        printf("[perf] Performance subsystems already initialized\n");
        return 0;
    }
    
    printf("[perf] Initializing BetaNet performance optimizations...\n");
    
    if (betanet_pool_init() != 0) {
        printf("[perf] Failed to initialize connection pool\n");
        return -1;
    }
    
    if (betanet_mempool_init(0) != 0) {
        printf("[perf] Failed to initialize memory pool\n");
        betanet_pool_shutdown();
        return -1;
    }
    
    if (betanet_metrics_init() != 0) {
        printf("[perf] Failed to initialize metrics\n");
        betanet_mempool_shutdown();
        betanet_pool_shutdown();
        return -1;
    }
    
    g_performance_initialized = true;
    printf("[perf] All performance subsystems initialized successfully\n");
    return 0;
}

/**
 * Shutdown all performance subsystems
 */
void betanet_performance_shutdown(void) {
    if (!g_performance_initialized) return;
    
    printf("[perf] Shutting down BetaNet performance optimizations...\n");
    
    // Print final performance report
    betanet_metrics_print_report();
    
    betanet_pool_shutdown();
    betanet_mempool_shutdown();
    
    g_performance_initialized = false;
    printf("[perf] Performance subsystems shutdown complete\n");
}
