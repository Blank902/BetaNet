#ifndef BETANET_PLATFORM_H
#define BETANET_PLATFORM_H

/**
 * Platform compatibility layer for Windows/Linux/macOS
 */

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <io.h>
    
    // Windows doesn't have unistd.h
    #define close(fd) closesocket(fd)
    #define ssize_t int
    
    // Socket compatibility
    typedef int socklen_t;
    
    // Threading compatibility
    typedef HANDLE thread_t;
    typedef DWORD thread_return_t;
    #define thread_return(val) return 0
    #define thread_create(thread, func, arg) do { \
        *(thread) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(func), (arg), 0, NULL); \
    } while(0)
    #define thread_join(thread, retval) WaitForSingleObject((thread), INFINITE)
    #define thread_sleep_ms(ms) Sleep(ms)
    
    #pragma comment(lib, "ws2_32.lib")
    
#else
    #include <unistd.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <pthread.h>
    
    // Threading compatibility  
    typedef pthread_t thread_t;
    typedef void* thread_return_t;
    #define thread_return(val) return (val)
    #define thread_create(thread, func, arg) pthread_create((thread), NULL, (func), (arg))
    #define thread_join(thread, retval) pthread_join((thread), (retval))
    #define thread_sleep_ms(ms) usleep((ms) * 1000)
#endif

#include <time.h>
#include <errno.h>

// Cross-platform initialization
static inline int betanet_platform_init(void) {
#ifdef _WIN32
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
    return 0;
#endif
}

static inline void betanet_platform_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

#endif /* BETANET_PLATFORM_H */
