#ifndef ARGON2_THREAD_H
#define ARGON2_THREAD_H

#if defined(_MSC_VER)
#include <process.h>
typedef _beginthreadex_proc_type argon2_thread_func_t;
typedef uintptr_t argon2_thread_handle_t;
#else
#include <pthread.h>
typedef void* (*argon2_thread_func_t)(void *);
typedef pthread_t argon2_thread_handle_t;
#endif

int argon2_thread_create(argon2_thread_handle_t * handle, argon2_thread_func_t func, void * args);
int argon2_thread_join(argon2_thread_handle_t handle);
int argon2_thread_exit(void);

#endif

