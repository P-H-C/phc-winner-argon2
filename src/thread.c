#include "thread.h"
#if defined(_MSC_VER)
#include <Windows.h>
#endif

int argon2_thread_create(argon2_thread_handle_t * handle,
                         argon2_thread_func_t func, void * args)
{
  if (NULL == handle || func == NULL) {
    return -1;
  }
#if defined(_MSC_VER)
  *handle = _beginthreadex(NULL, 0, func, args, 0, NULL);
  return *handle != 0 ? 0 : -1;
#else
  return pthread_create(handle, NULL, func, args);
#endif
}

int argon2_thread_join(argon2_thread_handle_t handle)
{
#if defined(_MSC_VER)
  if(WaitForSingleObject((HANDLE)handle, INFINITE) == WAIT_OBJECT_0) {
    return CloseHandle((HANDLE)handle) != 0 ? 0 : -1;
  }
  return -1;
#else
  return pthread_join(handle, NULL);
#endif
}

void argon2_thread_exit(void)
{
#if defined(_MSC_VER)
  _endthreadex(0);
#else
  pthread_exit(NULL);
#endif
}
