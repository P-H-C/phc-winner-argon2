#include "thread.h"
#include <Windows.h>

int argon2_thread_create(argon2_thread_handle_t * handle, argon2_thread_func_t func, void * args)
{
  if (NULL == handle) {
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
  switch (WaitForSingleObject((HANDLE)handle, INFINITE)) {
  default:
    return -1;
  case WAIT_OBJECT_0:
    return CloseHandle((HANDLE)handle) != 0 ? 0 : -1;
  }
#else
  return pthread_join(handle, NULL);
#endif
}

int argon2_thread_exit(void)
{
#if defined(_MSC_VER)
  _endthreadex(0);
#else
  pthread_exit(NULL);
#endif
  return 0;
}
