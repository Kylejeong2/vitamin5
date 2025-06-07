#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stddef.h>  

void syscall_init(void);

void validate_user_addr(const void *addr);

void validate_user_buffer(const void *buffer, size_t size);

void validate_user_string(const char *str);

void validate_user_ptr(const void *ptr, size_t size);

void syscall_exit(int status);

#endif /* userprog/syscall.h */
