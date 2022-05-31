#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define STDIN_FILENO 0
#define STDOUT_FILENO 1
void syscall_init (void);

/* #### Process identifier. ##### 수정 */
typedef int pid_t;

#endif /* userprog/syscall.h */
