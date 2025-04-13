#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "devices/shutdown.h"

static void syscall_handler(struct intr_frame *);

typedef void (*handler)(struct intr_frame *);
static void syscall_exit(struct intr_frame *f);
static void syscall_write(struct intr_frame *f);

#define SYSCALL_MAX_CODE 19
static handler call[SYSCALL_MAX_CODE + 1];

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  memset(call, 0, SYSCALL_MAX_CODE + 1);

  /* initialize the handler providing the function to handle, in our case only write and exit*/
  call[SYS_EXIT] = syscall_exit;
  call[SYS_WRITE] = syscall_write;
}

static void
syscall_handler(struct intr_frame *f)
{
  /*handle the calls requested that are the write and thfe exit with the handler */
  /*retrieve the system call number from the stack*/
  int syscall_num = *(int *)f->esp;
  /*call the appropriate function based on the sys call number*/
  call[syscall_num](f);
}

/* function that handles the exit system call*/
static void
syscall_exit(struct intr_frame *f)
{
  /*f->esp points to the top of the stack so we point now to the top of the stack*/
  int *stk = f->esp;
  /* retrieve the current thread */
  struct thread *t = thread_current();
  /* retrieve the exit status from the stack and place it into the thread struct*/
  int *tmp = stk + 1;
  t->exit_status = *tmp;
  /* call the apropriate function to conclude the thread exit*/
  thread_exit();
}

/* function that handles the write system call*/
static void
syscall_write(struct intr_frame *f)
{
  /*we need to go through the stack to retrive all the needed paramteres pushed before from the program*/
  int *stk = f->esp;
  /*retrieve the buffer*/
  int *tmp1 = stk + 2;
  char *buffer = *tmp1;
  /*retrieve the length of the buffer*/
  int *tmp2 = stk + 3;
  int len = *tmp2;
  /*use appropriate function to print on the stdout in one go the buffer context*/
  putbuf(buffer, len);
  /*save in the important information, in our case the length into the f->eax*/
  f->eax = len;
}