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

//added
/* prototypes for the functions */
static void syscall_handler(struct intr_frame *);
static void syscall_exit (uint32_t *arguments, uint32_t *eax);
static void syscall_write (uint32_t *arguments, uint32_t *eax);
static void syscall_wait (uint32_t *arguments, uint32_t *eax);
static void syscall_exec (uint32_t *arguments, uint32_t *eax);
typedef void (*handler) (uint32_t *, uint32_t *);
void exit_with_status(int status);
static bool validate_arguments (uint32_t *arguments, int num_arguments);

//added
#define BAD_STATUS -1

#define SYSCALL_MAX_CODE 19
static handler call[SYSCALL_MAX_CODE + 1];

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  memset(call, 0, SYSCALL_MAX_CODE + 1);

  /* initialize the handler providing the function to handle, in our case only write and exit*/
  call[SYS_EXIT] = syscall_exit;
  call[SYS_WRITE] = syscall_write;
  //added
  call[SYS_WAIT]  = syscall_wait;  
  call[SYS_EXEC]  = syscall_exec;  
}

static void
syscall_handler(struct intr_frame *f)
{
  // added 
  /* if f is not a valid pointer then just delegate to the approriate helper function to exit with appropriate exit status */
  if (f == NULL)
    exit_with_status(BAD_STATUS);
  /* we check if the first argument on the stack is valid with esp which points at the top of the stack, this will be the system call number */
  uint32_t* arguments = ((uint32_t*) f->esp);
  int arg_to_check_num = 1;
  /* we check if the argument is valid by delegating to the appropriate helper function */
  if (!validate_arguments (arguments, arg_to_check_num))
    exit_with_status(BAD_STATUS);
  /* retrieve sys call number which is what is arguments pointing to and enter the call handler with it*/
  /* now it would be useless to pass the sys call number to the handler so we make arguments point to the actual first argument by incrementing the pointer */
  call[*arguments](++arguments, &(f->eax));
}

/* function that handles the exit system call*/
// changed argument passing
static void
syscall_exit(uint32_t *arguments, uint32_t *eax)
{
  //added
  /* if we are in this system call then we know that the arguments on the stack being pushed is only one*/
  int arg_on_stack = 1;
  /* initialize a status where we will save the status code*/
  int status;
  /* we check if the argument is valid by delegating to the appropriate helper function */
  if (validate_arguments(arguments, arg_on_stack))
    /* if the argument is valid the we retrieve it, we know that the exit system call puts on the stack just an 
       argument (watch syscall.c in /lib/user) which is a status code so we retrieve it */
    status = (int) *arguments;
  else
    /* if the argument is not valid then place the BAD_STATUS code in the status */
    status = BAD_STATUS;

  /* after that we delegate to the appropriate functio to have an appropriate exit */
  exit_with_status(status);
}


/* function that handles the write system call*/
// changed the argument passing 
static void
syscall_write(uint32_t *arguments, uint32_t *eax)
{
  // added
  /* if we are in this system call then we know that the arguments on the stack being pushed are three */
  int arg_on_stack = 3;
  /* delegate to helper functions the check for the validity of the arguments, we also check the address of the buffer to see if its a safe one*/
  if (!validate_arguments(arguments, arg_on_stack) || (pagedir_get_page(thread_current()->pagedir, arguments[1]) == NULL))
    /* in case the validity of the arguments or the buffer address is not safe we need to exit with BAD_STATUS as status*/
    exit_with_status(BAD_STATUS);

  //added
  /* now we need to pop the arguments from the stack thatthe syscall pushed to retrieve the fd, the buffer and its len*/
  /*firstwe retrieve the fd which should be 1 since we are in a write syscall handling*/
  int fd = (int) arguments[0];
  /* once retrieved the fd we assure that it is 1*/
  ASSERT(fd == 1);
  /* the we retrieve the actual buffer */
  char *buffer = (char *) arguments[1];
  /*then we retrieve the length of the buffer*/
  int len = (int) arguments[2];

  //added
  /* use appropriate function to print to stdout*/
  putbuf(buffer, len);
  /* save important stuff in this case the length of the buffer to eax*/
  *eax = len;
}

//added
/* function that handles the wait system call*/
static void
syscall_wait (uint32_t *argument, uint32_t *eax) {

  /* if we are in this system call then we know that the arguments on the stack being pushed is only one (watch syscall.c in /lib/user)*/
  int arg_on_stack = 1;

  /* check that arguments are valid by delegating to helper function*/
  if (!validate_arguments(argument, arg_on_stack))
    /* if they are not valid exit with status BAD_STATUS*/
    exit_with_status(BAD_STATUS);

  /*  if arguments are valid just call appropriate function and save the output into eax*/
  uint32_t result = process_wait((int) *argument);
  *eax = result;
}

//added
/* function that handles the exec system call*/
static void
syscall_exec (uint32_t *argument, uint32_t *eax) {

  /* if we are in this system call then we know that the arguments on the stack being pushed is only one (watch syscall.c in /lib/user)*/
  int arg_on_stack = 1;
  /* check validity of the arguments and pointers as requested */
  if (!validate_arguments(argument, arg_on_stack) || (pagedir_get_page(thread_current()->pagedir, *argument) == NULL))
    /*exit with status BAD_STATUS in case not*/
    exit_with_status(BAD_STATUS);

  /*delegate to approriate function that will handle the execution and save output to eax*/
  uint32_t result = process_execute((char *) *argument);
  *eax = result;
}


//added
static bool
validate_arguments (uint32_t *arguments, int num_arguments)
{

  /* The user may provide an invalid pointer in a syscall
      • a null pointer
      • a pointer to kernel address space
      • a pointer to unmapped virtual memory
     We should control this*/

  /* we then need to check that what the user passed is ok and not whats in the list above */
  int i;
  for (i = 0; i < num_arguments + 1; i++, arguments++) {
    /* is_user_vadr : Returns true if VADDR is a user virtual address. 
       pagedir_get_page : Looks up the physical address that corresponds to user virtual
                          address UADDR in PD.  Returns the kernel virtual address
                          corresponding to that physical address, or a null pointer if UADDR is unmapped.
      we also check if the pointer is null  */
    if ( !(is_user_vaddr(arguments) && pagedir_get_page(thread_current()->pagedir, arguments) != NULL && arguments != NULL)) {
      return false;
    } 
  }
  return true;
}

//added
void
exit_with_status (int status)
{
  /*retrieve the current thread and set to it the status that we passed as argument to the function*/
  struct thread * t = thread_current();
  t->exit_status = status;
  /*print the exit status of the thread*/
  printf("%s: exit(%d)\n", thread_current ()->name, status);
  /*after this delegate to thread_exit method to finish exit */
  thread_exit ();
}