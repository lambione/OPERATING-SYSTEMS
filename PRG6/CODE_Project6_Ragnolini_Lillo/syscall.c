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
#include "userprog/pagedir.h"
#include "lib/kernel/hash.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "filesys/inode.h"


/* prototypes for the functions */
static void syscall_handler(struct intr_frame *);

static void syscall_exit (uint32_t *arguments, uint32_t *eax);
static void syscall_wait (uint32_t *arguments, uint32_t *eax);
static void syscall_exec (uint32_t *arguments, uint32_t *eax);


static void syscall_write (struct intr_frame *f);
static void syscall_create (struct intr_frame *f);
static void syscall_remove(struct intr_frame *f);
static void syscall_open (struct intr_frame *f);
static void syscall_close (struct intr_frame *f);
static void syscall_read (struct intr_frame *f);
static void syscall_seek (struct intr_frame *f);
static void syscall_tell (struct intr_frame *f);
static void syscall_filesize (struct intr_frame *f);
static void syscall_halt (struct intr_frame *f);

typedef void (*handler) (uint32_t *, uint32_t *);
typedef void (*handler_frame) (struct intr_frame *);

void exit_with_status(int status);
static bool validate_arguments (uint32_t *arguments, int num_arguments);

#define BAD_STATUS -1
#define SYSCALL_MAX_CODE 19
static handler call[SYSCALL_MAX_CODE + 1];
static handler_frame call_frame[SYSCALL_MAX_CODE + 1];


/* declare locks and fyles */
struct hash fd_table;
struct lock filesys_lock;
/* File descriptors numbered 0 and 1 are reserved for the console, documentation says*/
int next_fd = 2;

/* we need a struct to handle the the fd's for the specific items */
struct file_with_fd {
  struct file * file;
  struct hash_elem elem;
  int fd;
  char * thread_name;
};


static unsigned item_hash (const struct hash_elem* e, void* aux) {
  struct file_with_fd* i = hash_entry(e, struct file_with_fd, elem);
  return hash_int(i->fd);
}

static bool item_compare(const struct hash_elem* a, const struct hash_elem* b, void* aux) {
  struct file_with_fd *i_a = hash_entry(a, struct file_with_fd, elem);
  struct file_with_fd *i_b = hash_entry(b, struct file_with_fd, elem);
  return i_a->fd < i_b->fd;
}


void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  memset(call, 0, SYSCALL_MAX_CODE + 1);

  memset(call_frame, 0, SYSCALL_MAX_CODE + 1);

  call_frame[SYS_WRITE] = syscall_write;
  call_frame[SYS_CREATE] = syscall_create;
  call_frame[SYS_REMOVE] = syscall_remove;
  call_frame[SYS_OPEN] = syscall_open;
  call_frame[SYS_CLOSE] = syscall_close;
  call_frame[SYS_READ] = syscall_read;
  call_frame[SYS_SEEK] = syscall_seek;
  call_frame[SYS_TELL] = syscall_tell;
  call_frame[SYS_FILESIZE] = syscall_filesize;
  call_frame[SYS_HALT] = syscall_halt;

  call[SYS_EXIT] = syscall_exit;
  call[SYS_WAIT]  = syscall_wait;  
  call[SYS_EXEC]  = syscall_exec;


  hash_init(&fd_table, item_hash, item_compare, NULL);
  lock_init(&filesys_lock);
}

static void
syscall_handler(struct intr_frame *f)
{ 
  /* if f is not a valid pointer then just delegate to the approriate helper function to exit with appropriate exit status */
  if (f == NULL)
    exit_with_status(BAD_STATUS);
  /* we check if the first argument on the stack is valid with esp which points at the top of the stack, this will be the system call number */
  uint32_t* arguments = ((uint32_t*) f->esp);
  if(!validate_arguments(arguments, 1)) exit_with_status(BAD_STATUS);

  if(*arguments == SYS_EXIT || *arguments == SYS_EXEC || *arguments == SYS_WAIT) {
    call[*arguments](++arguments, &(f->eax));
  } else {
    call_frame[*arguments](f);
  }
}

//new implementation


static void syscall_create (struct intr_frame *f) {

  /* retrieve params */
  uint32_t* eax = &(f->eax);
  unsigned int * stack = f->esp;
  const char * file = stack[1];
  unsigned initial_size = stack[2];

  /* check params */
  if (!file || !is_user_vaddr(file)) {
      *eax = false;
      exit_with_status(BAD_STATUS);
      return;
  }

  if(pagedir_get_page (thread_current ()->pagedir, file) == NULL ) {
    *eax = false;
    exit_with_status(BAD_STATUS);
    return;
  }

  if (initial_size < 0) {
      *eax = false;
      return;
  }

  /* Acquire lock to ensure synchronization */
  lock_acquire(&filesys_lock);
  *eax = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
}

static void 
syscall_remove (struct intr_frame *f){

  /* retrieve params */
  uint32_t* eax = &(f->eax);
  unsigned int * stack = f->esp;
  const char * file = stack[1];

  /* check params */
  if (!file || !is_user_vaddr(file)) {
      *eax = false;
      return;
  }

  lock_acquire (&filesys_lock);
  *eax = filesys_remove(file);
  lock_release (&filesys_lock);
}

static void
syscall_open (struct intr_frame *f){

  /* retrieve params */
  uint32_t* eax = &(f->eax);
  unsigned int * stack = f->esp;
  const char * file = stack[1];

  /* check params */
  if (!file || !is_user_vaddr(file)) {
      *eax = false;
      exit_with_status(BAD_STATUS);
      return;
  }


  if (pagedir_get_page (thread_current ()->pagedir, file) == NULL) {
    *eax = false;
    exit_with_status(BAD_STATUS);
    return;
  }

  if(strlen(file) < 1){
    *eax = -1;
    return;
  }

  /* allocate memory for the struct */
  struct file_with_fd * allocated_fd = malloc(sizeof(struct file_with_fd));
  /* check that allocation didn't fail*/
  if (!allocated_fd) {
    *eax = -1;
    return;
  }
  /* acquire lock so that you are sure that you enable synchronization */
  lock_acquire (&filesys_lock);

  struct file* fopen;
  fopen = filesys_open(file);
  if (!fopen) {
    free(allocated_fd);
    lock_release (&filesys_lock);
    *eax = -1;
    return;
  }
  /* fill the struct and insert maping in hash, return file descriptor */
  allocated_fd->file = fopen; 
  allocated_fd->fd = next_fd++;
  allocated_fd->thread_name = thread_current()->name;
  hash_insert(&fd_table, &allocated_fd->elem);
  *eax = allocated_fd->fd;
  lock_release (&filesys_lock);
}

static void
syscall_close(struct intr_frame *f){

   /* retrieve params */
  uint32_t* eax = &(f->eax);
  unsigned int * stack = f->esp;
  int fd = stack[1];

  lock_acquire (&filesys_lock);
  /* if there is no entry in the hash table do nothing and release lock*/
  struct file_with_fd closing_file;
  closing_file.fd = fd;
  struct hash_elem* helem = hash_find(&fd_table, &closing_file.elem);
  if (helem) {
    struct file_with_fd* file_to_close = hash_entry(helem, struct file_with_fd, elem);
    struct file * ff = file_to_close->file;
    if(strcmp(thread_current()->name, file_to_close->thread_name) == 0) {
      file_close(ff);
      hash_delete(&fd_table, &(file_to_close->elem));
      free(file_to_close);   
    }
  }
  lock_release (&filesys_lock);
}

static void
syscall_filesize(struct intr_frame *f){

  /* retrieve params */
  uint32_t* eax = &(f->eax);
  unsigned int * stack = f->esp;
  int fd = stack[1];
  
  lock_acquire (&filesys_lock);
  struct file_with_fd search_fd;
  search_fd.fd = fd;
  struct hash_elem* helem = hash_find(&fd_table, &search_fd.elem);
  if (!helem) {
    *eax = 0;
    lock_release(&filesys_lock);
    return;
  }
  /* otherwise find it in the hash table and then returns its size*/
  struct file_with_fd* file_for_size = hash_entry(helem, struct file_with_fd, elem);
  if(!file_for_size) {
    *eax = 0;
    lock_release (&filesys_lock);
    return;
  }
  /* return correct value */
  *eax = file_length(file_for_size->file);
  lock_release (&filesys_lock);

}

static void
syscall_read(struct intr_frame *f){
  
  lock_acquire (&filesys_lock);

  /* retrieve params */
  uint32_t* eax = &(f->eax);
  unsigned int * stack = f->esp;
  int fd = stack[1];
  void * buffer = stack[2];
  unsigned size = stack[3];

  /* check params */
  if (!buffer || !is_user_vaddr(buffer)) {
      *eax = -1;
      exit_with_status(BAD_STATUS);
      return;
  } 

  if(pagedir_get_page (thread_current ()->pagedir, buffer) == NULL ) {
    *eax = -1;
    exit_with_status(BAD_STATUS);
    return;
  }

  /* use return call function value initiliazied to -1*/
  int ret = -1;
  if(fd==0) { 
    int i;
    for (i = 0; i < size; i++) {
      if (input_getc() == '\0') break;
    }
    ret = i;
  } else {
    /* retrieve the file from the map */
    struct file_with_fd reading_file;
    reading_file.fd = fd;
    struct hash_elem* helem = hash_find(&fd_table, &reading_file.elem);
    if (!helem){
      *eax = ret;
      lock_release (&filesys_lock);
      return;
    } 
    /* if it exists retrieve it and read it and save in return call variable the num of bytes read */
    struct file_with_fd * file_to_read = hash_entry(helem, struct file_with_fd, elem);
    if (file_to_read && file_to_read->file) {
      ret = file_read(file_to_read->file, buffer, size);
    }
    /*if it will fail/does not exist then ret is already -1 */
  }
  *eax = ret;
  lock_release (&filesys_lock);

}

static void
syscall_write(struct intr_frame *f){ 

  lock_acquire (&filesys_lock);
  /* retrieve params */
  uint32_t* eax = &(f->eax);
  unsigned int * stack = f->esp;
  int fd = stack[1];
  const void * buffer = stack[2];
  unsigned size = stack[3];

  /* check params */
  if (!buffer || !is_user_vaddr(buffer)) {
      *eax = -1;
      exit_with_status(BAD_STATUS);
      return;
  } 

  if(pagedir_get_page (thread_current ()->pagedir, buffer) == NULL ) {
    *eax = -1;
    lock_release(&filesys_lock);
    exit_with_status(BAD_STATUS);
    return;
  }

  if(fd == 1) {
    /* use appropriate function to print to stdout*/
    putbuf(buffer, size);
    /* save important stuff in this case the length of the buffer to eax*/
    *eax = size;
  } else {
    /* retrieve the file to write */
    struct file_with_fd file_to_write;
    file_to_write.fd = fd;
    struct hash_elem* helem = hash_find(&fd_table, &file_to_write.elem);
    if (helem) {
      struct file_with_fd* file_in_writing = hash_entry(helem, struct file_with_fd, elem);
      struct file * ff = file_in_writing->file;
      *eax = file_write(ff, buffer, size);
    } 
  }
  lock_release (&filesys_lock);
}

static void
syscall_seek(struct intr_frame *f){

  /* retrieve params */
  uint32_t* eax = &(f->eax);
  unsigned int * stack = f->esp;
  int fd = stack[1];
  unsigned position = stack[2];

  lock_acquire (&filesys_lock);
  /* try to retrieve the file if it doens't exist then release the lock*/
  struct file_with_fd seeked_file;
  seeked_file.fd = fd;
  struct hash_elem* helem = hash_find(&fd_table, &seeked_file.elem);
  if (!helem) {
    lock_release (&filesys_lock);
    return;
  }
  /* otherwise if it exists retrieve the file */
  struct file_with_fd* file_to_seek = hash_entry(helem, struct file_with_fd, elem);
  if(file_to_seek && file_to_seek->file) {
    file_seek(file_to_seek->file, position);
  }
  lock_release (&filesys_lock);

}

static void 
syscall_tell(struct intr_frame *f){

  /* retrieve params */
  uint32_t* eax = &(f->eax);
  unsigned int * stack = f->esp;
  int fd = stack[0];

  lock_acquire (&filesys_lock);
  unsigned int pos = 0;
  struct file_with_fd telled_file;
  telled_file.fd = fd;
  struct hash_elem* helem = hash_find(&fd_table, &telled_file.elem);
  if (!helem) {
    *eax = pos;
    lock_release(&filesys_lock);
    return;
  }
  /* otherwise actually retrieve the file */
  struct file_with_fd* file_to_tell = hash_entry(helem, struct file_with_fd, elem);
  if(file_to_tell && file_to_tell->file) {
    pos = file_tell(file_to_tell->file);
  }
  *eax = pos;
  lock_release (&filesys_lock);
}

/*halt system call*/
static void
syscall_halt(struct intr_frame *f){
   shutdown_power_off();
}


//helper functions

/* previous sys call implementation */

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

void
exit_with_status (int status)
{
  /*retrieve the current thread and set to it the status that we passed as argument to the function*/
  struct thread * t = thread_current();
  t->exit_status = status;
  /*print the exit status of the thread*/
  /*after this delegate to thread_exit method to finish exit */
  thread_exit ();
}

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
