#include "thread.h"
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "threads/fpr_arith.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

static struct list sleep_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* stores the system load (in number of ready+running threads per second in the last minute), initialized to 0*/
FPReal load_avg;

/*range of values for the nice var*/
int MIN_NICE = -20;
int MAX_NICE = 20;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame
{
  void *eip;             /* Return address. */
  thread_func *function; /* Function to call. */
  void *aux;             /* Auxiliary data for function. */
};

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4          /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *running_thread(void);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static bool is_thread(struct thread *) UNUSED;
static void *alloc_frame(struct thread *, size_t size);
static void schedule(void);
void thread_schedule_tail(struct thread *prev);
static tid_t allocate_tid(void);
void check_for_sleeping_threads(void);
bool compare_threads(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
void check_priority_range(struct thread *t, void *AUX UNUSED);

/*auxiliary that checks that the priority lies in the correct range*/
void check_priority_range(struct thread *t, void *AUX UNUSED)
{
  if (t->priority > PRI_MAX)
    t->priority = PRI_MAX;
  else if (t->priority < PRI_MIN)
    t->priority = PRI_MIN;
}

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void thread_init(void)
{
  ASSERT(intr_get_level() == INTR_OFF);

  lock_init(&tid_lock);
  list_init(&ready_list);
  list_init(&sleep_list);
  list_init(&all_list);
  /*initialize load average to 0 and transform it into an FPReal*/
  load_avg = INT_TO_FPR(0);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread();
  init_thread(initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void)
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init(&idle_started, 0);
  thread_create("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down(&idle_started);
}

// prototypes
void update_recent_cpu(struct thread *, void *UNUSED);
void update_priority(struct thread *, void *UNUSED);

void update_recent_cpu(struct thread *t, void *aux UNUSED)
{
  /*assigning/reassiging the recent_cpu value to the thread based on the formula -> (2 ∗ load avg)/(2 ∗ load avg + 1) ∗ recent cpu + nice*/
  FPReal numerator = FPR_MUL_FPR(INT_TO_FPR(2), load_avg);
  FPReal denominator = FPR_ADD_INT(numerator, 1);
  FPReal division = FPR_DIV_FPR(numerator, denominator);
  t->recent_cpu = FPR_ADD_INT(FPR_MUL_FPR(division, t->recent_cpu), (t->nice));
}

void update_priority(struct thread *t, void *aux UNUSED)
{
  /*save the current priority which will become the old since we are updating it (maybe)*/
  int old = t->priority;
  /*update it w.r.t to the formula -> PRI MAX − (recent cpu/4) − (nice ∗ 2)*/
  t->priority = (PRI_MAX - FPR_TO_INT(FPR_DIV_INT(t->recent_cpu, 4)) - (t->nice * 2));
  /*check the correctness of the priority (it doesn't go out of bounds)*/
  check_priority_range(t, NULL);
  /*if priority was changed, the thread status is ready and the thread is not already the current one then we can re-insert it in the sorted list since it's position could be changed*/
  if (t->status != THREAD_RUNNING && t->status != THREAD_BLOCKED && t->status != THREAD_DYING && t != thread_current() && old != t->priority)
  {
    list_remove(&(t->elem));
    list_insert_ordered(&ready_list, &t->elem, compare_threads, NULL);
  }
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void)
{
  struct thread *t = thread_current();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return();

  check_for_sleeping_threads();

  /*if advance scheduler is active*/
  if (thread_mlfqs)
  {
    /*check that the current thread is not idle in order to increment by 1 its recent_cpu (we do it every interrrupt so everytime we are in this function)*/
    if (t != idle_thread)
    {
      FPR_INC(&(running_thread()->recent_cpu));
    }
    /*every fourth tick we update the priority of every thread*/
    if (timer_ticks() % 4 == 0)
    {
      thread_foreach(update_priority, NULL);
    }
    /*every second we update the load average w.r.t to the formula -> (59/60) ∗ load avg + (1/60) ∗ ready or running threads
      we update also the recent_cpu value to all the threads
    */
    if (timer_ticks() % TIMER_FREQ == 0)
    {
      /*count the number of ready and running threads by counting the elements in the ready_list adding also the current thread if it is not idle*/
      int ready_or_running_threads = list_size(&ready_list);
      if (thread_current() != idle_thread)
      {
        ready_or_running_threads++;
      }
      /*calculate load average and update it*/
      FPReal firstmul = FPR_MUL_FPR(FPR_DIV_FPR(INT_TO_FPR(59), INT_TO_FPR(60)), load_avg);
      FPReal secondmul = FPR_MUL_INT(FPR_DIV_FPR(INT_TO_FPR(1), INT_TO_FPR(60)), ready_or_running_threads);
      load_avg = FPR_ADD_FPR(firstmul, secondmul);
      // update
      thread_foreach(update_recent_cpu, NULL);
    }
  }
}

/* Prints thread statistics. */
void thread_print_stats(void)
{
  printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
         idle_ticks, kernel_ticks, user_ticks);
}

struct thread *
thread_get_by_tid(int tid)
{
  /*iterate over the all_list to search for the thread with the same tid passed in function*/
  struct list_elem *it;
  for (it = list_begin(&all_list);
       it != list_end(&all_list);
       it = list_next(it))
  {
    /*check the match by tid*/
    struct thread *tt = list_entry(it, struct thread, allelem);
    if (tt->tid == tid)
    {
      /*the match has been successfull so we return the matched thread*/
      return tt;
    }
  }
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t thread_create(const char *name, int priority,
                    thread_func *function, void *aux)
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT(function != NULL);

  /* Allocate thread. */
  t = palloc_get_page(PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread(t, name, priority);
  tid = t->tid = allocate_tid();

#ifdef USERPROG
  /* thread default exit code is an error value in 
     order to prevent a possible fail in the assignment of it */
  t->exit_status = TID_ERROR;
  /* assign parent to the newly created thread which will obviously be 
     the current running thread */
  t->parent = thread_current();
  /* used to let the child klnow if the parent is waiting or not for the completion */
  t->pwait = false;
#endif

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack'
     member cannot be observed. */
  old_level = intr_disable();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame(t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame(t, sizeof *ef);
  ef->eip = (void (*)(void))kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame(t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level(old_level);

  /* Add to run queue. */
  thread_unblock(t);

  /*check if the priority of the just created thread is greater
    than the current running thread, if so, we yield the current running one
  */
  if (t->priority > thread_get_priority())
  {
    thread_yield();
  }

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void)
{
  ASSERT(!intr_context());
  ASSERT(intr_get_level() == INTR_OFF);

  thread_current()->status = THREAD_BLOCKED;
  schedule();
}

bool compare_threads(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
  struct thread *thea = list_entry(a, struct thread, elem);
  struct thread *theb = list_entry(b, struct thread, elem);
  return (thea->priority > theb->priority);
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void thread_unblock(struct thread *t)
{
  enum intr_level old_level;

  ASSERT(is_thread(t));

  old_level = intr_disable();
  ASSERT(t->status == THREAD_BLOCKED);
  /*insert the thread in the ready list sorted by priority*/
  list_insert_ordered(&ready_list, &t->elem, compare_threads, NULL);
  // list_push_back (&ready_list, &t->elem);
  t->status = THREAD_READY;
  intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name(void)
{
  return thread_current()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current(void)
{
  struct thread *t = running_thread();

  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT(is_thread(t));
  ASSERT(t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void)
{
  return thread_current()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void)
{
  ASSERT(!intr_context());

#ifdef USERPROG
  process_exit();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable();
  list_remove(&thread_current()->allelem);
  thread_current()->status = THREAD_DYING;
  schedule();
  NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void thread_yield(void)
{
  struct thread *cur = thread_current();
  enum intr_level old_level;

  ASSERT(!intr_context());

  old_level = intr_disable();
  if (cur != idle_thread)
    /*insert the thread in the ready list sorted by priority*/
    list_insert_ordered(&ready_list, &cur->elem, compare_threads, NULL);
  // list_push_back (&ready_list, &cur->elem);
  cur->status = THREAD_READY;
  schedule();
  intr_set_level(old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void thread_foreach(thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT(intr_get_level() == INTR_OFF);

  for (e = list_begin(&all_list); e != list_end(&all_list);
       e = list_next(e))
  {
    struct thread *t = list_entry(e, struct thread, allelem);
    func(t, aux);
  }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void thread_set_priority(int new_priority)
{
  /*if we are not using the advance scheduler*/
  if (!thread_mlfqs)
  {
    /*retrieve current thread*/
    struct thread *curr = thread_current();
    /*if ready list is empty just let the current thread run*/
    if (list_empty(&ready_list))
    {
      /*just update the priority*/
      curr->priority = new_priority;
    }
    else
    {
      /*otherwise retrieve first element from ready list because it is sorted by priority*/
      struct list_elem *first = list_begin(&ready_list);
      struct thread *th = list_entry(first, struct thread, elem);
      /*assign new priority to current thread*/
      curr->priority = new_priority;
      /*if the current thread's priority is lower then the first in the queue which will be the thread with the highest priority, we yeld it*/
      if (curr->priority <= th->priority)
        thread_yield();
    }
  }
}

/* Returns the current thread's priority. */
int thread_get_priority(void)
{
  return thread_current()->priority;
}

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice)
{
  if (thread_mlfqs)
  {
    /*assert nice value is in the range of possible nice values */
    ASSERT(MIN_NICE <= nice && nice <= MAX_NICE);
    struct thread *cur = thread_current();
    cur->nice = nice;
    /*adjust priority*/
    update_priority(cur, NULL);

    /*check priorities with the ready list if the list is not empty*/
    if (!list_empty(&ready_list))
    {
      /*retrieve first element from ready list which is sorted by priority*/
      struct list_elem *first = list_begin(&ready_list);
      struct thread *th = list_entry(first, struct thread, elem);
      /*if the current thread's priority is lower then the first in the queue which will be the highest, we yeld it */
      if (cur->priority <= th->priority)
        thread_yield();
    }
  }
}

/* Returns the current thread's nice value. */
int thread_get_nice(void)
{
  return thread_current()->nice;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void)
{
  return FPR_TO_INT(FPR_MUL_INT(load_avg, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void)
{
  return FPR_TO_INT(thread_current()->recent_cpu) * 100;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle(void *idle_started_ UNUSED)
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current();
  sema_up(idle_started);

  for (;;)
  {
    /* Let someone else run. */
    intr_disable();
    thread_block();

    /* Re-enable interrupts and wait for the next one.

       The `sti' instruction disables interrupts until the
       completion of the next instruction, so these two
       instructions are executed atomically.  This atomicity is
       important; otherwise, an interrupt could be handled
       between re-enabling interrupts and waiting for the next
       one to occur, wasting as much as one clock tick worth of
       time.

       See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
       7.11.1 "HLT Instruction". */
    asm volatile("sti; hlt" : : : "memory");
  }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread(thread_func *function, void *aux)
{
  ASSERT(function != NULL);

  intr_enable(); /* The scheduler runs with interrupts off. */
  function(aux); /* Execute the thread function. */
  thread_exit(); /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread(void)
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm("mov %%esp, %0" : "=g"(esp));
  return pg_round_down(esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread(struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread(struct thread *t, const char *name, int priority)
{
  ASSERT(t != NULL);
  ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT(name != NULL);
  memset(t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;

#ifdef USERPROG
  /* the thread name should be just the filename that it executes, 
    excluding any additional arguments passed in command line */
  strcpyfw(t->name, name, 16);
#else
  /*otherwise just compute normal execution*/
  strlcpy(t->name, name, sizeof t->name);
#endif

  t->stack = (uint8_t *)t + PGSIZE;
  /*if we are not in advance scheduler*/
  if (!thread_mlfqs)
  {
    t->priority = priority;
  }
  else
  {
    /*if we are in advance scheduler*/
    t->recent_cpu = INT_TO_FPR(0);
    t->nice = 0;
  }
  t->magic = THREAD_MAGIC;
  list_push_back(&all_list, &t->allelem);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame(struct thread *t, size_t size)
{
  /* Stack data is always allocated in word-size units. */
  ASSERT(is_thread(t));
  ASSERT(size % sizeof(uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run(void)
{
  if (list_empty(&ready_list))
    return idle_thread;
  else
    return list_entry(list_pop_front(&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void thread_schedule_tail(struct thread *prev)
{
  struct thread *cur = running_thread();

  ASSERT(intr_get_level() == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread)
  {
    ASSERT(prev != cur);
    palloc_free_page(prev);
  }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule(void)
{
  struct thread *cur = running_thread();
  struct thread *next = next_thread_to_run();
  struct thread *prev = NULL;

  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(cur->status != THREAD_RUNNING);
  ASSERT(is_thread(next));

  if (cur != next)
    prev = switch_threads(cur, next);
  thread_schedule_tail(prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid(void)
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire(&tid_lock);
  tid = next_tid++;
  lock_release(&tid_lock);

  return tid;
}

void thread_sleep(int64_t wakeuptick)
{
  enum intr_level old_lvl = intr_disable();
  struct thread *curr = thread_current();
  curr->wakeup = wakeuptick;
  list_push_back(&sleep_list, &curr->elem);
  thread_block();
  intr_set_level(old_lvl);
}

// Checking if we should wake up some thread and do that
void check_for_sleeping_threads()
{
  enum intr_level old_lvl = intr_disable();
  struct list_elem *it = list_begin(&sleep_list);
  int64_t now = timer_ticks();

  while (it != list_end(&sleep_list))
  {
    struct thread *t = list_entry(it,
                                  struct thread, elem);
    struct list_elem *next = list_next(it);
    if (now >= t->wakeup)
    {
      list_remove(it);
      thread_unblock(t);
    }
    it = next;
  }

  intr_set_level(old_lvl);
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof(struct thread, stack);