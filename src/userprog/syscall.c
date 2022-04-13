#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"     // filesys_OOO()
#include "devices/shutdown.h" // shutdown_power_off()
#include "userprog/process.h"
#include "threads/synch.h"
#include "filesys/off_t.h"
#include "filesys/file.h"
#include "lib/string.h"
#include "devices/input.h"

/*
  struct thread *holder; //thread holding lock
  struct sempahore semaphore;//binary semaphore
*/
typedef void sig_func(void);

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  // filesys->holder = NULL
  // sema_init(&filesys->semaphore, 1);
  //   sema->value = 1;
  //   list_init(&sema->waiters);
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf("syscall num : %d\n", *(uint32_t *)(f->esp));
  //printf("system call!\n");
  
  switch (*(uint32_t *)(f->esp))
    {
    case SYS_HALT: // call number : 0
      halt(); // shutdown pintos
      break;
 
    case SYS_EXIT: // call number : 1
      check_address(f->esp+4);
      exit(*(uint32_t *)(f->esp + 4)); // thread_current exit
      break;

    case SYS_EXEC: // call number : 2
      check_address(f->esp+4);
      f->eax = exec((const char *)*(uint32_t *)(f->esp+4));
      break;
      
    case SYS_WAIT: // call number : 3
      check_address(f->esp+4);
      f->eax=wait(*(uint32_t *)(f->esp+4));
      break;
      
    case SYS_CREATE: // call number : 4 
      check_address(f->esp+4);
      check_address(f->esp+8);
      f->eax=create((const char *)*(uint32_t *)(f->esp+4),
		    (unsigned)*(uint32_t *)(f->esp+8));
      break;
      
    case SYS_REMOVE: // call number : 5
      check_address(f->esp+4);
      f->eax=remove((const char *)*(uint32_t *)(f->esp+4));
      break;
      
    case SYS_OPEN: // call number : 6
      check_address(f->esp+4);
      f->eax =open((const char *)*(uint32_t *)(f->esp+4));
      break;

    case SYS_FILESIZE: // call number : 7
      check_address(f->esp+4);
      f->eax = filesize((int)*(uint32_t *)(f->esp+4));
      break;
      
    case SYS_READ:     // call number : 8
      check_address(f->esp+4);
      check_address(f->esp+8);
      check_address(f->esp+12);
      f->eax = read((int)*(uint32_t *)(f->esp+4),
		    (void *)*(uint32_t *)(f->esp+8),
		    (unsigned)*(uint32_t *)(f->esp+12));
      
      break;
      
    case SYS_WRITE:    // call number : 9
      check_address(f->esp+4);
      check_address(f->esp+8);
      check_address(f->esp+12);

      f->eax = write((int)*(uint32_t *)(f->esp+4),
		     (void *)*(uint32_t *)(f->esp+8),
		     (unsigned)*(uint32_t *)(f->esp+12));

      break;
      
    case SYS_SEEK:     // call number : 10
      check_address(f->esp+4);
      check_address(f->esp+8);
      seek((int)*(uint32_t *)f->esp+4,
	   (unsigned)*(uint32_t *)(f->esp+8));
      break;
      
    case SYS_TELL:     // call number : 11
      check_address(f->esp+4);
      tell((int)*(uint32_t *)(f->esp+4));
      break;
      
    case SYS_CLOSE:    // call number : 12
      check_address(f->esp+4);
      //printf("system call handler say : %d\n",(int)*(uint32_t *)(f->esp+4));
      close((int)*(uint32_t *)(f->esp+4));
      break;
      
    case SYS_SIGACTION: // call number : 13
      check_address(f->esp+4);
      check_address(f->esp+8);
      sigaction((int)*(uint32_t *)(f->esp+4),
		            *(sig_func **)(f->esp+8));
      break;
      
    case SYS_SENDSIG:  // call number : 14
      check_address(f->esp+4);
      check_address(f->esp+8);
      sendsig((int)*(uint32_t *)(f->esp+4),
	            (int)*(uint32_t *)(f->esp+8));
      break;
      
    case SYS_YIELD:   // call number : 15
      sched_yield();
      break;
      
    default:
      thread_exit();
    }
  //thread_exit();
}






/* 1. Shutdown pintos - Complete */
void
halt(void)
{
  shutdown_power_off();
}


/* 2. Exit the current process - Complete */
void
exit(int status)
{
  struct thread* cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);

  /* Save final exit status in current thread */
  cur->exit_status = status;
  thread_exit();
}

/* 4. Create a file - Completed*/
bool
create(const char *file, unsigned initial_size)
{
  if(file==NULL){
    exit(-1);
    return false; // failed
  }
  return filesys_create(file, initial_size);
}

/* 5. Remove a file - Completed */
bool
remove(const char *file)
{
  if(file==NULL){
    exit(-1);
    return false;
  }
  return filesys_remove(file);
}

// 3. process_execute
// 3.Create child process and execute program corresponds to cmd_line on it 
//   Combine fork() and exec() in unix

pid_t
exec(const char *cmd_line)
{
  return process_execute(cmd_line);
}

int
wait(pid_t pid)
{
  return process_wait(pid);
}



/*Completed*/
int
filesize(int fd)
{
  struct file* f = thread_current()->fd[fd];
  if(f==NULL)
    exit(-1);
  else
    return file_length(f);
  // return inode_length(file->node)
}


      
      
/*Not completed*/
int
read(int fd, void* buffer, unsigned size){
  int i;
  int ret=-1;
  lock_acquire(&filesys_lock);
  check_address(buffer);
  if (fd==0){ //stdin
      return input_getc();
  }
  
  else{
    struct file *f = thread_current()->fd[fd];
    if(f==NULL){
      exit(-1);
      lock_release(&filesys_lock);
    }
    else{
      off_t read_bytes = file_read(f,buffer,size);
      ret = read_bytes;
    }
  }
  lock_release(&filesys_lock);
  return ret;
}


/*Not completed*/
int
write(int fd, const void* buffer, unsigned size)
{
  check_address(buffer);
  lock_acquire(&filesys_lock);
  int ret=0;
  if(fd==1){ //stdout
    putbuf(buffer,size);
    ret=size; 
  }

  else{
    struct file *f = thread_current()->fd[fd];
    if(f== NULL){
      lock_release(&filesys_lock);
      exit(-1);
    }
    
    off_t write_bytes = file_write(f, buffer, size);
    ret=write_bytes;
  }
  lock_release(&filesys_lock);
  return ret;
}		     
		     
/*Not completed*/
int
open(const char *file)
{
  check_address(file);
  int ret = -1;
  if(file == NULL)
    return -1;
  //printf("file : %s\n", file);
  //lock_acquire(&filesys_lock);
  struct file *f = filesys_open(file);
  
  /* open error */
  if (f == NULL)
    return -1;
  
  /* success */
  
  struct thread * cur = thread_current();
  cur->fd[cur->next_fd] = f;
  int open_fd = cur->next_fd;
  
  for(int i=2;i<128;i++){
    /*detect where is NULL*/
    if(thread_current()->fd[i]==NULL)
    {
      thread_current()->next_fd = i;
      break;
    }
  }
  
  //lock_release(&filesys_lock);
  return open_fd;
}

/*Not Completed*/
void
close(int fd)
{
  struct file *f = thread_current()->fd[fd];
  if(f == NULL)
    exit(-1);
  
  f=NULL;
  file_close(f);
  
  for(int i=2;i<128;i++){
    if(thread_current()->fd[i]==NULL)
      thread_current()->next_fd = i;
      break;
  }
}

/*Completed*/
void
seek(int fd, unsigned position)
{
  struct file *f = thread_current()->fd[fd];
  if(f==NULL) // not exist
    exit(-1);
  file_seek(f, position);
  // f->pos = position,
  // set the current position in FILE to postion bytes from start
}

/*Completed*/
unsigned
tell(int fd)
{
  struct file *f = thread_current()->fd[fd];
  if(f == NULL) // not exist
    exit(-1);
  file_tell(f);
  // return f->pos
  // current position in FILE as a byte offset from start
}

// child-sig
void sigaction(int signum, void(*handler)(void))
{
  // register handler to parent;
  // so parent process(sendsig()) know handler
  thread_current()->parent->sig_handler[signum-1] = handler;
}

/* Signal part */
void sendsig(pid_t pid, int signum)
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  for(e=list_begin(&cur->children);
      e!=list_end(&cur->children);e=list_next(e)){
    
    struct thread *child_t = list_entry(e, struct thread, child_elem);
    if(child_t->tid == pid){
      if(cur->sig_handler[signum-1])
        printf("Signum: %d, Action: %p\n",signum, cur->sig_handler[signum-1]);
    }
  }
}

void check_address(void *addr)
{
  // is_user_vaddr { return vaddr < PHYS_BASE }
  if(addr == NULL || !is_user_vaddr(addr) ){
    exit(-1);
  }   
}

void sched_yield()
{
  thread_yield();
}
