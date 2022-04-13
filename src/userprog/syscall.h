#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/* ++++ Project2.2 System Call ++++ */

typedef int pid_t;
#define bool    _Bool

struct lock filesys_lock;

void syscall_init (void);

void check_address(void *addr);

void get_argument(void *esp, int *arg, int count);


/* ++++ Project2.2 system call  ++++ */

void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);

int wait(pid_t);

int open (const char *file);
void close (int fd);

int filesize (int fd);

int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);

void seek (int fd, unsigned position);
unsigned tell (int fd);

void sigaction(int signum, void(*handler)(void));
void sendsig(pid_t pid, int signum);

void sched_yield(void);

/* +++++++++++++++++++++++++++++++++ */



#endif /* userprog/syscall.h */
