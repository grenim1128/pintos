#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/stdio.h"
#include "lib/string.h"
#include "lib/user/syscall.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

static struct semaphore fs_lock;

static struct list file_list;

struct file_descriptor
{
  int file_id;
  char name[128];
  struct file *file;
  struct list_elem all_elem;
  struct list_elem elem;
};

static void
syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  sema_init(&fs_lock, 1);
  list_init(&file_list);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void check_valid_addr(const void *ptr);
void check_valid_buffer(const void *ptr, size_t size);

struct file_descriptor *fd_create(char *, struct file *);
struct file_descriptor *fd_find(int);
void fd_destroy(struct file_descriptor *);
bool is_already_opened(struct file_descriptor *);

static void syscall_handler(struct intr_frame *f)
{
  check_valid_addr(f->esp);
  switch (*(int *)(f->esp))
  {
  case SYS_HALT:
    syscall_halt();
    NOT_REACHED();
    break;
  case SYS_EXIT:
    check_valid_addr(f->esp + 4);
    syscall_exit(*(int *)(f->esp + 4));
    NOT_REACHED();
    break;
  case SYS_EXEC:
    check_valid_addr(f->esp + 4);
    f->eax = (uint32_t)(syscall_exec(*(const char **)(f->esp + 4)));
    break;
  case SYS_WAIT:
    check_valid_addr(f->esp + 4);
    f->eax = (uint32_t)(syscall_wait(*(pid_t *)(f->esp + 4)));
    break;
  case SYS_CREATE:
    check_valid_addr(f->esp + 4);
    check_valid_addr(f->esp + 8);
    f->eax = (uint32_t)(syscall_create(*(const char **)(f->esp + 4), *(unsigned *)(f->esp + 8)));
    break;
  case SYS_REMOVE:
    check_valid_addr(f->esp + 4);
    f->eax = (uint32_t)(syscall_remove(*(const char **)(f->esp + 4)));
    break;
  case SYS_OPEN:
    check_valid_addr(f->esp + 4);
    f->eax = (uint32_t)(syscall_open(*(const char **)(f->esp + 4)));
    break;
  case SYS_FILESIZE:
    check_valid_addr(f->esp + 4);
    f->eax = (uint32_t)(syscall_filesize(*(int *)(f->esp + 4)));
    break;
  case SYS_READ:
    check_valid_addr(f->esp + 4);
    check_valid_addr(f->esp + 8);
    check_valid_addr(f->esp + 12);
    f->eax = (uint32_t)(syscall_read(*(int *)(f->esp + 4), *(void **)(f->esp + 8), *(unsigned *)(f->esp + 12)));
    break;
  case SYS_WRITE:
    check_valid_addr(f->esp + 4);
    check_valid_addr(f->esp + 8);
    check_valid_addr(f->esp + 12);
    f->eax = (uint32_t)(syscall_write(*(int *)(f->esp + 4), *(void **)(f->esp + 8), *(unsigned *)(f->esp + 12)));
    break;
  case SYS_SEEK:
    check_valid_addr(f->esp + 4);
    check_valid_addr(f->esp + 8);
    syscall_seek(*(int *)(f->esp + 4), *(unsigned *)(f->esp + 8));
    break;
  case SYS_TELL:

    check_valid_addr(f->esp + 4);
    f->eax = (uint32_t)(syscall_tell(*(int *)(f->esp + 4)));
    break;
  case SYS_CLOSE:
    check_valid_addr(f->esp + 4);
    syscall_close(*(int *)(f->esp + 4));
    break;
  default:
    syscall_exit(-1);
    NOT_REACHED();
    break;
  }
}

void syscall_halt(void)
{
  power_off();
}

void syscall_exit(int status)
{
  struct list_elem *e;
  struct thread *curr;

  curr = thread_current();
  curr->self->exit_status = status < 0 ? -1 : status;
  printf("%s: exit(%d)\n", curr->name, curr->self->exit_status);

  sema_down(&fs_lock);
  while (!list_empty(&curr->self->files))
  {
    e = list_pop_front(&curr->self->files);
    struct file_descriptor *fd = list_entry(e, struct file_descriptor, elem);
    file_close(fd->file);
    list_remove(&fd->all_elem);
    palloc_free_page(fd);
  }
  sema_up(&fs_lock);

  sema_up(&curr->self->wait);
  thread_exit();
}

pid_t syscall_exec(const char *cmdline)
{
  pid_t ret;
  check_valid_addr(cmdline);

  sema_down(&fs_lock);
  ret = process_execute(cmdline);
  sema_up(&fs_lock);
  return ret;
}

int syscall_wait(pid_t pid)
{
  return process_wait(pid);
}

bool syscall_create(const char *file, unsigned initial_size)
{
  bool ret;
  check_valid_addr(file);

  sema_down(&fs_lock);
  ret = filesys_create(file, initial_size);
  sema_up(&fs_lock);
  return ret;
}
bool syscall_remove(const char *file)
{
  bool ret;
  check_valid_addr(file);

  sema_down(&fs_lock);
  ret = filesys_remove(file);
  sema_up(&fs_lock);
  return ret;
}

int syscall_open(const char *file)
{
  struct file *open_file;
  struct file_descriptor *fd;
  struct list_elem *e;
  check_valid_addr(file);

  sema_down(&fs_lock);
  open_file = filesys_open(file);
  fd = fd_create(file, open_file);
  if (!fd)
  {
    sema_up(&fs_lock);
    return -1;
  }

  if (strcmp(thread_current()->name, fd->name) == 0)
    file_deny_write(fd->file);

  sema_up(&fs_lock);
  return fd->file_id;
}

int syscall_filesize(int file_id)
{
  int ret = -1;
  struct file_descriptor *fd;
  sema_down(&fs_lock);
  fd = fd_find(file_id);
  if (fd)
  {

    ret = file_length(fd->file);
    sema_up(&fs_lock);
    return ret;
  }
  else
  {
    sema_up(&fs_lock);
    syscall_exit(-1);
  }
}

int syscall_read(int file_id, void *buffer, unsigned size)
{
  int i, ret = -1;
  struct file_descriptor *fd;
  check_valid_buffer(buffer, size);
  if (file_id == STDIN_FILENO)
  {
    for (i = 0; i < size; ++i)
    {
      if (*(char *)(buffer + i) == '\0')
        return i;
    }
  }
  sema_down(&fs_lock);
  fd = fd_find(file_id);
  if (fd)
  {
    ret = file_read(fd->file, buffer, size);
    sema_up(&fs_lock);
    return ret;
  }
  else
  {
    sema_up(&fs_lock);
    syscall_exit(-1);
  }
}

int syscall_write(int file_id, const void *buffer, unsigned size)
{
  int ret = -1;
  struct file_descriptor *fd;
  struct list_elem *e;
  check_valid_buffer(buffer, size);

  if (file_id == STDOUT_FILENO)
  {
    putbuf(buffer, size);
    return size;
  }
  else
  {
    sema_down(&fs_lock);
    fd = fd_find(file_id);
    if (fd)
    {
      if (is_already_opened(fd))
        file_deny_write(fd->file);

      ret = file_write(fd->file, buffer, size);
      sema_up(&fs_lock);
      return ret;
    }
    else
    {
      sema_up(&fs_lock);
      syscall_exit(-1);
    }
  }

  return ret;
}

void syscall_seek(int file_id, unsigned position)
{
  struct file_descriptor *fd;
  sema_down(&fs_lock);
  fd = fd_find(file_id);
  if (fd)
  {
    file_seek(fd->file, position);
    sema_up(&fs_lock);
  }
  else
  {
    sema_up(&fs_lock);
    syscall_exit(-1);
  }
}

unsigned syscall_tell(int file_id)
{
  unsigned ret = 0;
  struct file_descriptor *fd;
  sema_down(&fs_lock);
  fd = fd_find(file_id);
  if (fd)
  {
    ret = file_tell(fd->file);
    sema_up(&fs_lock);
    return ret;
  }
  else
  {
    sema_up(&fs_lock);
    syscall_exit(-1);
  }
}

void syscall_close(int file_id)
{
  struct file_descriptor *fd;
  sema_down(&fs_lock);
  fd = fd_find(file_id);
  if (fd)
  {
    file_close(fd->file);
    fd_destroy(fd);
    sema_up(&fs_lock);
  }
  else
  {
    sema_up(&fs_lock);
    syscall_exit(-1);
  }
}

struct file_descriptor *fd_find(int id)
{
  struct thread *curr = thread_current();
  if (id > 2 && !list_empty(&curr->self->files))
  {
    struct list_elem *e;
    for (e = list_front(&curr->self->files); e != list_end(&curr->self->files); e = list_next(e))
    {
      struct file_descriptor *fd = list_entry(e, struct file_descriptor, elem);
      if (fd->file_id == id)
      {
        sema_up(&fs_lock);
        return fd;
      }
    }
  }
  return NULL;
}

int allocate_file_id(void)
{
  static int fd = 2;
  fd += 1;
  return fd;
}

struct file_descriptor *fd_create(char *name, struct file *file)
{
  if (file)
  {
    struct file_descriptor *fd;
    int len;
    fd = palloc_get_page(PAL_ZERO);
    if (fd == NULL)
      return NULL;
    len = strlen(name) + 1;
    fd->file_id = allocate_file_id();
    fd->file = file;
    strlcpy(fd->name, name, len > 128 ? 128 : len);
    list_push_back(&thread_current()->self->files, &fd->elem);
    list_push_back(&file_list, &fd->all_elem);
    return fd;
  }
  else
    return NULL;
}

void fd_destroy(struct file_descriptor *fd)
{
  ASSERT(fd != NULL);
  list_remove(&fd->elem);
  list_remove(&fd->all_elem);
  palloc_free_page(fd);
}

void check_valid_addr(const void *ptr)
{
  if (!ptr || !is_user_vaddr(ptr) || !pagedir_get_page(thread_current()->pagedir, ptr))
  {
    syscall_exit(-1);
  }
}

void check_valid_buffer(const void *ptr, size_t size)
{
  int i;
  for (i = 0; i < size; ++i)
  {
    check_valid_addr(ptr + i);
  }
}

bool is_already_opened(struct file_descriptor *fd)
{
  if (!list_empty(&file_list))
  {
    struct list_elem *e;
    for (e = list_front(&file_list); e != list_end(&file_list); e = list_next(e))
    {
      struct file_descriptor *temp = list_entry(e, struct file_descriptor, all_elem);
      if (temp->file_id != fd->file_id && strcmp(temp->name, fd->name) == 0)
      {
        return true;
      }
    }
  }
  return false;
}