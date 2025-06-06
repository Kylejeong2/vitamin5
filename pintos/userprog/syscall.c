#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "userprog/pagedir.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "threads/malloc.h"

/* Global file system lock for synchronization */
static struct lock filesys_lock;

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
}

static void syscall_handler(struct intr_frame *f UNUSED) {
    uint32_t *args = ((uint32_t *) f->esp);

    /*
     * The following print statement, if uncommented, will print out the syscall
     * number whenever a process enters a system call. You might find it useful
     * when debugging. It will cause tests to fail, however, so you should not
     * include it in your final submission.
     */

    /* printf("System call number: %d\n", args[0]); */


    if (args[0] == SYS_EXIT) {
        int status = args[1];
        syscall_exit(status);
    }

    else if (args[0] == SYS_INCREMENT) {
        f->eax = args[1] + 1;
    }

    else if (args[0] == SYS_CREATE) {
        const char *file = (char *) args[1];
        off_t size = (off_t) args[2];

        if (file == NULL) {
            syscall_exit(-1);
        }

        validate_user_string(file);

        lock_acquire(&filesys_lock);
        bool success = filesys_create(file, size);
        lock_release(&filesys_lock);
        f->eax = success;
    }

    else if (args[0] == SYS_REMOVE) {
        const char *file = (char *) args[1];

        if (file == NULL) {
            syscall_exit(-1);
        }

        validate_user_string(file);

        lock_acquire(&filesys_lock);
        f->eax = filesys_remove(file);
        lock_release(&filesys_lock);
    }

    else if (args[0] == SYS_OPEN) {
        const char *file = (char *) args[1];

        if (file == NULL) {
            syscall_exit(-1);
        }

        validate_user_string(file);

        lock_acquire(&filesys_lock);
        struct file *open_file = filesys_open(file);
        lock_release(&filesys_lock);

        if (open_file == NULL) {
            f -> eax = -1;
            return;
        }

        struct thread *t = thread_current();
        
        int fd;

        for (fd = 0; fd < 128; fd++) {
            if (t -> fd_table[fd] == NULL) {
                break;
            }
        }

        if (fd < 128) {
            t -> fd_table[fd] = open_file;
            f -> eax = fd + 2;
        } else {
            lock_acquire(&filesys_lock);
            file_close(open_file);
            lock_release(&filesys_lock);
            f -> eax = -1;
        }
    }

    else if (args[0] == SYS_FILESIZE) {
        int fd = (int) args[1];

        if (fd < 2) {
            f->eax = -1;
            return;
        }

        struct thread *t = thread_current();

        if (fd - 2 >= 128 || t->fd_table[fd - 2] == NULL) {
            f->eax = -1;
            return;
        }

        struct file* file = t->fd_table[fd - 2];

        lock_acquire(&filesys_lock);
        int size = file_length(file);
        lock_release(&filesys_lock);

        f->eax = size;
    }

    else if (args[0] == SYS_READ) {
        int fd = (int) args[1];
        void *buffer = (void *) args[2];
        unsigned size = (unsigned) args[3];

        if (buffer == NULL) {
            syscall_exit(-1);
        }

        validate_user_buffer(buffer, size);

        // do for fd == 0 and 1
        if (fd < 0 || fd == 1) {
            f->eax = -1;
            return;
        }

        if (fd == 0) {
            uint8_t *buf = (uint8_t *) buffer;
            for (unsigned i = 0; i < size; i++) {
                buf[i] = input_getc();
            }
            f->eax = size;
            return;
        }

        struct thread *t = thread_current();

        if (fd - 2 >= 128 || t->fd_table[fd - 2] == NULL) {
            f->eax = -1;
            return;
        }

        struct file* file = t->fd_table[fd - 2];

        lock_acquire(&filesys_lock);
        int bytes = file_read(file, buffer, size);
        lock_release(&filesys_lock);

        f -> eax = bytes;
    }

    else if (args[0] == SYS_WRITE) {
        int fd = (int) args[1];
        void *buffer = (void *) args[2];
        unsigned size = (unsigned) args[3];

        if (buffer == NULL) {
            syscall_exit(-1);
        }

        validate_user_buffer(buffer, size);

        struct thread *t = thread_current();

        if (fd < 1 || fd - 2 >= 128 || t->fd_table[fd - 2] == NULL) {
            f->eax = -1;
            return;
        }

        if (fd == 1) {
            putbuf((const char *) buffer, size);
            f->eax = size;
            return;
        }
        
        struct file* file = t->fd_table[fd - 2];

        lock_acquire(&filesys_lock);
        int bytes = file_write(file, buffer, size);
        lock_release(&filesys_lock);

        f -> eax = bytes;
    }

    else if (args[0] == SYS_SEEK) {
        int fd = (int) args[1];
        unsigned position = (unsigned) args[2];

        if (fd < 2) {
            f->eax = -1;
            return;
        }

        struct thread *t = thread_current();

        if (fd - 2 >= 128 || t->fd_table[fd - 2] == NULL) {
            f->eax = -1;
            return;
        }

        struct file* file = t->fd_table[fd - 2];

        lock_acquire(&filesys_lock);
        file_seek(file, position);
        lock_release(&filesys_lock);
    }

    else if (args[0] == SYS_TELL) {
        int fd = (int) args[1];

        if (fd < 2) {
            f->eax = -1;
            return;
        }

        struct thread *t = thread_current();

        if (fd - 2 >= 128 || t->fd_table[fd - 2] == NULL) {
            f->eax = -1;
            return;
        }

        struct file* file = t->fd_table[fd - 2];

        lock_acquire(&filesys_lock);
        f->eax = file_tell(file);
        lock_release(&filesys_lock);
    }

    else if (args[0] == SYS_CLOSE) {
        int fd = (int) args[1];

        if (fd < 2) {
            f->eax = -1;
            return;
        }

        struct thread *t = thread_current();

        if (fd - 2 >= 128 || t->fd_table[fd - 2] == NULL) {
            f->eax = -1;
            return;
        }

        struct file* file = t->fd_table[fd - 2];

        t->fd_table[fd - 2] = NULL;

        lock_acquire(&filesys_lock);
        file_close(file);
        lock_release(&filesys_lock);
    }

    else if (args[0] == SYS_HALT) {
        shutdown_power_off();
    }

    else if (args[0] == SYS_EXEC) {
        const char *cmd_line = (const char *) args[1];
        
        if (cmd_line == NULL) {
            f->eax = -1;
            return;
        }
        
        validate_user_string(cmd_line);
        
        tid_t child_tid = process_execute(cmd_line);
        
        if (child_tid == TID_ERROR) {
            f->eax = -1;
            return;
        }
        
        /* Create child PCB entry and add to parent's children list */
        struct child_pcb *child_pcb = malloc(sizeof(struct child_pcb));
        if (child_pcb == NULL) {
            f->eax = -1;
            return;
        }
        
        child_pcb->pid = child_tid;
        child_pcb->exit_code = 0;
        child_pcb->has_exited = false;
        child_pcb->has_been_waited = false;
        sema_init(&child_pcb->wait_sema, 0);
        
        struct thread *parent = thread_current();
        list_push_back(&parent->children, &child_pcb->elem);
        
        f->eax = child_tid;
    }

    else if (args[0] == SYS_WAIT) {
        tid_t child_tid = (tid_t) args[1];
        int exit_status = process_wait(child_tid);
        f->eax = exit_status;
    }
}


void validate_user_addr(const void *addr) {
    if (addr == NULL || !is_user_vaddr(addr) || pagedir_get_page(thread_current()->pagedir, addr) == NULL) {
        syscall_exit(-1); 
    }
}

void validate_user_buffer(const void *buffer, size_t size) {
    uint8_t *ptr = (uint8_t *) buffer;
    for (size_t i = 0; i < size; i++) {
        validate_user_addr(ptr + i);
    }
}

void validate_user_string(const char *str) {
    while (true) {
        validate_user_addr(str);
        if (*str == '\0') break;
        str++;
    }
}

void syscall_exit(int status) {
    struct thread *current = thread_current();
    current->exit_status = status;
    printf("%s: exit(%d)\n", current->name, status);
    thread_exit();
}






    // SYS_HALT, /* Halt the operating system. */
    // SYS_EXIT, /* Terminate this process. */
    // SYS_EXEC, /* Start another process. */
    // SYS_WAIT, /* Wait for a child process to die. */
    // SYS_CREATE, /* Create a file. */
    // SYS_REMOVE, /* Delete a file. */
    // SYS_OPEN, /* Open a file. */
    // SYS_FILESIZE, /* Obtain a file's size. */
    // SYS_READ, /* Read from a file. */
    // SYS_WRITE, /* Write to a file. */
    // SYS_SEEK, /* Change position in a file. */
    // SYS_TELL, /* Report current position in a file. */
    // SYS_CLOSE, /* Close a file. */
    // SYS_INCREMENT, /* Increments an int. */

    // /* Unused. */
    // SYS_MMAP, /* Map a file into memory. */
    // SYS_MUNMAP, /* Remove a memory mapping. */
    // SYS_CHDIR, /* Change the current directory. */
    // SYS_MKDIR, /* Create a directory. */
    // SYS_READDIR, /* Reads a directory entry. */
    // SYS_ISDIR, /* Tests if a fd represents a directory. */
    // SYS_INUMBER /* Returns the inode number for a fd. */