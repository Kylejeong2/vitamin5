#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "userprog/pagedir.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
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
        f->eax = args[1];
        printf("%s: exit(%d)\n", thread_current()->name, args[1]);
        thread_exit();
    }

    else if (args[0] == SYS_INCREMENT) {
        f->eax = args[1] + 1;
    }

    else if (args[0] == SYS_WRITE) {
        putbuf((const char *) args[2], args[3]);
        f->eax = args[3];
    }

    else if (args[0] == SYS_CREATE) {
        const char *file = (char *) args[1];
        off_t size = (off_t) args[2];

        if (file == NULL) {
            syscall_exit(-1);
        }

        validate_user_string(file);

        bool success = filesys_create(file, size);
        f->eax = success;
    }

    else if (args[0] == SYS_REMOVE) {

    }

    else if (args[0] == SYS_OPEN) {

    }

    else if (args[0] == SYS_FILESIZE) {

    }

    else if (args[0] == SYS_READ) {

    }

    else if (args[0] == SYS_WRITE) {

    }

    else if (args[0] == SYS_SEEK) {

    }

    else if (args[0] == SYS_TELL) {

    }

    else if (args[0] == SYS_CLOSE) {

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
    printf("%s: exit(%d)\n", thread_current()->name, status);
    //thread_current()->exit_status = status;
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