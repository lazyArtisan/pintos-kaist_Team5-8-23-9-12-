#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/init.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/synch.h"
#include "string.h"
#include "userprog/process.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void check_address(void *addr) {
    struct thread *cur = thread_current();
	if (addr == NULL || !(is_user_vaddr(addr)) || pml4_get_page(cur->pml4, addr) == NULL) {
		exit(-1);
	}
}

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	switch (f->R.rax)
    {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit(f->R.rdi);
            break;
        case SYS_FORK:
            f->R.rax = fork(f->R.rdi, f);
            break;
        case SYS_EXEC:
            if (exec(f->R.rdi) == -1)
            {
                exit(-1);
            }
            break;
        case SYS_WAIT:
            f->R.rax = wait(f->R.rdi);
            break;
        case SYS_CREATE:
            f->R.rax = create(f->R.rdi, f->R.rsi);
            break;
        case SYS_REMOVE:
            f->R.rax = remove(f->R.rdi);
            break;
        case SYS_OPEN:
            f->R.rax = open(f->R.rdi);
            break;
        case SYS_FILESIZE:
            f->R.rax = filesize(f->R.rdi);
            break;
        case SYS_READ:
            f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:
            f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_SEEK:
            seek(f->R.rdi, f->R.rsi);
            break;
        case SYS_TELL:
            f->R.rax = tell(f->R.rdi);
            break;
        case SYS_CLOSE:
            close(f->R.rdi);
            break;
        default:
            thread_exit();
            break;
    }
}

void halt(void){
	power_off();
}

void exit(int status){
	struct thread *cur = thread_current();
    cur->exit_status = status;
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}

tid_t fork(const char *thread_name, struct intr_frame *f){
	return process_fork(thread_name, f);
}


int exec(const char *cmd_line){
	check_address(cmd_line);

	int file_name_size = strlen(cmd_line)+1;

	char *fn_copy = palloc_get_page(PAL_ZERO);
	if (fn_copy == NULL) exit(-1);
	strlcpy(fn_copy, cmd_line, file_name_size);

	if (process_exec(fn_copy) == -1) return -1;

	NOT_REACHED();
	return 0;
}

int wait(pid_t pid){
	return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
	check_address(file);

	//printf("SYSCALL:: CREATE :LOCK ACQUIRE\n");
    lock_acquire(&filesys_lock);

	 if (filesys_create(file, initial_size)) {
        //printf("SYSCALL:: CREATE : LOCK_RELEASE\n");
        lock_release(&filesys_lock);

        return true;
    } 
	
	else {
        //printf("SYSCALL:: CREATE : LOCK_RELEASE\n");
        lock_release(&filesys_lock);

        return false;
    }
}

bool remove(const char *file) {
	check_address(file);

	//printf("SYSCALL:: REMOVE :LOCK ACQUIRE\n");
    lock_acquire(&filesys_lock);

   
    if (filesys_remove(file)) {
        //printf("SYSCALL:: REMOVE : LOCK_RELEASE\n");
        lock_release(&filesys_lock);

        return true;
    } else {
        //printf("SYSCALL:: REMOVE : LOCK_RELEASE\n");
        lock_release(&filesys_lock);

        return false;
    }
}

int add_file_to_fdt(struct file *file)
{
    struct thread *cur = thread_current();
    struct file **fdt = cur->fd_table;

    //  fd 범위를 넘지 않는 선에서, 할당 가능한 fd 번호를 찾는다.
    while (cur->fd_idx < FDT_COUNT_LIMIT && fdt[cur->fd_idx])
    {
        cur->fd_idx++;
    }

    // fd table이 꽉 찼을 경우 -1 리턴
    if (cur->fd_idx >= FDT_COUNT_LIMIT)
        return -1;

    // fd table에 파일을 할당하고 fd 번호를 리턴한다
    fdt[cur->fd_idx] = file;
    return cur->fd_idx;
}

static struct file *find_file_by_fd(int fd)
{
    struct thread *cur = thread_current();
    if (fd < 0 || fd >= FDT_COUNT_LIMIT)
    {
        return NULL;
    }
    return cur->fd_table[fd];
}

int open(const char *file) {
	check_address(file);

    
    
	//printf("SYSCALL:: OPEN : LOCK ACQUIRE\n");
    lock_acquire(&filesys_lock);

    //printf("SYSCALL:: OPEN : current file char : %s\n", file);

    struct file *open_file = filesys_open(file);

    //printf("SYSCALL::OPEN:%p\n", open_file);

    if (open_file == NULL) {
        //printf("SYSCALL:: OPEN : LOCK_RELEASE BY OPEN_FILE == NULL\n");
        lock_release(&filesys_lock);
        return -1;
    }

    // fd table에 file추가
    int fd = add_file_to_fdt(open_file);
   
    // fd table 가득 찼을경우
    if (fd == -1) {
        file_close(open_file);
    }
    //printf("SYSCALL:: OPEN : LOCK_RELEASE\n");
    lock_release(&filesys_lock);

    return fd;
}

void remove_file_from_fdt(int fd) {
    struct thread *cur = thread_current();

    // error : invalid fd
    if (fd < 0 || fd >= FDT_COUNT_LIMIT){
        //printf("SYSCALL::REMV_FI_FROM_FDT:INVALID FD\n");
        return;
    }

    cur->fd_table[fd] = NULL;
}

int filesize(int fd)
{
    struct file *open_file = find_file_by_fd(fd);
    if (open_file == NULL)
    {
        return -1;
    }

    //printf("SYSCALL:: FILESIZE :LOCK ACQUIRE\n");
    lock_acquire(&filesys_lock);

    int fileLength = file_length(open_file);
    //printf("SYSCALL:: FILESIZE : LOCK_RELEASE\n");
    lock_release(&filesys_lock);


    return fileLength;
}

int read(int fd, void *buffer, unsigned size)
{
    check_address(buffer);

    if (fd < 0 || fd > FDT_COUNT_LIMIT)
        exit(-1);
    
   
    // 읽은 바이트 수 저장할 변수
    off_t read_byte;
    // 버퍼를 바이트 단위로 접근하기 위한 포인터
    uint8_t *read_buffer = buffer;

    // 표준입력일 경우 데이터를 읽는다
    if (fd == 0)
    {
        char key;
        for (read_byte = 0; read_byte < size; read_byte++)
        {
            // input_getc 함수로 입력을 가져오고, buffer에 저장한다
            key = input_getc();
            *read_buffer++ = key;

            // 널 문자를 만나면 종료한다.
            if (key == '\0')
            {
                break;
            }
        }
    }
    // 표준출력일 경우 -1을 리턴한다.
    else if (fd == 1)
    {
        return -1;
    }
    // 2이상, 즉 파일일 경우 파일을 읽어온다.
    else
    {
        struct file *read_file = find_file_by_fd(fd);
        
        if (read_file == NULL)
        {
            return -1;
        }

        //if (size == 0) return 0;

        lock_acquire(&filesys_lock);

        read_byte = file_read(read_file, buffer, size);
        //file_deny_write(read_file);
        lock_release(&filesys_lock);
    }

    // 읽어온 바이트 수 리턴
    return read_byte;
}

int write(int fd, const void *buffer, unsigned size) {
    check_address(buffer);

	int write_result;
	lock_acquire(&filesys_lock);
	if (fd == 1) {
		putbuf(buffer, size);		// 문자열을 화면에 출력하는 함수
		write_result = size;
	}
    else if (fd == 0) {
        lock_release(&filesys_lock);
        exit(-1);
        return -1;
    }
	else {
		if (find_file_by_fd(fd) != NULL) {
			write_result = file_write(find_file_by_fd(fd), buffer, size);
		}
		else {
			write_result = -1;
		}
	}
	lock_release(&filesys_lock);
	return write_result;
}



void seek(int fd, unsigned position) {
    //printf("SYSCALL::SEEK:INIT\n");
    if (fd < 2) {
        //printf("SYSCALL::SEEK:FD INVALID\n");
        return;
    }
    struct file *file = find_file_by_fd(fd);
    //printf("SYSCALL::SEEK: fild addr : %p\n", file);
    //check_address(file);
    if (file == NULL) {
        return;
    }
    file_seek(file, position);
}

unsigned tell (int fd) {
    if (fd < 2) {
        return;
    }
    struct file *file = find_file_by_fd(fd);
    check_address(file);
    if (file == NULL) {
        return;
    }
    return file_tell(file);
}

void close(int fd){
    struct file *fileobj = find_file_by_fd(fd);
	if (fileobj == NULL) return;
	
	remove_file_from_fdt(fd);
}