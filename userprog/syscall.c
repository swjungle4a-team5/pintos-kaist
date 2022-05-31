#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include <devices/input.h>


void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(uintptr_t *addr);

void halt(void);
void exit (int status);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int write (int fd, const void *buffer, unsigned size);
int open (const char *file);
// pid_t fork(const char* thread_name, struct intr_frame *if_);
// int exec(const char* cmd_line);

int add_file_to_fd_table(struct file *file);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface
 * 시스템 콜 번호를 이용하여 해당 시스템 콜의 서비스 루틴을 호출 하도록 구현
 * 유저 스택 포인터(rsp) 주소와 시스템 콜 인자가 가리키는 주소(포인터)가 유효 주소 ((유저 영역)인지 확인하도록 구현
 * 기존 핀토스는 유저영역을 벗어난 주소를 참조할 경우 page fault 발생
 * 유저 스택에 존재하는 스택 프레임의 인자들을 커널에 복사하도록 구현
 * 시스템 콜의 함수의 리턴 값은 intr_frame의 rax에 저장되도록 구현
 */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.

	switch (f->R.rax)
	{
	/* Projects 2 and later. */
	/* Halt the operating system. */
	case SYS_HALT:
		halt();
		break;

	/* Terminate this process. */
	case SYS_EXIT:
		exit(f->R.rdi);
		break;

	/* Clone current process. */
	case SYS_FORK:
		// f->R.rax = fork(f->R.rdi, f);
		break;

	/* Switch current process. */
	case SYS_EXEC:
		// f->R.rax = exec(f->R.rdi);
		break;

	/* Wait for a child process to die. */
	case SYS_WAIT:
		break;

	/* Create a file. */
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;

	/* Delete a file. */
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;

	/* Open a file. */
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;

	/* Obtain a file's size. */
	case SYS_FILESIZE:
		break;

	/* Read from a file. */
	case SYS_READ:
		break;

	/* Write to a file. */
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;

	/* Change position in a file. */
	case SYS_SEEK:
		break;

	/* Report current position in a file. */
	case SYS_TELL:
		break;

	/* Close a file. */
	case SYS_CLOSE:
		break;

	/* Extra for Project 2
	 * Duplicate the file descriptor to kernel area
	 */
	case SYS_DUP2:
		break;
	case SYS_MOUNT:
		break;
	case SYS_UMOUNT:
		break;
	}

	//thread_exit();
}

void halt(void)
{
	power_off();
}

/* 현재 프로세스를 종료시키는 시스템 콜 */
void exit (int status)
{	
	struct thread *t = thread_current();
	t->exit_status = status;
	printf("name:%s exit_status:%d", t->name, status);
	thread_exit();
}

bool create (const char *file, unsigned initial_size)
{
	check_address(file);
	if (filesys_create(file, initial_size)){
		printf("file create success\n");
		return true;
	}
	printf("file create fail\n");
	return false;
}

bool remove (const char *file)
{
	check_address(file);
	if (filesys_remove(file)){
		printf("file remove success\n");
		return true;
	}
	printf("file remove fail\n");
	return false;
}

int write (int fd, const void *buffer, unsigned size)
{
	if (fd == STDOUT_FILENO)
		putbuf(buffer, size);
	return size;
}

int open (const char *file)
{
	check_address(file);
	// 파일이 잘 열렸으면 새 파일 객체를 리턴하고, 그렇지않다면 NULL을 리턴
	// 만약, 존재하지 않는 파일이라면 -1을 리턴한다.
	struct file *file_obj = filesys_open(file);

	if (file_obj == NULL)
		return -1;
	// 만들어진 파일을 스레드 내 fdt 테이블 추가
	int fd = add_file_to_fd_table(file_obj);
	
	if (fd == -1)
		file_close(file_obj);
	return fd;
}

// pid_t fork(const char* thread_name, struct intr_frame *if_)
// {
// 	check_address(thread_name);

// 	process_fork(thread_name, if_);

// }

// int exec(const char* cmd_line)
// {
// 	int status;
// 	check_address(cmd_line);
	
// 	struct thread* curr = thread_current();
// 	status = process_exec(cmd_line);
// 	/* file descriptors들은 exec 호출 후에도 남아있다는 것을 기억해야 한다. */

// 	return status;
// }

/* check_address()
 * 주소 값이 유저 영역에서 사용하는 주소 값((0x8048000~0xc0000000))인지 확인 하는 함수
 * 유저 영역을 벗어난 경우 프로세스 종료 (exit(-1))
 */
void check_address(uintptr_t *addr)
{
	struct thread *t = thread_current();
	/* TODO : User Memory Access */
	if(!is_user_vaddr(addr) || addr == NULL || !pml4_get_page(t->pml4, addr)){
		printf("check_address~!!");
		exit(-1);
	}
}

/* 파일을 현재 프로세스의 fdt에 추가 */
int add_file_to_fd_table(struct file *file)
{
	struct thread *t = thread_current();
	struct file **fdt = t->file_descriptor_table;
	int fd = t->fdidx;

	while (t->file_descriptor_table[fd]!=NULL && fd<FDT_COUNT_LIMIT){
		fd++;
	}

	if (fd >= FDT_COUNT_LIMIT){
		return -1;
	}
	t->fdidx = fd;
	fdt[fd] = file;
	return fd;
}