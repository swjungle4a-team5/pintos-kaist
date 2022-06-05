#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
// #include "init.h"
// #include "lib/user/syscall.h"

#include "filesys/filesys.h"
#include "filesys/file.h"
#include <list.h>
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/synch.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

void check_address(uintptr_t *addr);
void get_argument(uintptr_t *rsp, int *arg, int count);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int wri1te(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell (int fd);
void close(int fd);

static struct file *find_file_by_fd(int fd);
int add_file_to_fdt(struct file *file);
void remove_file_from_fdt(int fd);

/* Project2-extra */
const int STDIN = 1;
const int STDOUT = 2;

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
	lock_init(&filesys_lock);
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
	check_address(f->rsp);

	// TODO: Your implementation goes here.
	printf("system call!\n");

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
		break;

	/* Switch current process. */
	case SYS_EXEC:
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
		f->R.rax = filesize(f->R.rdi);
		break;

	/* Read from a file. */
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;

	/* Write to a file. */
	case SYS_WRITE:
		// rdi, rsi, rdx // fd, buffer, size
		// int write (int fd, const void *buffer, unsigned size) {
		// 	return syscall3 (SYS_WRITE, fd, buffer, size); }
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;

	/* Change position in a file. */
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;

	/* Report current position in a file. */
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;

	/* Close a file. */
	case SYS_CLOSE:
		close(f->R.rdi);
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
	default:
		// thread_exit();
		exit(-1);
		break;
	}
}

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

void halt(void){
	power_off();
}

void exit(int status){
	struct  thread *t = thread_current();
	printf("%s: exit(%d)\n", t->name, status);
	t->exit_status = status;
	thread_exit();
}

bool create(const char *file, unsigned initial_size){
	check_address(file);
	return filesys_create (file, initial_size);
}

bool remove(const char *file){
	check_address(file);
	return filesys_remove (file);
}


/* 요청받은 파일을 open. 파일 디스크립터가 가득차있다면 다시 닫아준다. */
int open(const char *file){
	check_address(file);
	lock_acquire(&filesys_lock);

	struct file *f_obj = filesys_open(file);

	if(f_obj == NULL){
		// lock_release(&filesys_lock);	// 여긴 안해도되나??
		return -1;
	}

	int fd = add_file_to_fdt(f_obj);

	if(fd==-1){
		file_close(f_obj);
	}
	lock_release(&filesys_lock);
	return fd;
}

/* 파일이 열려있다면 바이트 반환, 없다면 -1 반환 */
int filesize(int fd){
	struct file *f_obj = find_file_by_fd(fd);
	if(f_obj==NULL){
		return -1;
	}
	return file_length(f_obj);
}

/* read()
 * 요청한 파일을 버퍼에 읽어온다. 읽어들인 바이트를 반환
 * 열린 파일의 데이터를 읽는 시스템 콜
 * 성공 시 읽은 바이트 수를 반환, 실패 시 -1 반환
 * buffer : 읽은 데이터를 저장한 버퍼의 주소 값, size : 읽을 데이터의 크기
 * fd 값이 0일 때? 키보드의 데이터를 읽어 버퍼에 저장 (input_getc() 이용)
 */
int read(int fd, void *buffer, unsigned size){
	check_address(buffer);

	struct file *f_obj = find_file_by_fd(fd);
	int ret = 0;

	if(f_obj==NULL){
		return -1;	
	}
	if(f_obj==1){			// STDIN : 표준입력
		unsigned char *buf = buffer;
		int i=0;
		/* 키보드로 적은(버퍼) 내용 받아옴 */
		for(i; i<size; i++){
			char c = input_getc();
			*buf++ = c;
			if(c=='\n'){
				break;
			}

		}
		ret = i;
	}
	else if(f_obj==2){			// STDOUT : 표준출력
		ret = -1;
	}
	else{					// 그 외 파일
		lock_acquire(&filesys_lock);
		ret = file_read(f_obj, buffer, size);
		lock_release(&filesys_lock);
	}
	return ret;
}

/* write()
 * 열린 파일의 데이터를 기록하는 시스템 콜
 * 버퍼에 있는 내용을 fd 파일에 작성. 파일에 작성한 바이트 반환
 * 성공 시 기록한 데이터의 바이트 수를 반환, 실패시 -1 반환
 * buffer : 기록할 데이터를 저장한 버퍼의 주소 값, size : 기록할 데이터의 크기
 * fd 값이 1일 때? 버퍼에 저장된 데이터를 화면에 출력 (putbuf() 이용)
 */
int write(int fd, const void *buffer, unsigned size){
	check_address(buffer);

	struct file *f_obj = find_file_by_fd(fd);
	int ret = 0;
	
	if(f_obj==NULL){
		return -1;
	}

	if(f_obj==1){				// STDIN : 표준입력
		ret = -1;
	}
	else if(f_obj==2){			// STDOUT : 표준출력
		putbuf(buffer, size);
		ret = size;
	}
	else{					// 그 외 파일
		lock_acquire(&filesys_lock);
		ret = file_write(f_obj, buffer, size);
		lock_release(&filesys_lock);
	}
	return ret;
}


void seek(int fd, unsigned position){
	struct file *f_obj = find_file_by_fd(fd);
	
	if(f_obj <= 2)
		return;

	file_seek(f_obj, position);
	// f_obj->pos = position;
}


unsigned tell (int fd){
	struct file *f_obj = find_file_by_fd(fd);

	if(f_obj <= 2)
		return;
	
	return file_tell(f_obj);
}


void close(int fd){
	struct thread *curr = thread_current();
	struct file *f_obj = find_file_by_fd(fd);

	if(f_obj == NULL){
		return;
	}

	remove_file_from_fdt(fd);

	curr->fdTable[fd] = NULL;

	if(fd <= 1 || f_obj <= 2){
		return;
	}

	file_close(f_obj);

	return;
}


/* find_file_by_fd()
 * 프로세스의 파일 디스크립터 테이블을 검색하여 파일 객체의 주소를 리턴
 * 파일 디스크립터로 파일 검색 하여 파일 구조체 반환
 */
static struct file *find_file_by_fd(int fd){
	struct thread *curr = thread_current();
	// Error - invalid id : 잘못된 fd -> NULL // 이거 아닌가??
	// 해당 테이블에 파일 객체가 없을 시 NULL 반환
	if (fd < 0 || fd >= FDCOUNT_LIMIT){
		return NULL;
	}
	return curr->fdTable[fd];
}

/* add_file_to_fdt()
 * 파일 객체에 대한 파일 디스크립터 생성 
 * 새로 만든 파일을 파일 디스크립터 테이블에 추가
 */
int add_file_to_fdt(struct file *file){

	/* 현재 스레드의 파일 디스크립터 테이블을 가져온다. */ 
	struct thread *curr = thread_current();
	struct file **fdt = curr->fdTable; // file descriptor table

	/* Project2 user programs
	 * 다음 File Descriptor 값 1 증가
	 * 최대로 열 수 있는 파일 제한(FDCOUNT_LIMIT)을 넘지 않고, 
	 * 해당 fd에 이미 열려있는 파일이 있다면 1씩 증가한다.
	 * ?? 
	 * 현재스레드의 fdIdx<limit이고 fdt[fdIdx]가 존재한다면 다음 idx 탐색 
	 * => 빈자리 나올때까지 증가  
	 */
	while (curr->fdIdx < FDCOUNT_LIMIT && fdt[curr->fdIdx]){
		curr->fdIdx++;
	}
	
	/* Error - fdt full */
	if (curr->fdIdx >= FDCOUNT_LIMIT){
		return -1;
	}

	/* 가용한 fd로 fdt[fd] 에 인자로 받은 file을 넣는다. */ 
	fdt[curr->fdIdx] = file;

	/* 추가된 파일 객체의 File Descriptor 반환 */ 
	return curr->fdIdx;
}

/* remove_file_from_fdt()
 * 파일 디스크립터에 해당하는 파일을 닫고 해당 엔트리 초기화
 * 파일 테이블에서 fd 제거
 */
void remove_file_from_fdt(int fd){
	struct thread *curr = thread_current();

	/* Error - invalid fd */ 
	if (fd < 0 || fd >= FDCOUNT_LIMIT){
		return;
	}

	curr->fdTable[fd] = NULL;
	// return;
}

