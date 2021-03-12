#define _GNU_SOURCE
#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/types.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <poll.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE);	\
	} while (0)

static int page_size;


static void * fault_handler_thread(void *arg){
	static struct uffd_msg msg;   /* Data read from userfaultfd */
	static int fault_cnt = 0;     /* Number of faults so far handled */
	long uffd;                    /* userfaultfd file descriptor */
	static char *page = NULL;
	struct uffdio_copy uffdio_copy;
	ssize_t nread;

	uffd = (long) arg;

	if (page == NULL) {
		page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (page == MAP_FAILED)
			errExit("mmap");
	}

	for (;;) {

		struct pollfd pollfd;
		int nready;

		pollfd.fd = uffd;
		pollfd.events = POLLIN;
		nready = poll(&pollfd, 1, -1);
		if (nready == -1)
			errExit("poll");


		nread = read(uffd, &msg, sizeof(msg));
		if (nread == 0) {
			printf("EOF on userfaultfd!\n");
			exit(EXIT_FAILURE);
		}

		if (nread == -1)
			errExit("read");

		if (msg.event != UFFD_EVENT_PAGEFAULT) {
			fprintf(stderr, "Unexpected event on userfaultfd\n");
			exit(EXIT_FAILURE);
		}

		memset(page, '\0', page_size);
		fault_cnt++;

		uffdio_copy.src = (unsigned long) page;
		uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
			~(page_size - 1);
		uffdio_copy.len = page_size;
		uffdio_copy.mode = 0;
		uffdio_copy.copy = 0;

		if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
			errExit("ioctl-UFFDIO_COPY");

		printf("[x] PAGEFAULT\n");
	}
}

void read_and_print_page(char * addr, int page_num){
	char message[4096];
        strcpy(message, addr);
        printf("[*] Page %d:\n%s\n", page_num, message);
}

void write_page(char * addr, char * message){
	int j = 0;
	while (j <= strlen(message)){
		memset(addr+j, *(message+j), 1);
		j++;
	}
}

int perform_read_write_actions(char * mmapped_addr, int num_pages){
		while (1){
			char command_option;
			int page_number_option;	
			char write_message_buffer[page_size];

			printf("Which command should I run? (r:read, w:write, 1:exit):");
			scanf(" %c", &command_option);

			if (command_option != 'r' && command_option != 'w'){
				printf("Thanks for stopping by\n");
				return 0;
			}

			printf("For which page?(0-%d, or -1 for all):", num_pages-1);
			scanf("%d", &page_number_option);
			
			if (command_option == 'w'){
				printf("> Type your new message:");
				scanf(" %[^\n]%*c", write_message_buffer);	// not very safe, using it because of upper limit on message
			}

			if (page_number_option == -1){
				int i=0;
				int l = 0x0;
				if (command_option == 'r'){
					while (i < num_pages){
						read_and_print_page(mmapped_addr+l, i);
						i++;
						l = l + page_size;
					}
				}
				else {
					while (i < num_pages){
						write_page(mmapped_addr+l, write_message_buffer);
						read_and_print_page(mmapped_addr+l, i);
						i++;
                                                l = l + page_size;
                                        }
				}	
			}
			else {
				int l = 0x0;
				l = l + page_number_option * page_size;
				if (command_option == 'r'){
					read_and_print_page(mmapped_addr+l, page_number_option);
				}
				else {
					write_page(mmapped_addr+l, write_message_buffer);
					read_and_print_page(mmapped_addr+l, page_number_option);
				}
			}
		}
}

void setup_userfaultfd(char * mmapped_addr, unsigned long len){
	long uffd;
        pthread_t thr;      /* ID of thread that handles page faults */
        struct uffdio_api uffdio_api;
        struct uffdio_register uffdio_register;
        int s;

	uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);

        if (uffd == -1)
        	errExit("userfaultfd");

        uffdio_api.api = UFFD_API;
        uffdio_api.features = 0;
        if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        	errExit("ioctl-UFFDIO_API");

        uffdio_register.range.start = (unsigned long) mmapped_addr;
        uffdio_register.range.len = len;
        uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
        if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
 	       errExit("ioctl-UFFDIO_REGISTER");


        s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
        if (s != 0) {
        	errno = s;
                errExit("pthread_create");
        }
}

int main(int argc, char const *argv[]) 
{
	int local_port_number, remote_port_number, num_pages, x;
	int remote_server_sock = 0, local_server_sock = 0, new_socket = 0, option = 1;
	struct sockaddr_in self_address, serv_addr;
	int addrlen = sizeof(self_address);
	char * mmapped_addr;
	long mmapped_addr_long=0;
        unsigned long len;  /* Length of region handled by userfaultfd */

	if (argc != 3) {
		fprintf(stderr, "invalid number of arguments");
		exit(EXIT_FAILURE);
	}

	local_port_number = strtoul(argv[1], NULL, 0);
	remote_port_number = strtoul(argv[2], NULL, 0);

	if ((remote_server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Socket creation error \n");
	}

	memset(&serv_addr, '0', sizeof(serv_addr));
    	serv_addr.sin_family = AF_INET;
    	serv_addr.sin_port = htons(remote_port_number);

	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
		printf("\nInvalid address/ Address not supported \n");
		exit(EXIT_FAILURE);
	}

	if (connect(remote_server_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		printf("\nConnection Failed \n");

		if ((local_server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			printf("\n Socket creation error \n");
			exit(EXIT_FAILURE);
		}

		if (setsockopt(local_server_sock, SOL_SOCKET, 
			SO_REUSEADDR | SO_REUSEPORT,
			&option, sizeof(option))) {
			perror("setsockopt");
			exit(EXIT_FAILURE);
		}

		self_address.sin_family = AF_INET;
		self_address.sin_addr.s_addr = INADDR_ANY;
		self_address.sin_port = htons(local_port_number);


        	if (bind(local_server_sock, (struct sockaddr *)&self_address, 
			sizeof(self_address)) < 0) {
                	perror("bind failed");
	                exit(EXIT_FAILURE);
        	}


        	if (listen(local_server_sock, 3) < 0) {
                	perror("listen");
	                exit(EXIT_FAILURE);
        	}

        	if ((new_socket = accept(local_server_sock, (struct sockaddr *)&self_address,
                                 (socklen_t*)&addrlen)) < 0) {
                	perror("accept");
	                exit(EXIT_FAILURE);
        	}

		printf("How many pages would you like to allocate (greater than 0)?\n");
		if(scanf("%d", &num_pages)){
			printf("num_pages read is %d\n", num_pages);
		}

		page_size = sysconf(_SC_PAGE_SIZE);
		len = num_pages * page_size;

		mmapped_addr = mmap(NULL, len, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (mmapped_addr == MAP_FAILED)
			printf("memory allocation unsuccessful\n");
		else 
			printf("memory allocation successful, mmapped address = %p, mmapped size = %ld\n", 
					mmapped_addr, len);

		mmapped_addr_long = (unsigned long) mmapped_addr;

		send (new_socket, &mmapped_addr_long, sizeof(mmapped_addr_long), 0);
		//printf("Mapped address pointer sent to client\n");

		send (new_socket, &len, sizeof(len), 0);
		//printf("Mapped size sent to client\n");
		
		setup_userfaultfd(mmapped_addr, len);	

		printf("-----------------------------------------------------\n");

		perform_read_write_actions(mmapped_addr, num_pages);
		
		return 0;

    	}

	page_size = sysconf(_SC_PAGE_SIZE);

 	x = read (remote_server_sock, &mmapped_addr_long, sizeof(mmapped_addr_long));
	printf("number of bytes read %d\n", x);
	if (x > 0){
		mmapped_addr = (char *) mmapped_addr_long;
	}

	if (read(remote_server_sock, &len, sizeof(len)) < 0){
                printf("len read failed\n");
        } 
     
	mmapped_addr = mmap((char *)mmapped_addr_long, len, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
                if (mmapped_addr == MAP_FAILED)
                        printf("memory allocation unsuccessful\n");
                else
                        printf("memory allocation successful, mmapped address = %p, mmapped size = %ld\n", mmapped_addr, len);

	num_pages = len/page_size;

	setup_userfaultfd(mmapped_addr, len);

	perform_read_write_actions(mmapped_addr, num_pages);

	return 0;
}


