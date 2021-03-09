#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <errno.h>


int main(int argc, char const *argv[]) 
{
	int local_port_number, remote_port_number, num_pages, page_size, len, x;
	int remote_server_sock = 0, local_server_sock = 0, new_socket = 0, option = 1;
	struct sockaddr_in self_address, serv_addr;
	int addrlen = sizeof(self_address);
	char * mmapped_addr;
	long y=0;

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
			printf("memory allocation successful, mmapped address = %p, mmapped size = %d\n", 
					mmapped_addr, len);

		y = (unsigned long) mmapped_addr;

		send (new_socket, &y, sizeof(y), 0);
		//printf("Mapped address pointer sent to client\n");

		send (new_socket, &len, sizeof(len), 0);
		//printf("Mapped size sent to client\n");

		return 0;

    	}

 	x = read (remote_server_sock, &y, sizeof(y));
	printf("number of bytes read %d\n", x);
	if (x > 0){
		mmapped_addr = (char *) y;
	}

	if (read(remote_server_sock, &len, sizeof(len)) < 0){
                printf("len read failed\n");
        } 
     
	mmapped_addr = mmap((char *)y, len, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
                if (mmapped_addr == MAP_FAILED)
                        printf("memory allocation unsuccessful\n");
                else
                        printf("memory allocation successful, mmapped address = %p, mmapped size = %d\n", mmapped_addr, len);
	
	
	return 0;
}


