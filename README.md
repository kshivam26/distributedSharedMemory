# distributedSharedMemory

[Part 1] Pairing memorey regions between two systems

Create a (user-land) application named s2dsm that takes as input a local port number and a
remote port number. Two instances of s2dsm communicates each other over sockets. For example, when
running ./s2dsm 5000 6000 and ./s2dsm 6000 5000, two processes pair up each other. The first
s2dsm process listens on the port 5000 and send messages to the port 6000. The second process listens
on the port 6000 and send messages to the port 5000.
After pairing, the first s2dsm process:
• asks a user to specify the number of pages to allocate through stdin: e.g., " > How many pages would
you like to allocate (greater than 0)?"
• mmaps a memory region of the size specified by <the number of pages> * PAGESIZE;
• printfs the address of the mmaped region (the return value of mmap) and the mmapped size; and
• sends a message including the mmaped address and size to the second process over a socket
communication.
The second s2dsm process:
• receives the message including the mmapped address and size from the first process;
• mmaps a memory region of the same size to the same address (by specifying the first argument of
mmap); and
• printfs the address of the mmaped region and the mma
