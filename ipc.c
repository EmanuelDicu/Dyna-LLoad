#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"

int create_socket()
{
	int sockfd;

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket");
		return -1;
	}
	return sockfd;
}

int connect_socket(int fd)
{
	struct sockaddr_un addr;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		perror("connect");
		return -1;
	}
	return 0;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
	ssize_t send;

	send = write(fd, buf, len);
	if (send == -1) {
		perror("send");
		return -1;
	}

	return send;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	ssize_t recv = 0;

	recv = read(fd, buf, len);
	if (recv == -1) {
		perror("recv");
		return -1;
	}

	// fprintf(stderr, "Received %ld bytes\n", recv);

	return recv;
}

void close_socket(int fd) { close(fd); }
