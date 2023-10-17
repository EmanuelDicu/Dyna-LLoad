#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <pthread.h>

#include "ipc.h"
#include "server.h"

#ifndef OUTPUTFILE_TEMPLATE
#define OUTPUTFILE_TEMPLATE "../checker/output/out-XXXXXX"
#endif

static int lib_prehooks(struct lib *) { return 0; }

static int lib_load(struct lib *lib)
{
	lib->handle = dlopen(lib->libname, RTLD_LAZY);
	if (!lib->handle) {
		fprintf(stderr, "dlopen: %s\n", dlerror());
		return -1;
	}

	if (lib->funcname) {
		if (lib->filename) {
			lib->p_run = dlsym(lib->handle, lib->funcname);
			if (!lib->p_run) {
				fprintf(stderr, "dlsym: %s\n", dlerror());
				dlclose(lib->handle);
				return -1;
			}
		} else {
			lib->run = dlsym(lib->handle, lib->funcname);
			if (!lib->run) {
				fprintf(stderr, "dlsym: %s\n", dlerror());
				dlclose(lib->handle);
				return -1;
			}
		}
	} else {
		lib->run = dlsym(lib->handle, "run");
		if (!lib->run) {
			fprintf(stderr, "dlsym: %s\n", dlerror());
			dlclose(lib->handle);
			return -1;
		}
	}

	return 0;
}

static int lib_execute(struct lib *lib)
{
	if (lib->filename) {
		lib->p_run(lib->filename);
	} else {
		lib->run();
	}
	return 0;
}

static int lib_close(struct lib *lib)
{
	if (lib->handle) {
		dlclose(lib->handle);
		lib->handle = NULL;
	}

	return 0;
}

static int lib_posthooks(struct lib *) { return 0; }

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_load(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *libname, char *funcname,
												 char *filename)
{
	return sscanf(buf, "%s %s %s", libname, funcname, filename);
}

void process_client(int client_fd)
{
	char buf[BUFSIZE];
	int read_bytes;

	read_bytes = recv_socket(client_fd, buf, sizeof(buf));
	DIE(read_bytes < 0, "recv");

	buf[read_bytes] = '\0';

	struct lib lib;
	char libname[BUFSIZE];
	char funcname[BUFSIZE];
	char filename[BUFSIZE];
	char outputfile[BUFSIZE];

	int nr = parse_command(buf, libname, funcname, filename);
	if (nr < 1) {
		return;
	}

	memset(&lib, 0, sizeof(lib));
	

	lib.libname = libname;
	if (nr > 1)
		lib.funcname = funcname;
	if (nr > 2)
		lib.filename = filename;

	strncpy(outputfile, OUTPUTFILE_TEMPLATE, BUFSIZE);
	int outfd = mkstemp(outputfile);
	DIE(outfd < 0, "mkstemp");

	lib.outputfile = outputfile;

	pid_t pid = fork();
	DIE(pid < 0, "fork");

	if (pid == 0) {
		int ret = dup2(outfd, STDOUT_FILENO);
		DIE(ret < 0, "dup2");

		setvbuf(stdout, NULL, _IONBF, 0);

		ret = lib_run(&lib);
		if (ret != 0) {
			printf("Error: ");
			if (lib.libname)
				printf("%s ", lib.libname);
			if (lib.funcname)
				printf("%s ", lib.funcname);
			if (lib.filename)
				printf("%s ", lib.filename);

			printf("could not be executed.\n");
		}
		exit(ret);
	}

	int status;
	waitpid(pid, &status, 0);

	send_socket(client_fd, outputfile, strlen(outputfile));
}

int main(void)
{
	int ret = 0;
	int server_fd;
	struct sockaddr_un addr;

	ret = unlink(SOCKET_NAME);
	DIE(ret < 0 && errno != ENOENT, "unlink");

	server_fd = create_socket();

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);
	ret = bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
	DIE(ret < 0, "bind");

	ret = listen(server_fd, MAX_CLIENTS + 1);
	DIE(ret < 0, "listen");

	while (1) {
		int client_fd;
		struct sockaddr_un raddr;
		socklen_t addr_len = sizeof(raddr);

		client_fd = accept(server_fd, (struct sockaddr *)&raddr, &addr_len);
		DIE(client_fd < 0, "accept");

		pid_t pid = fork();
		DIE(pid < 0, "fork");

		if (pid == 0) {
			process_client(client_fd);
			close(client_fd);
			exit(0);
		}
	}

	return 0;
}
