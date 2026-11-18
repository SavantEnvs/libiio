/* Network backend as a client: the input is everything a (malicious) iiod sends back, byte for byte.
 * A loopback listener hands the whole input to each connection the client opens, then closes its
 * write side, so the client sees end-of-stream instead of waiting. The client creates the context
 * through iio_create_context("ip:..."), then reads/writes every attribute and streams a buffer. */
#include <arpa/inet.h>
#include <iio/iio.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "walk.h"
#include "xml_inert.h"

#define MAX_CONNECTIONS 8

struct server {
	int listener;
	const uint8_t *data;
	size_t size;
};

struct connection {
	pthread_t thread;
	int fd;
	const struct server *srv;
};

static bool send_all(int fd, const uint8_t *data, size_t len)
{
	while (len) {
		ssize_t n = send(fd, data, len, MSG_NOSIGNAL);

		if (n <= 0)
			return false;
		data += n;
		len -= n;
	}
	return true;
}

/* Plays the server side of one connection from the input. The first line answers "BINARY\r\n". When
 * that answer is 0 the client switches to the binary protocol, whose reader thread drops any response
 * it is not waiting for, so the rest of the input is sent one frame (8-byte header, plus payload for a
 * response) per client write. Otherwise it is the line protocol, which reads the stream in order, and
 * the rest is sent at once. The input ending closes the write side, so the client sees end-of-stream
 * instead of waiting. */
static void *feed(void *arg)
{
	struct connection *conn = arg;
	const uint8_t *data = conn->srv->data;
	size_t size = conn->srv->size, off = 0;
	char sink[4096];
	const uint8_t *nl = memchr(data, '\n', size);
	size_t line = nl ? (size_t)(nl - data) + 1 : size;
	bool binary = false;
	char num[16] = { 0 };

	if (read(conn->fd, sink, sizeof(sink)) <= 0)
		goto out;

	if (line < sizeof(num)) {
		char *end;

		memcpy(num, data, line);
		binary = strtol(num, &end, 10) == 0 && end != num;
	}
	if (!send_all(conn->fd, data, line))
		goto out;
	off = line;

	while (binary && off < size) {
		size_t frame = size - off;
		int32_t code;

		if (frame >= 8) {
			memcpy(&code, data + off + 4, sizeof(code));
			frame = 8;
			if (data[off + 2] == 0 && code > 0)
				frame += (size_t)code < size - off - 8 ? (size_t)code : size - off - 8;
		}
		if (read(conn->fd, sink, sizeof(sink)) <= 0)
			goto out;
		if (!send_all(conn->fd, data + off, frame))
			goto out;
		off += frame;
	}
	if (off < size)
		send_all(conn->fd, data + off, size - off);

out:
	shutdown(conn->fd, SHUT_WR);
	while (read(conn->fd, sink, sizeof(sink)) > 0)
		;
	close(conn->fd);
	return NULL;
}

/* The client opens one connection for the context and one more per streaming buffer; each is answered
 * with the same input. */
static void *serve(void *arg)
{
	struct server *srv = arg;
	struct connection conns[MAX_CONNECTIONS];
	unsigned int nb = 0;

	while (nb < MAX_CONNECTIONS) {
		int fd = accept(srv->listener, NULL, NULL);

		if (fd < 0)
			break;
		conns[nb].fd = fd;
		conns[nb].srv = srv;
		if (pthread_create(&conns[nb].thread, NULL, feed, &conns[nb])) {
			close(fd);
			break;
		}
		nb++;
	}
	for (unsigned int i = 0; i < nb; i++)
		pthread_join(conns[i].thread, NULL);
	return NULL;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	xml_inert(NULL);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct iio_context_params params = { .log_level = LEVEL_NOLOG, .timeout_ms = 200 };
	static const uint8_t write_bytes[] = "0123456789abcdef";
	struct walk w = { .payload = write_bytes, .size = 16, .write = true };
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t alen = sizeof(addr);
	struct server srv = { .data = data, .size = size };
	struct iio_context *ctx;
	pthread_t thread;
	char uri[64];

	srv.listener = socket(AF_INET, SOCK_STREAM, 0);
	if (srv.listener < 0)
		return 0;
	if (bind(srv.listener, (struct sockaddr *)&addr, sizeof(addr)) || listen(srv.listener, MAX_CONNECTIONS) ||
			getsockname(srv.listener, (struct sockaddr *)&addr, &alen)) {
		close(srv.listener);
		return 0;
	}
	if (pthread_create(&thread, NULL, serve, &srv)) {
		close(srv.listener);
		return 0;
	}

	snprintf(uri, sizeof(uri), "ip:127.0.0.1:%u", ntohs(addr.sin_port));
	ctx = iio_create_context(&params, uri);
	if (!iio_err(ctx)) {
		walk_context(&w, ctx);
		walk_stream(ctx);
		iio_context_destroy(ctx);
	}

	/* If the client gave up before connecting, unblock accept(). */
	shutdown(srv.listener, SHUT_RDWR);
	pthread_join(thread, NULL);
	close(srv.listener);
	return 0;
}
