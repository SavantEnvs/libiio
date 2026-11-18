/* XML backend: a context description given as memory ("xml:<?xml ...?>..."), the form a client
 * parses when a server sends its XML. Reaches xml.c and the common context walk. */
#include <iio/iio.h>
#include <libxml/parser.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "walk.h"
#include "xml_inert.h"

#define XML_HEADER "<?xml version=\"1.0\""

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	xml_inert(NULL);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct iio_context_params params = { .log_level = LEVEL_NOLOG };
	struct walk w = { 0 };
	struct iio_context *ctx;
	char *uri;

	/* xml.c reads the argument as a file name unless it starts with XML_HEADER; a file name taken
	 * from the input would read arbitrary files instead of testing the parser. */
	if (size < sizeof(XML_HEADER) - 1 || memcmp(data, XML_HEADER, sizeof(XML_HEADER) - 1))
		return -1;

	uri = malloc(4 + size + 1);
	if (!uri)
		return 0;
	memcpy(uri, "xml:", 4);
	memcpy(uri + 4, data, size);
	uri[4 + size] = '\0';

	ctx = iio_create_context(&params, uri);
	free(uri);
	if (iio_err(ctx))
		return 0;

	walk_context(&w, ctx);
	iio_context_destroy(ctx);
	return 0;
}
