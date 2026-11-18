/* Emulation backend: "emu:<file.xml>" builds a fake device tree from the XML, and attribute writes
 * mutate it in place. The input is the XML, optionally followed by a NUL and the bytes written to
 * the attributes (exact-size heap copies, no trailing NUL). */
#include <iio/iio.h>
#include <libxml/parser.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "walk.h"
#include "xml_inert.h"

static char xml_path[4096];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	const char *tmp = getenv("TMPDIR");
	char dir[4096];

	(void)argc;
	(void)argv;
	snprintf(dir, sizeof(dir), "%s/emu-XXXXXX", tmp && *tmp ? tmp : "/tmp");
	if (!mkdtemp(dir))
		return 1;
	snprintf(xml_path, sizeof(xml_path), "%s/dev.xml", dir);
	xml_inert(xml_path);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct iio_context_params params = { .log_level = LEVEL_NOLOG };
	struct walk w = { 0 };
	struct iio_context *ctx;
	char uri[4200];
	size_t xml_len = size;
	FILE *f;
	const uint8_t *nul = memchr(data, 0, size);

	w.write = true;
	w.payload = (const uint8_t *)"0123456789abcdef";
	w.size = 16;
	if (nul && nul + 1 < data + size) {
		xml_len = nul - data;
		w.payload = nul + 1;
		w.size = size - xml_len - 1;
	}

	f = fopen(xml_path, "wb");
	if (!f)
		return 0;
	fwrite(data, 1, xml_len, f);
	fclose(f);

	snprintf(uri, sizeof(uri), "emu:%s", xml_path);
	ctx = iio_create_context(&params, uri);
	if (!iio_err(ctx)) {
		walk_context(&w, ctx);
		iio_context_destroy(ctx);
	}
	unlink(xml_path);
	return 0;
}
