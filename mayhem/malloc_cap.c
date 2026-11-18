/* Models a memory-limited process for the harnesses that drive iiod's responder (linked with
 * -Wl,--wrap=malloc). handle_write_attr() does malloc(len) with a 64-bit length read off the wire and
 * answers -ENOMEM on NULL; glibc returns NULL for an unsatisfiable size, but ASan's allocator aborts
 * instead ("allocation size exceeds maximum"), which would report that handled failure as a defect. */
#include <errno.h>
#include <stddef.h>

#define MALLOC_CAP ((size_t)1 << 30)

void *__real_malloc(size_t size);

void *__wrap_malloc(size_t size)
{
	if (size > MALLOC_CAP) {
		errno = ENOMEM;
		return NULL;
	}
	return __real_malloc(size);
}
