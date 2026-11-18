/* Shared by the harnesses: exercise a freshly created context through libiio's public API. */
#ifndef MAYHEM_WALK_H
#define MAYHEM_WALK_H

#include <iio/iio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct walk {
	const uint8_t *payload;
	size_t size;
	size_t pos;
	bool write;
};

/* Reads and, when w->write is set, writes one attribute. The written bytes are an exact-size heap copy
 * of the payload, with no trailing NUL, so a backend that treats them as a C string overreads. */
static void walk_attr(struct walk *w, const struct iio_attr *attr)
{
	char val[256];
	double min, step, max;
	char **list;
	size_t count;

	if (!attr)
		return;

	(void)iio_attr_get_name(attr);
	(void)iio_attr_get_filename(attr);
	(void)iio_attr_get_static_value(attr);
	(void)iio_attr_read_raw(attr, val, sizeof(val));
	(void)iio_attr_get_range(attr, &min, &step, &max);
	if (iio_attr_get_available(attr, &list, &count) == 0) {
		for (size_t i = 0; i < count; i++)
			(void)strlen(list[i]);
		iio_available_list_free(list, count);
	}

	if (w->write && w->size) {
		size_t len = 1 + w->payload[w->pos % w->size] % 33;
		uint8_t *copy = malloc(len);

		if (!copy)
			return;
		for (size_t i = 0; i < len; i++)
			copy[i] = w->payload[(w->pos + 1 + i) % w->size];
		w->pos += len + 1;

		(void)iio_attr_write_raw(attr, copy, len);
		free(copy);
		(void)iio_attr_read_raw(attr, val, sizeof(val));
	}
}

static void walk_channel(struct walk *w, const struct iio_channel *chn)
{
	(void)iio_channel_get_id(chn);
	(void)iio_channel_get_name(chn);
	(void)iio_channel_get_label(chn);
	(void)iio_channel_is_output(chn);
	(void)iio_channel_is_scan_element(chn);
	(void)iio_channel_get_type(chn);
	(void)iio_channel_get_data_format(chn);

	for (unsigned int i = 0; i < iio_channel_get_attrs_count(chn); i++)
		walk_attr(w, iio_channel_get_attr(chn, i));
	for (unsigned int i = 0; i < iio_channel_get_event_attrs_count(chn); i++)
		walk_attr(w, iio_channel_get_event_attr(chn, i));
}

static void walk_device(struct walk *w, struct iio_device *dev)
{
	(void)iio_device_get_id(dev);
	(void)iio_device_get_name(dev);
	(void)iio_device_get_label(dev);
	(void)iio_device_is_trigger(dev);
	(void)iio_device_get_trigger(dev);

	for (unsigned int i = 0; i < iio_device_get_attrs_count(dev); i++)
		walk_attr(w, iio_device_get_attr(dev, i));
	for (unsigned int i = 0; i < iio_device_get_debug_attrs_count(dev); i++)
		walk_attr(w, iio_device_get_debug_attr(dev, i));
	for (unsigned int i = 0; i < iio_device_get_event_attrs_count(dev); i++)
		walk_attr(w, iio_device_get_event_attr(dev, i));
	for (unsigned int i = 0; i < iio_device_get_buffers_count(dev); i++) {
		struct iio_buffer *buf = iio_device_get_buffer(dev, i);

		if (!buf)
			continue;
		(void)iio_buffer_is_output(buf);
		for (unsigned int j = 0; j < iio_buffer_get_attrs_count(buf); j++)
			walk_attr(w, iio_buffer_get_attr(buf, j));
	}
	for (unsigned int i = 0; i < iio_device_get_channels_count(dev); i++)
		walk_channel(w, iio_device_get_channel(dev, i));
}

static void walk_context(struct walk *w, struct iio_context *ctx)
{
	char *xml;

	(void)iio_context_get_name(ctx);
	(void)iio_context_get_description(ctx);
	(void)iio_context_get_version_major(ctx);

	xml = iio_context_get_xml(ctx);
	free(xml);

	for (unsigned int i = 0; i < iio_context_get_attrs_count(ctx); i++)
		walk_attr(w, iio_context_get_attr(ctx, i));
	for (unsigned int i = 0; i < iio_context_get_devices_count(ctx); i++)
		walk_device(w, iio_context_get_device(ctx, i));
}

/* Reads a few blocks from the first input buffer that has scan elements. */
static void walk_stream(struct iio_context *ctx)
{
	for (unsigned int d = 0; d < iio_context_get_devices_count(ctx); d++) {
		struct iio_device *dev = iio_context_get_device(ctx, d);
		struct iio_buffer *buf;
		struct iio_channels_mask *mask;
		struct iio_stream *stream;
		unsigned int nb = iio_device_get_channels_count(dev);
		bool any = false;

		if (!nb || !iio_device_get_buffers_count(dev))
			continue;
		buf = iio_device_get_buffer(dev, 0);
		if (!buf || iio_buffer_is_output(buf))
			continue;
		mask = iio_create_channels_mask(nb);
		if (!mask)
			continue;
		for (unsigned int c = 0; c < nb; c++) {
			struct iio_channel *chn = iio_device_get_channel(dev, c);

			if (iio_channel_is_scan_element(chn) && !iio_channel_is_output(chn)) {
				iio_channel_enable(chn, mask);
				any = true;
			}
		}
		if (any) {
			stream = iio_buffer_create_stream(buf, 2, 64, mask);
			if (!iio_err(stream)) {
				for (int i = 0; i < 3; i++) {
					const struct iio_block *blk = iio_stream_get_next_block(stream);

					if (iio_err(blk))
						break;
					(void)iio_block_start(blk);
				}
				iio_stream_destroy(stream);
			}
		}
		iio_channels_mask_destroy(mask);
		return;
	}
}

#endif
