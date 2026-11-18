/* The XML a harness feeds libiio may name a DTD or external entity; libxml2 would then open whatever
 * path or URL the input picked (a FIFO or /dev/stdin blocks forever). Only the harness's own document
 * is loadable, and libxml2's messages are dropped. */
#ifndef MAYHEM_XML_INERT_H
#define MAYHEM_XML_INERT_H

#include <libxml/parser.h>
#include <libxml/xmlIO.h>
#include <string.h>

static const char *xml_allowed_path;
static xmlExternalEntityLoader xml_default_loader;

static void xml_quiet(void *ctx, const char *msg, ...)
{
	(void)ctx;
	(void)msg;
}

static xmlParserInputPtr xml_only_own_file(const char *url, const char *id, xmlParserCtxtPtr ctxt)
{
	if (!xml_allowed_path || !url || strcmp(url, xml_allowed_path))
		return NULL;
	return xml_default_loader(url, id, ctxt);
}

static void xml_inert(const char *allowed_path)
{
	xml_allowed_path = allowed_path;
	xml_default_loader = xmlGetExternalEntityLoader();
	xmlSetExternalEntityLoader(xml_only_own_file);
	xmlSetGenericErrorFunc(NULL, xml_quiet);
}

#endif
