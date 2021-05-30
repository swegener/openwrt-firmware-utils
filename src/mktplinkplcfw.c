/*
 * Copyright (C) 2021 Sven Wegener
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#include <libgen.h>
#include <getopt.h>
#include <endian.h>
#include <arpa/inet.h>

#include "md5.h"


#define MD5SUM_LEN	16
#define MD5SUM_DATA_LEN	(32 * 1024)
#define HEADER_VERSION	1
#define HEADER_MAGIC	"NEW"

struct fw_header {
	uint8_t		md5sum1[MD5SUM_LEN];
	uint32_t	file_size;
	uint8_t		version;
	char		magic[3]; /* "NEW" */
	uint32_t	header_size;
	uint8_t		padding[8];
	uint32_t	firmware_size;
	uint8_t		md5sum2[MD5SUM_LEN];
} __attribute__ ((packed));


static char *ifname;
static char *ofname;
static char *progname;


static void get_md5(const uint8_t *data, int size, uint8_t *md5)
{
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, data, size);
	MD5_Final(md5, &ctx);
}

static const char md5salt[MD5SUM_LEN] = {
	0xcc, 0x96, 0x28, 0xee, 0x8d, 0xfb, 0x21, 0xbb,
	0x3d, 0xef, 0x6c, 0xb5, 0x9f, 0x77, 0x4c, 0x7c,
};

static void usage(int status)
{
	fprintf(stderr, "Usage: %s [OPTIONS...]\n", progname);
	fprintf(stderr,
"\n"
"Options:\n"
"  -i <file>       read input from file <file>\n"
"  -o <file>       write output to the file <file>\n"
"  -h              show this screen\n"
	);

	exit(status);
}

static void fill_header(char *buf, int len)
{
	struct fw_header *hdr = (struct fw_header *)buf;

	memset(hdr, 0, sizeof(struct fw_header));

	hdr->version = HEADER_VERSION;
	memcpy(hdr->magic, HEADER_MAGIC, sizeof(hdr->magic));
	memset(hdr->padding, 0, sizeof(hdr->padding));

	hdr->file_size = htonl(len - offsetof(struct fw_header, version));
	hdr->header_size = htonl(sizeof(struct fw_header) - offsetof(struct fw_header, version));
	hdr->firmware_size = htonl(len - sizeof(struct fw_header));

	// The md5sums include the salt plus the next 32 KiB of data
	memcpy(hdr->md5sum2, md5salt, sizeof(hdr->md5sum2));
	get_md5(hdr->md5sum2, MD5SUM_LEN + MD5SUM_DATA_LEN, hdr->md5sum2);
	memcpy(hdr->md5sum1, md5salt, sizeof(hdr->md5sum1));
	get_md5(hdr->md5sum1, MD5SUM_LEN + MD5SUM_DATA_LEN, hdr->md5sum1);
}

static int build(void)
{
	char *buf;
	uint32_t len;
	struct stat st;
	FILE *file;

	if (stat(ifname, &st))
		return EXIT_FAILURE;

	len = st.st_size + sizeof(struct fw_header);
	buf = malloc(len);
	if (!buf)
		return EXIT_FAILURE;

	file = fopen(ifname, "rb");
	if (!file)
		return EXIT_FAILURE;
	fread(buf + sizeof(struct fw_header), st.st_size, 1, file);
	fclose(file);

	fill_header(buf, len);

	file = fopen(ofname, "wb");
	if (!file)
		return EXIT_FAILURE;
	fwrite(buf, len, 1, file);
	fclose(file);

	return 0;
}

int main(int argc, char *argv[])
{
	progname = basename(argv[0]);

	while (true) {
		int c;

		c = getopt(argc, argv, "i:o:h");
		if (c == -1)
			break;

		switch (c) {
		case 'i':
			ifname = optarg;
			break;
		case 'o':
			ofname = optarg;
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		default:
			usage(EXIT_FAILURE);
			break;
		}
	}

	return build();
}
