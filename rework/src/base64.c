/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include "base64.h"

static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

byte* ssc_base64_encode(byte*src, size_t len,size_t *out_len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len)return NULL; /* integer overflow */

	out = custom_malloc(olen);
	if (out == NULL)return NULL;

	end = src + len;
	in = src;
	pos = out;
	while (end - in >= 3) {
		*pos++ = base64_table[(in[0] >> 2) & 0x3f];
		*pos++ = base64_table[(((in[0] & 0x03) << 4) |
				       (in[1] >> 4)) & 0x3f];
		*pos++ = base64_table[(((in[1] & 0x0f) << 2) |
				       (in[2] >> 6)) & 0x3f];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
	}

	if (end - in) {
		*pos++ = base64_table[(in[0] >> 2) & 0x3f];
		if (end - in == 1) {
			*pos++ = base64_table[((in[0] & 0x03) << 4) & 0x3f];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[(((in[0] & 0x03) << 4) |
					       (in[1] >> 4)) & 0x3f];
			*pos++ = base64_table[((in[1] & 0x0f) << 2) & 0x3f];
		}
		*pos++ = '=';
	}

	*pos = '\0';
	if (out_len)
		*out_len = pos - out;
	return out;
}

byte* ssc_base64_decode(byte *src, size_t len,size_t *out_len)
{
	unsigned char dtable[256], *out, *pos, block[4], tmp;
	size_t i, count, olen;
	int pad = 0;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char) i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = out = custom_malloc(olen);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					custom_free(out);
					return NULL;
				}
				break;
			}
		}
	}

	*out_len = pos - out;
	return out;
}
