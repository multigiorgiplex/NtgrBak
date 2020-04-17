#include <stdint.h>
#include <string.h>
#include <endian.h>
#include "config.h"


/* Model ID */
enum {
	MODEL_UNKNOWN = 0,
	MODEL_WNDR4500v2,

	MODEL_ELEMENTS
};

/* Model string (ID-indexed) */
const char *MODELS_s[] = {
	"unknown",
	"WNDR4500v2"
};

/* Model magic (ID-indexed) */
const unsigned int MODELS_m[] = {
	0,			//Unknown
	0x62744915	//WNDR4500v2
};


/* Checks if the buffer is corrupted
 * buffer:		The buffer to checks
 * buffer_len:	The buffer length
 * RETURN:		1: The buffer is not corrupted, 0: The buffer is corrupted
 */
int verify_checksum (unsigned char* buffer, int buffer_len)
{
	/* The buffer is not corrupted if the checksum calculated for the entire buffer is 0x00000000 */
	return calculate_checksum(buffer, buffer_len) == 0 ? 1 : 0;
}


/* Generate and apply the buffer checksum
 * buffer:		Data buffer
 * buffer_len:	Data buffer length
 */
void generate_checksum (unsigned char* buffer, int buffer_len)
{
	unsigned int cksum;
	uint32_t cksum_be;

	if (!buffer || buffer_len < 0)
		return;

	/* Set checksum region at 0 */
	cksum = 0;
	memcpy (buffer +8, &cksum, 4);

	/* Calculate the actual checksum */
	cksum = calculate_checksum (buffer, buffer_len);
	cksum_be = htobe32 ((uint32_t) cksum);

	/* Apply the checksum */
	memcpy (buffer +8, &cksum_be, 4);
}


/* Calculate a checksum for the given input buffer
 * buffer:		Input data buffer
 * buffer_len:	Input data buffer length
 * RETURN:		Input buffer checksum
 * NOTE: This function has been reverse engineered from Netgear's firmware
 */
unsigned int calculate_checksum (unsigned char* buffer, int buffer_len)
{
	unsigned int cksum, ret;
	unsigned short * buffer_w;

	if (!buffer || buffer_len <= 0)
		return 0xFFFFFFFF;

	/* In case of a odd input buffer length place the last byte to cksum variable */
	buffer_w = (unsigned short *) buffer;
	if (buffer_len % 2)
		cksum = (unsigned int) *(buffer + (--buffer_len));
	else
		cksum = 0;

	/* Take two bytes at a time and sum to the cksum variable */
	while (buffer_len > 0)
	{
		cksum += (unsigned int) *buffer_w++;
		buffer_len -= 2;
	}

	/* Compress the result in sum to 16bit and return the swapped bytes (account for endianness) */
	ret = cksum & 0xFFFF;
	ret += cksum >> 16;
	ret += ret >> 16;
	return (((unsigned int) be16toh (~ret)) & 0xFFFF);
}


/* Generate the configuration magic number based on model string
 * router_name:		Model string
 * RETURN:			Configuration magic number (Model magic)
 * NOTE: This function has been reverse engineered from Netgear's firmware
 */
unsigned int generate_magic (unsigned char *router_name)
{
	unsigned int magic;
	unsigned char buffer[16+1];	//Accommodate for \0 byte
	unsigned int * buffer_p;

	if (!router_name)
		return 0;

	memset (buffer, 0x00, 16+1);
	strncpy ((char *)buffer, (char *)router_name, 16);

	/* Take the string 4 characters at the time and XOR them */
	buffer_p = (unsigned int *) buffer;
	magic  = *(buffer_p++);
	magic ^= *(buffer_p++);
	magic ^= *(buffer_p++);
	magic ^= *(buffer_p);

	return ((unsigned int) magic);
}


/* Get the configuration magic
 * config_buffer:	The configuration buffer
 * RETURN:			The configuration magic number (Model magic)
 */
unsigned int get_magic (unsigned char *config_buffer)
{
	if (!config_buffer)
		return 0;

	return (unsigned int) be32toh (*((uint32_t *)(config_buffer)));
}


/* Applies to a configuration the provided magic number
 * config_buffer:	The configuration buffer
 * magic:			The magic number calculated before
 */
void set_magic (unsigned char *config_buffer, unsigned int magic)
{
	uint32_t magic_be;

	if (!config_buffer)
		return;

	magic_be = htobe32 ((uint32_t) magic);
	memcpy (config_buffer, &magic_be, 4);
}


/* Get the model based on the magic number
 * magic:	The magic number
 * RETURN:	A pointer from the models internal list matching that magic
 */
const char * get_model (unsigned int magic)
{
	int i;

	for (i = 0; i < MODEL_ELEMENTS; i++)
	{
		if (MODELS_m[i] == magic)
			return MODELS_s[i];
	}

	return MODELS_s[MODEL_UNKNOWN];
}


/* Get the configuration length
 * config_buffer:	The configuration buffer
 * RETURN:			The configuration length
 */
unsigned int get_config_length (unsigned char *config_buffer)
{
	if (!config_buffer)
		return 0;

	return (unsigned int) be32toh (*((uint32_t *)(config_buffer +4)));
}


/* Applies to a configuration the provided length
 * config_buffer:	The configuration buffer
 * len:				The configuration length
 */
void set_config_length (unsigned char *config_buffer, int len)
{
	uint32_t len_be;

	if (!config_buffer || len < 0)
		return;

	len_be = htobe32 ((uint32_t) len);
	memcpy (config_buffer +4, &len_be, 4);
}


/* Get the configuration version
 * config_buffer:	The configuration buffer
 * RETURN:			Configuration version
 */
unsigned int get_config_version (unsigned char *config_buffer)
{
	if (!config_buffer)
		return 0;

	return (unsigned int) be32toh (*((uint32_t *)(config_buffer +12)));
}


/* Applies to a configuration the provided version
 * config_buffer:	The configuration buffer
 * ver:				The configuration version
 */
void set_config_version (unsigned char *config_buffer, int ver)
{
	uint32_t ver_be;

	if (!config_buffer || ver < 0)
		return;

	ver_be = htobe32 ((uint32_t) ver);
	memcpy (config_buffer +12, &ver_be, 4);
}
