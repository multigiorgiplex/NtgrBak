/*
 ============================================================================
 Name        : NtgrBak.c
 Author      : Marco Giorgi (multigiorgiplex), decryption/encryption routines are heavily based on Roberto Paleari's early work (http://roberto.greyhats.it/) (https://www.exploit-db.com/exploits/24916)
 Version     :
 Copyright   : See Apache License 2.0
 Description : Netgear configuration backup decrypter and encrypter
 ============================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* Defines */
#define BUFFER_SIZE		(0x20000)
#define MAX_FILE_SIZE	BUFFER_SIZE
#define KEY_STR			"NtgrBak"
#define USAGE	\
"Usage:\n\
		./NtgrBak <mode> [options] <input_file.txt >output_file.bin\n\
		./NtgrBak <mode> [options] -i input_file.txt -o output_file.bin\n\
Modes:\n\
		X	eXtracts the configuration internal NVRAM image to the output file\n\
		D	Decripts without extracting the configuration\n\
		W	Wraps a NVRAM image to the output file with the info supplied by options\n\
Options:\n\
		General:\n\
		-v[erbose]:	Dumps some informations\n\
		-f[orce]:	Avoid checks\n\
		-i[nput]:	Specify the input file path. Otherwise stdin is used\n\
		-o[utput]:	Specify the output file path. Otherwise stdout is used\n\
\n\
		Wrap mode:\n\
		-m[odel]:	Specify the router model. (eg. \"WNDR4500v2\")\n\
		-V[ersion]:	Specify the configuration version. (eg. \"1\")\n"

/* Typdefs */
struct main_opts {
	int (*option_routine)(unsigned char*, int, unsigned char*, int*);
	char * input_file_name;
	char * output_file_name;
	union {
		unsigned int main_sets;
		struct {
			unsigned int main_set_verbose	:1;
			unsigned int main_set_force		:1;
			unsigned int 					:30;
		};
	};
};

struct wrap_opts {
	unsigned int magic;
	unsigned int version;
	union {
		unsigned int wrap_sets;
		struct {
			unsigned int wrap_set_magic		:1;
			unsigned int wrap_set_version	:1;
			unsigned int 					:30;
		};
	};
};

typedef enum {
	wrap_opt_model,
	wrap_opt_version,
} wrap_options;


/* Fuctions signs */
// Routine
int				routine_decrypt				(unsigned char*, int, unsigned char*, int*);
int				routine_extract				(unsigned char*, int, unsigned char*, int*);
int				routine_wrap				(unsigned char*, int, unsigned char*, int*);
void			routine_wrap_set_option		(wrap_options, void *);

// Decryption/Encryption
int				run_codec					(unsigned char*, int, unsigned char*, int*, unsigned char);
void			generate_des_key			(unsigned char*);

// Header - Magic
unsigned int	generate_magic				(unsigned char*);
unsigned int	get_magic					(unsigned char*);
void			set_magic					(unsigned char*, unsigned int);
const char *	get_model					(unsigned int);

// Header - Checksum
unsigned int	calculate_checksum			(unsigned char*, int);
void			generate_checksum			(unsigned char*, int);
int				verify_checksum				(unsigned char*, int);

// Header - Version
unsigned int	get_config_version			(unsigned char*);
void			set_config_version			(unsigned char*, int);

// Header - Length
unsigned int	get_config_length			(unsigned char*);
void			set_config_length			(unsigned char*, int);

// Misc
void			console_output				(char*, ...);


/* Global variables */
unsigned char key_str[8] = KEY_STR;
struct wrap_opts wrap_opt;
struct main_opts main_opt;


/* Funtions definitions */
int main (int argc, char **argv)
{
	unsigned char buffer_input[BUFFER_SIZE];
	unsigned char buffer_output[BUFFER_SIZE];
	int buffer_output_len, buffer_input_len;
	FILE *input_file, *output_file;
	unsigned char i;


	/* Initial setup */
	memset (&main_opt, 0, sizeof (struct main_opts));
	memset (&wrap_opt, 0, sizeof (struct wrap_opts));

	/* Parse the arguments */
	if (argc < 2)
	{
		console_output ("Error: Need more arguments!\n" USAGE);
		return 1;
	}
	switch (argv[1][0])
	{
		case 'D':
			main_opt.option_routine = routine_decrypt;
			break;
		case 'X':
			main_opt.option_routine = routine_extract;
			break;
		case 'W':
			main_opt.option_routine = routine_wrap;
			break;
		default:
			console_output ("Error: Select a mode!\n" USAGE);
			return 1;
	}
	wrap_opt.wrap_sets = 0;
	for (i = 2; i < argc; i++)
	{
		if (argv[i][0] == '-')
		{
			switch (argv[i][1])
			{
			case 'v':
				main_opt.main_set_verbose = 1;
				break;
			case 'f':
				main_opt.main_set_force = 1;
				break;
			case 'i':
				main_opt.input_file_name = argv[++i];
				break;
			case 'o':
				main_opt.output_file_name = argv[++i];
				break;
			case 'm':
				routine_wrap_set_option(wrap_opt_model, argv[++i]);
				break;
			case 'V':
				routine_wrap_set_option(wrap_opt_version, argv[++i]);
				break;
			default:
				console_output ("Error: Unknown option \"%s\".\n" USAGE, argv[i]);
				return 1;
			}
		}
		else
		{
			console_output ("Error: Unknown option \"%s\".\n" USAGE, argv[i]);
			return 1;
		}
	}

	/* Getting the input */
	if (main_opt.input_file_name)
	{
		input_file = fopen (main_opt.input_file_name, "r");
		if (input_file == NULL)
		{
			console_output ("Error opening file: %s\n", main_opt.input_file_name);
			return 1;
		}
	}
	else
		input_file = stdin;

	buffer_input_len = fread (buffer_input, 1, BUFFER_SIZE, input_file);	//TODO: Consider using Memory Mapped IO
	if (!buffer_input_len)
	{
		console_output ("Error reading the input\n");
		return 1;
	}
	if (main_opt.main_set_verbose)
		console_output ("Read %u bytes from input\n", buffer_input_len);



	/* Run the selected routine */
	if (main_opt.option_routine (buffer_input, buffer_input_len, buffer_output, &buffer_output_len))
		return 1;



	/* Writing to output */
	if (main_opt.output_file_name)
	{
		output_file = fopen (main_opt.output_file_name, "w");
		if (output_file == NULL)
		{
			console_output ("Error writing to file: %s\n", main_opt.output_file_name);
			return 1;
		}
	}
	else
		output_file = stdout;

	if (fwrite (buffer_output, 1, buffer_output_len, output_file) != buffer_output_len)		//TODO: Consider using Memory Mapped IO
	{
		console_output ("Error writing the output, it can be incomplete!\n");
		return 1;
	}

	if (main_opt.main_set_verbose)
		console_output ("Done! %u bytes in, %u bytes out\n", buffer_input_len, buffer_output_len);

	return 0;
}

void console_output(char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

int routine_decrypt (unsigned char* buffer_input, int buffer_input_len, unsigned char* buffer_output, int* buffer_output_len)
{
	if (run_codec(buffer_input, buffer_input_len, buffer_output, buffer_output_len, 0))
	{
		console_output ("Error processing the input!\nMake sure the input data size is a multiple of 8 bytes.");
		return 1;
	}

	return 0;
}

int routine_extract (unsigned char* buffer_input, int buffer_input_len, unsigned char* buffer_output, int* buffer_output_len)
{
	unsigned char buffer_dec[BUFFER_SIZE];
	int buffer_dec_len;
	unsigned int payload_size;

	/* First decrypt the data */
	if (routine_decrypt (buffer_input, buffer_input_len, buffer_dec, &buffer_dec_len))
		return 1;

	/* Check for consistency */
	if (main_opt.main_set_force)
	{
		if (main_opt.main_set_verbose) console_output ("Skipping checksum verify.\n");
	}
	else
	{
		if (!verify_checksum(buffer_dec, buffer_dec_len))
		{
			console_output ("Checksum verify failed.\n");
			return 1;
		}

		if (main_opt.main_set_verbose) console_output ("Checksum verify passed.\n");
	}

	/* Print info */
	if (main_opt.main_set_verbose)
	{
		console_output ("Router Model: %s\n", get_model(get_magic(buffer_dec)));
		console_output ("Configuration version: %u\n", get_config_version(buffer_dec));
	}

	/* Check lengths */
	payload_size = get_config_length(buffer_dec) - 0x18;
	if (main_opt.main_set_force)
	{
		if (main_opt.main_set_verbose) console_output ("Skipping length check.\n");
	}
	else
	{
		if (payload_size > MAX_FILE_SIZE)
		{
			console_output ("Configuration NVRAM image is too big. (%u bytes, max: %u bytes)\n", payload_size, MAX_FILE_SIZE);
			return 1;
		}

		if (payload_size != (buffer_input_len - 0x18))
		{
			console_output ("Configuration NVRAM image size is not what expected. Expecting %u bytes instead of %u bytes\n", payload_size, buffer_input_len - 0x18);
			return 1;
		}
	}
	if (main_opt.main_set_verbose) console_output ("Configuration NVRAM image size: %u bytes\n", payload_size);

	/* Check padding */
	//TODO: Check if bytes from 0x10 to 0x18 are 0s


	/* Copy the payload */
	memcpy (buffer_output, buffer_dec + 0x18, payload_size);
	*buffer_output_len = (int)payload_size;

	return 0;
}


void routine_wrap_set_option (wrap_options opt, void * value)
{
	switch (opt)
	{
	case wrap_opt_model:
		wrap_opt.magic = generate_magic((unsigned char *) value);
		wrap_opt.wrap_set_magic = 1;
		break;
	case wrap_opt_version:
		wrap_opt.version = (unsigned int) atoi ((char *) value);
		wrap_opt.wrap_set_version = 1;
		break;
	}
}

int routine_wrap (unsigned char* buffer_input, int buffer_input_len, unsigned char* buffer_output, int* buffer_output_len)
{
	unsigned char buffer_wrap[BUFFER_SIZE];
	int buffer_wrap_len;

	if (wrap_opt.wrap_sets != 0x00000003)
	{
		console_output("Error, provide wrap settings!\n" USAGE);
		return 1;
	}

	/* Clean the output buffer */
	memset (buffer_wrap, 0x00, 0x18);

	/* Dump the payload in output buffer */
	memcpy (buffer_wrap + 0x18, buffer_input, buffer_input_len);

	/* Build the header */
	buffer_wrap_len = buffer_input_len + 0x18;
	set_magic(buffer_wrap, wrap_opt.magic);
	set_config_length(buffer_wrap, buffer_wrap_len);
	set_config_version(buffer_wrap, wrap_opt.version);
	generate_checksum(buffer_wrap, buffer_wrap_len);

	if (main_opt.main_set_verbose)
	{
		console_output ("Generated configuration:\n");
		console_output ("Router Model: %s\n", get_model(get_magic(buffer_wrap)));
		console_output ("Configuration version: %u\n", get_config_version(buffer_wrap));
	}

	/* Encrypting the result */
	if (run_codec (buffer_wrap, buffer_wrap_len, buffer_output, buffer_output_len, 1))
		return 1;

	if (main_opt.main_set_verbose) console_output ("Successfully encoded configuration.\n");

	return 0;
}


int run_codec (unsigned char* in, int in_len, unsigned char* out, int* out_len, unsigned char codec)	//1 = encryption, 0 = decryption
{
	EVP_CIPHER_CTX *ctx;
	unsigned char des_key[8];
	unsigned char iv[8] = {0};
	int dec_len, dec_len_final, out_len_partial, in_blk;

	*out_len = 0;
	out_len_partial = 0;

	/* Check if the source data is a multiple of 64 bit */
	if (in_len % 8)
		return 1;
	in_len /= 8;

	/* Create the cipher context */
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return 1;

	for (in_blk = 0; in_blk < in_len; in_blk++)
	{
		/* Generate the block key */
		generate_des_key(des_key);

		/* Set up the cipher context */
		if (!EVP_CipherInit_ex (ctx, EVP_des_ecb(), NULL, des_key, iv, codec))
			return 1;

		/* Removes padding (need to provide 64bit multiples of source data */
		EVP_CIPHER_CTX_set_padding (ctx, 0);

		/* Feed the source data */
		if (!EVP_CipherUpdate(ctx, out + out_len_partial, &dec_len, in + (in_blk*8), 8))
			return 1;

		out_len_partial += dec_len;

		/* Ending the codec routine */
		if (!EVP_CipherFinal_ex (ctx, out + out_len_partial, &dec_len_final))
			return 1;

		out_len_partial += dec_len_final;
	}

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	*out_len = out_len_partial;

	return 0;
}

void generate_des_key (unsigned char *out_key)
{
	unsigned char key_8b;
	uint64_t key_64b;

	/* Change key_str a bit */
	key_8b = key_str[0];
	key_str[0]+=8;
	if (key_str[0] < key_8b)		//byte #0 overflow
	{
		key_8b = key_str[1]++;
		if (key_str[1] < key_8b)	//byte #1 overflow
			key_str[2]++;
	}

	/* Calculate DES key based on key_str */
	key_64b = htobe64(*((uint64_t *) key_str));

	out_key[0] = (unsigned char) (key_64b >> 56);
	out_key[1] = (unsigned char) (key_64b >> 49);
	out_key[2] = (unsigned char) (key_64b >> 42);
	out_key[3] = (unsigned char) (key_64b >> 35);
	out_key[4] = (unsigned char) (key_64b >> 28);
	out_key[5] = (unsigned char) (key_64b >> 21);
	out_key[6] = (unsigned char) (key_64b >> 14);
	out_key[7] = (unsigned char) (key_64b >> 7);
}

int verify_checksum (unsigned char* buffer, int buffer_len)
{
	return calculate_checksum(buffer, buffer_len) == 0 ? 1 : 0;
}

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

unsigned int calculate_checksum (unsigned char* buffer, int buffer_len)
{
	unsigned int cksum, ret;
	unsigned short * buffer_w;

	if (!buffer || buffer_len <= 0)
		return 0xFFFFFFFF;

	buffer_w = (unsigned short *) buffer;
	if (buffer_len % 2)
		cksum = (unsigned int) *(buffer + (--buffer_len));
	else
		cksum = 0;

	while (buffer_len > 0)
	{
		cksum += (unsigned int) *buffer_w++;
		buffer_len -= 2;
	}

	ret = cksum & 0xFFFF;
	ret += cksum >> 16;
	ret += ret >> 16;
	return (((unsigned int) be16toh (~ret)) & 0xFFFF);
}

unsigned int generate_magic (unsigned char *router_name)
{
	unsigned int magic;
	unsigned char buffer[16+1];	//Accommodate for \0 byte
	unsigned int * buffer_p;

	if (!router_name)
		return 0;

	memset (buffer, 0x00, 16);
	strncpy ((char *)buffer, (char *)router_name, 16);

	buffer_p = (unsigned int *) buffer;
	magic  = *(buffer_p++);
	magic ^= *(buffer_p++);
	magic ^= *(buffer_p++);
	magic ^= *(buffer_p);

	return ((unsigned int) magic);
}

unsigned int get_magic (unsigned char *config_buffer)
{
	if (!config_buffer)
		return 0;

	return (unsigned int) be32toh (*((uint32_t *)(config_buffer)));
}

void set_magic (unsigned char *config_buffer, unsigned int magic)
{
	uint32_t magic_be;

	if (!config_buffer)
		return;

	magic_be = htobe32 ((uint32_t) magic);
	memcpy (config_buffer, &magic_be, 4);
}

const char * get_model (unsigned int magic)
{
	int i;

	enum {
		UNKNOWN = 0,
		WNDR4500v2,

		models
	};

	const char *MODELS_s[] = {
		"unknown",
		"WNDR4500v2"
	};

	const unsigned int MODELS_m[] = {
		0,
		0x62744915
	};

	for (i = 0; i < models; i++)
	{
		if (MODELS_m[i] == magic)
			return MODELS_s[i];
	}

	return MODELS_s[UNKNOWN];
}

unsigned int get_config_length (unsigned char *config_buffer)
{
	if (!config_buffer)
		return 0;

	return (unsigned int) be32toh (*((uint32_t *)(config_buffer +4)));
}

void set_config_length (unsigned char *config_buffer, int len)
{
	uint32_t len_be;

	if (!config_buffer || len < 0)
		return;

	len_be = htobe32 ((uint32_t) len);
	memcpy (config_buffer +4, &len_be, 4);
}

unsigned int get_config_version (unsigned char *config_buffer)
{
	if (!config_buffer)
		return 0;

	return (unsigned int) be32toh (*((uint32_t *)(config_buffer +12)));
}

void set_config_version (unsigned char *config_buffer, int ver)
{
	uint32_t ver_be;

	if (!config_buffer || ver < 0)
		return;

	ver_be = htobe32 ((uint32_t) ver);
	memcpy (config_buffer +12, &ver_be, 4);
}
