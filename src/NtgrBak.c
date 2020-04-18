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
#include <stdarg.h>
#include "config.h"
#include "crypt.h"

/* Defines */
#define BUFFER_SIZE		(0x20000)
#define MAX_FILE_SIZE	BUFFER_SIZE

#define USAGE	\
"Usage:\n\
		./NtgrBak <mode> [options] <input_file.bin >output_file.bin\n\
		./NtgrBak <mode> [options] -i input_file.bin -o output_file.bin\n\
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

//TODO: Get wrap model based on configuration (system_name key)

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

// Misc
void			console_output				(char*, ...);


/* Global variables */
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
	unsigned int payload_size, magic;

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
		magic = get_magic(buffer_dec);
		console_output ("Router Model: %s\n", get_model(magic));
		console_output ("Configuration version: %u\n", get_config_version(buffer_dec));
		console_output ("Configuration magic: 0x%08x\n", magic);
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
