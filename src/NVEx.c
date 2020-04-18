/*
 ============================================================================
 Name        : NVEx.c
 Author      : Marco Giorgi (multigiorgiplex)
 Version     :
 Copyright   : See Apache License 2.0
 Description : Netgear NVRAM extractor
 ============================================================================
 */

//TODO: Assert for LE systems

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "nvram.h"

/* Defines */
#define BUFFER_SIZE		(0x20000)
#define MAX_FILE_SIZE	BUFFER_SIZE

#define USAGE	\
"Usage:\n\
		./NVEx <mode> [options] <input_file >output_file\n\
		./NVEx <mode> [options] -i input_file -o output_file\n\
Modes:\n\
		X	eXtract the raw input file to a string file. Editable by all text editors.\n\
		W	Wrap the string input file to a raw NVRAM image.\n\
Options:\n\
		General:\n\
		-v[erbose]:	Dumps some informations\n\
		-f[orce]:	Avoid checks\n\
		-i[nput]:	Specify the input file path. Otherwise stdin is used\n\
		-o[utput]:	Specify the output file path. Otherwise stdout is used\n"

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

/* Fuctions signs */
// Routine
int				routine_extract				(unsigned char*, int, unsigned char*, int*);
int				routine_wrap				(unsigned char*, int, unsigned char*, int*);

// Misc
void			console_output				(char*, ...);


/* Global variables */
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

	/* Parse the arguments */
	if (argc < 2)
	{
		console_output ("Error: Need more arguments!\n" USAGE);
		return 1;
	}
	switch (argv[1][0])
	{
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


int routine_extract (unsigned char* buffer_input, int buffer_input_len, unsigned char* buffer_output, int* buffer_output_len)
{
	uint32_t magic;
	uint32_t length;
	uint8_t crc, crc_calc;
	int i, j;

	/* Acquire infos */
	magic = get_magic(buffer_input);
	length = get_length(buffer_input);
	crc = get_crc(buffer_input);

	/* Magic check */
	if (main_opt.main_set_verbose) console_output ("NVRAM Magic: %08x\n", magic);
	if (main_opt.main_set_force)
	{
		if (main_opt.main_set_verbose) console_output ("Skipping magic check.\n");
	}
	else
	{
		if (magic != NVRAM_CONTENT_MAGIC)
		{
			console_output ("Magic check failed!\n");
			return 1;
		}
		if (main_opt.main_set_verbose) console_output ("Magic check passed.\n");
	}

	/* Length check */
	if (main_opt.main_set_verbose) console_output ("NVRAM Length: %u bytes\n", length);
	if (length > NVRAM_SIZE_DATA_MAX)
	{
		if (main_opt.main_set_force)
		{
			length = NVRAM_SIZE_DATA_MAX;
			console_output ("Data size is too big! Output will be truncated to %u bytes.\n", length);
		}
		else
		{
			console_output ("Data size is too big!\n");
			return 1;
		}
	}

	/* CRC8 check */
	if (main_opt.main_set_verbose) console_output ("NVRAM CRC8: %02x\n", crc);
	if (main_opt.main_set_force)
	{
		if (main_opt.main_set_verbose) console_output ("Skipping CRC8 check.\n");
	}
	else
	{
		crc_calc = calculate_crc(buffer_input);
		if (main_opt.main_set_verbose) console_output ("NVRAM calculated CRC8: %02x\n", crc_calc);
		if (crc != crc_calc)
		{
			console_output ("CRC8 check failed!\n");
			return 1;
		}
		if (main_opt.main_set_verbose) console_output ("CRC8 check passed.\n");
	}

	/* Copy the input buffer data to the output swapping null bytes with newlines */
	j = 0;
	for (i = NVRAM_INDEX_DATA; i < length; i++)
	{
		if (buffer_input[i] == '\0')
		{
			if (buffer_output[j-1] != '\n')	//Skip multiple \0\0 (at the end)
				buffer_output[j++] = '\n';
		}
		else
			buffer_output[j++] = buffer_input[i];
	}
	*buffer_output_len = j;

	return 0;
}

int routine_wrap (unsigned char* buffer_input, int buffer_input_len, unsigned char* buffer_output, int* buffer_output_len)
{
	int i, j;

	/* Copy the input data to the buffer swapping new lines with null bytes */
	j = NVRAM_INDEX_DATA;
	for (i = 0; i < buffer_input_len; i++)
	{
		if (buffer_input[i] == '\n')
			buffer_output[j++] = '\0';
		else
			buffer_output[j++] = buffer_input[i];
	}

	/* Even the output data to multiple of 4 bytes */
	while (j % 4)
		buffer_output[j++] = '\0';

	/* Setup the header */
	set_magic(buffer_output, NVRAM_CONTENT_MAGIC);
	set_length(buffer_output, j);
	set_field1(buffer_output);
	set_field2(buffer_output);
	set_crc(buffer_output, calculate_crc(buffer_output));

	/* Add the padding */
	while (j < NVRAM_IMAGE_SIZE_MAX)
		buffer_output[j++] = NVRAM_CONTENT_PADDING;

	*buffer_output_len = NVRAM_IMAGE_SIZE_MAX;
	return 0;
}
