/*
 ============================================================================
 Name        : NtgrBak.c
 Author      : Marco Giorgi (multigiorgiplex), heavily based on Roberto Paleari's early work (http://roberto.greyhats.it/) (https://www.exploit-db.com/exploits/24916)
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

#define BUFFER_SIZE		(0x20000)

#define	USAGE			"Usage:\n\t%s [options] <input_file.bin >output_file.bin\nOptions:\n\t-e[ncrypt]: Encrypts the input data\n\t-d[ecrypt]: Decrypts the input data\n\t-v[erbose]: Dump some informations\n"
#define KEY_STR			"NtgrBak"


int run_codec (unsigned char*, int, unsigned char*, int*);
void generate_des_key (unsigned char *);


unsigned char key_str[8] = KEY_STR;
unsigned char verbose = 0;
unsigned char codec = 0;	//1 = encryption, 0 = decryption (default)


int main (int argc, char **argv)
{
	unsigned char buffer_input[BUFFER_SIZE];
	unsigned char buffer_output[BUFFER_SIZE];
	int buffer_output_len, buffer_input_len;
	unsigned char i;


	for (i = 1; i < argc; i++)
	{
		if (argv[i][0] == '-')
		{
			switch (argv[i][1])
			{
			case 'v':
				verbose = 1;
				break;
			case 'e':
				codec = 1;
				break;
			case 'd':
				codec = 0;
				break;
			default:
				fprintf (stderr, "Error: Unknown option %s.\n" USAGE, argv[i], argv[0]);
				return 1;
			}
		}
		else
		{
			fprintf (stderr, "Error: Unknown option %s.\n" USAGE, argv[i], argv[0]);
			return 1;
		}
	}

	buffer_input_len = fread (buffer_input, 1, BUFFER_SIZE, stdin);
	if (!buffer_input_len)
	{
		fprintf (stderr, "Error reading the input\n");
		return 1;
	}

	if (verbose)
		fprintf (stderr, "Read %u bytes from stdin\n", buffer_input_len);

	if (run_codec(buffer_input, buffer_input_len, buffer_output, &buffer_output_len))
	{
		fprintf (stderr, "Error processing the input!\nMake sure the input data size is a multiple of 8\n");
		return 1;
	}

	if (fwrite (buffer_output, 1, buffer_output_len, stdout) != buffer_output_len)
	{
		fprintf (stderr, "Error writing the output, it can be incomplete!\n");
		return 1;
	}

	if (verbose)
		fprintf (stderr, "Done!\n%u bytes in, %u bytes out\n", buffer_input_len, buffer_output_len);

	return 0;
}

int run_codec (unsigned char* in, int in_len, unsigned char* out, int* out_len)
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
		if (verbose)
			fprintf (stderr, "block %u/%u\t\tusing DES key: %02x %02x %02x %02x %02x %02x %02x %02x\n", in_blk+1, in_len, des_key[0], des_key[1], des_key[2], des_key[3], des_key[4], des_key[5], des_key[6], des_key[7]);

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

