#include <endian.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "crypt.h"


/* Decrypts or Encrypts a buffer
 * in:			The input buffer
 * in_len:		The input buffer length
 * out:			The output buffer
 * out_len:		The output buffer length
 * codec:		0: Decryption, 1: Encryption
 * NOTE: This function is based on Roberto Paleari's early work (http://roberto.greyhats.it/) (https://www.exploit-db.com/exploits/24916)
 */
int run_codec (unsigned char* in, int in_len, unsigned char* out, int* out_len, unsigned char codec)
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


/* Generate the DES Key needed by run_codec()
 * out_key:		Output key buffer
 * NOTE: This function is based on Roberto Paleari's early work (http://roberto.greyhats.it/) (https://www.exploit-db.com/exploits/24916)
 */
void generate_des_key (unsigned char *out_key)
{
	static unsigned char key_str[8] = KEY_STR;
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
