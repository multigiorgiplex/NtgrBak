#ifndef SRC_CRYPT_H_
#define SRC_CRYPT_H_

#define KEY_STR			"NtgrBak"

int				run_codec			(unsigned char*, int, unsigned char*, int*, unsigned char);
void			generate_des_key	(unsigned char*);

#endif /* SRC_CRYPT_H_ */
