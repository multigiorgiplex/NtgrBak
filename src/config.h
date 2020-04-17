#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

//TODO: Use defines for configuration field offsets

/* Checksum functions */
unsigned int	calculate_checksum		(unsigned char*, int);
void			generate_checksum		(unsigned char*, int);
int				verify_checksum			(unsigned char*, int);

/* Magic functions */
unsigned int	generate_magic				(unsigned char*);
unsigned int	get_magic					(unsigned char*);
void			set_magic					(unsigned char*, unsigned int);
const char *	get_model					(unsigned int);

/* Version functions */
unsigned int	get_config_version			(unsigned char*);
void			set_config_version			(unsigned char*, int);

/* Lenght functions */
unsigned int	get_config_length			(unsigned char*);
void			set_config_length			(unsigned char*, int);

#endif /* SRC_CONFIG_H_ */
