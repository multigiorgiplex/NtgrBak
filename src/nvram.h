#ifndef SRC_NVRAM_H_
#define SRC_NVRAM_H_

#include <stdint.h>
#include <stddef.h>

#define NVRAM_IMAGE_SIZE_MAX	0x10000

#define NVRAM_INDEX_MAGIC	0	//Bytes 0-3
#define NVRAM_INDEX_LENGTH	4	//Bytes 4-7
#define NVRAM_INDEX_CRC		8	//Bytes 8
#define NVRAM_INDEX_FIELD1	9	//Bytes 9
#define NVRAM_INDEX_FIELD2	10	//Bytes 10-19
#define NVRAM_INDEX_DATA	20

#define NVRAM_SIZE_MAGIC	4
#define NVRAM_SIZE_LENGTH	4
#define NVRAM_SIZE_CRC		1
#define NVRAM_SIZE_FIELD1	1
#define NVRAM_SIZE_FIELD2	10
#define NVRAM_SIZE_DATA_MAX	(NVRAM_IMAGE_SIZE_MAX-NVRAM_INDEX_DATA)

#define NVRAM_CONTENT_MAGIC		0x464C5348	//"FLSH"
#define NVRAM_CONTENT_FIELD1	0x01
#define NVRAM_CONTENT_FIELD2	0x00
#define NVRAM_CONTENT_PADDING	0xFF

#define NVRAM_CRC_START		0xFF

uint32_t	get_magic		(uint8_t*);
void		set_magic		(uint8_t*, uint32_t);
uint32_t	get_length		(uint8_t*);
void		set_length		(uint8_t*, uint32_t);
uint8_t		get_crc			(uint8_t*);
void		set_crc			(uint8_t*, uint8_t);
uint8_t		calculate_crc	(uint8_t*);
void		set_field1		(uint8_t*);
void		set_field2		(uint8_t*);


#endif /* SRC_NVRAM_H_ */
