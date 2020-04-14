# NtgrBak
Netgear configuration backup decrypter and encrypter
## Description
NtgrBak is a small utility that can decrypt and encrypt Netgear configuration backup files.

The final goal is being able to manually edit and reupload the router configuration. **(CAREFUL! Not tested yet!)**

The decryption process has been successfully tested with this Netgear Routers models:
- WNDR4500v2

The encryption process has been successfully tested with this Netgear Routers models:
- (none)

## Building
In order to build the utility, OpenSSL's libcrypto headers must be included in the build
```
$ gcc -lcrypto -o NtgrBak NtgrBak.c
```
## Running
The input data and the output result is provided to the utility via console redirection.
```
Usage:
	./NtgrBak [options] <input_file.bin >output_file.bin
Options:
	-e[ncrypt]: Encrypts the input data
	-d[ecrypt]: Decrypts the input data
	-v[erbose]: Dump some informations
```
The output result can be examined easily with
```
$ xxd output_file.bin | less
```
or
```
$ strings output_file.bin | less
```
## Thanks
Thanks to Roberto Paleari's early work (http://roberto.greyhats.it/) (https://www.exploit-db.com/exploits/24916)
