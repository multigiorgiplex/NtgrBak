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
		./NtgrBak <mode> [options] <input_file.txt >output_file.bin
		./NtgrBak <mode> [options] -i input_file.txt -o output_file.bin
Modes:
		X	eXtracts the configuration internal NVRAM image to the output file
		D	Decripts without extracting the configuration
		W	Wraps a NVRAM image to the output file with the info supplied by options
Options:
		General:
		-v[erbose]:	Dumps some informations
		-f[orce]:	Avoid checks
		-i[nput]:	Specify the input file path. Otherwise stdin is used
		-o[utput]:	Specify the output file path. Otherwise stdout is used

		Wrap mode:
		-m[odel]:	Specify the router model. (eg. "WNDR4500v2")
		-V[ersion]:	Specify the configuration version. (eg. "1")

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
