# NtgrBak
Netgear configuration backup utilities for manual edit
## Description
NtgrBak is a little project that aims to being able to manually edit and reupload the router configuration.
It comes with two separate small utilities:
- NtgrBak
- NVEx

*NtgrBak* can import and export the router internal NVRAM image to and from the configuration backup file.
*NVEx* can import and export editable text file to and from the router internal NVRAM image.

The extraction process has been successfully tested with this Netgear Routers models:
- WNDR4500v2

The wrap process has been successfully tested with this Netgear Routers models:
- WNDR4500v2

## Building
In order to build this utility, use make. OpenSSL's libcrypto headers must be installed in the system.
```
$ make
```
## Running
### Workflow example
The first thing to do is to extract the RAW NVRAM image from the router configuration file.
```
$ ./NtgrBak X -i src.cfg -o src.cfg.nvram
```
Then the text editable string file must be extracted from the RAW NVRAM image.
```
$ ./NVEx X -i src.cfg.nvram -o src.cfg.str
```
At this point the output file `src.cfg.str` can be easily edited. **CAREFUL! This is an easy way to brick your router!**
To reverse the workflow, the first thing to do is generate a RAW NVRAM image from the text file.
```
$ ./NVEx W -i mod.cfg.str -o mod.cfg.nvram
```
**NOTE:** The input file `mod.cfg.str` must be ASCII encoded with new-lines ('\n') only.
The last operation to do is to generate an uploadable router configuration file.
```
$ ./NtgrBak W -m WNDR4500v2 -V 1 -i mod.cfg.nvram -o mod.cfg
```
The options `-m WNDR4500v2` and `-V 1` are mandatory because the router model (`-m`) and configuration version (`-V`) are needed to generate the configuration file.
The configuration version is usually "1" but can be determined by looking at the output info of the `src.cfg` unwrap procedure (via running *NtgrBak* with the `-v` option).
The router model can be easily guessed. To be sure compare the "Configuration magic" value (obtained by running *NtgrBak* with the `-v` option) between the original `src.cgf` file and the `mod.cfg`. The magic number must be the same.
The output file `mod.cfg` can now be uploaded to the router via it's web interface.
### Fast approach
To speed the operation the intermediate RAW NVRAM image file can be directly passed to the sourcing utility via output redirection.
```
$ ./NtgrBak X -i src.cfg | ./NVEx X -o src.cfg.str
```
```
$ ./NVEx W -i mod.cfg.str | ./NtgrBak W -o mod.cfg
```
## Thanks
Thanks to Roberto Paleari's early work (http://roberto.greyhats.it/) (https://www.exploit-db.com/exploits/24916)
