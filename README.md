# REHelper
This tool should help you look for initial artifacts that you can then hunt down in your disassembler of choice.

Sample output:

```
+Basic Information----------------------------------------------------------------------+
| Filename:   | readelf.exe                                                             |
+-------------+-------------------------------------------------------------------------+
| Filetype:   | PE IMAGE_FILE_MACHINE_I386                                              |
| Subsystem:  | IMAGE_SUBSYSTEM_WINDOWS_CUI                                             |
| SHA256:     | 687370a88d273a172004c9ebc2ca0e8994cb6e7107b8ff5b3bebfede4037d352        |
| VT link:    | https://tinyurl.com/yxs7q4co                                            |
| Symbols:    | No                                                                      |
| Entropy:    | 4.506409298318734                                                       |
| Sections:   | .text (0x5ba00) .data (0x1400) .rdata (0x32200) /4 (0x6800) .bss (0x0)  |
| (with size) | .idata (0xe00) .CRT (0x200) .tls (0x200)                                |
| Entrypoint: | 0x12e0                                                                  |
+-------------+-------------------------------------------------------------------------+

+---------------------+------------------------------------------------------+
| Domains:            | 0@.bs ar.pf sourceware.org/bugzilla/> gnu.link       |
|                     | gnu.link gnu.link Sym.Va                             |
|                     | Sym.Va Sym.Va v8-M.ba                                |
|                     | v8-M.ma ar.bs ar.bs                                  |
|                     | ar.pf ar.lc fs.ba                                    |
|                     | gs.ba                                                |
| Ips:                |                                                      |
| Paths:              | \3S03K4 \3C03S4 /300H /32/64-bit                     |
|                     | /file //www /binutils-2                              |
|                     | /binutils/readelf /soft /Value                       |
|                     | /VR4181 /mingw/share/locale /FP-D16                  |
|                     | /parse /binutils-2 /binutils/elfcomm                 |
|                     | /SYM64/ //TRANSLIT /mingw/share/locale               |
|                     | \Desktop\ResourceLocale /locale /mingw/share/locale  |
|                     | /0123456789 /0123456789 /lengths                     |
|                     | /length /length                                      |
+---------------------+------------------------------------------------------+
```

## How to install
```bash
git clone https://github.com/TheDuchy/REHelper
cd REHelper
python3 -m pip install -r requirements.txt
git clone https://github.com/Yara-Rules/rules
```

You can then launch the `main.py` script:

```
$ python3 main.py --help
usage: main.py [-h] [-v] -f filename

REHelper is an utility for initial binary analysis.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose output
  -f filename, --file filename
                        File to process
```
