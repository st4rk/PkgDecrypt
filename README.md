# PkgDecrypt
Decrypts and extracts PS Vita PKG files.

# Dependencies
* zlib

# Features
* Fully supports: PSV titles, PSV updates, PSV DLCs (through /bgdl/ method) and PSM titles, 
* 1:1 file extraction,
* Support for klicensee and zRIF keys for work.bin 1:1 recreation,
* Can either extract PKG or decrypt it into PKGS file,
* Different output hierarchies can be chosen for easy transfer to VITA.

# Usage
```
pkg_dec [--make-dirs=id|ux] [--license=<key>] [--raw] filename.pkg [output_directory]
	--make-dirs=id|ux	Use output directory to create special hierarchy,
				id	places all output in the <CONTENTID> folder
				ux	places all output in ux0-style hierarchy
	--license=<key>		Provide key to use as base for work.bin (*.rif) file creation.
				Two formats accepted - klicensee key (deprecated) and zRIF (recommended)
				zRIF could be made by NoNpDrm fake RIFs using make_key
	--queue-length=<int>	Maximum length of install queue for DLCs to generate, default is 32
	--split			Creates new directory to continue installation queue if limit reached
	--raw			Output fully decrypted PKG instead of unpacking it, exclusive
	<filename.pkg>		Input PKG file
	<output_directory>	Directory where all files will be places. Current directory by default.
```
To create new, zRIF license, use the make_key.

```
make_key [--force] license_file...
	--force		Use to skip the input file validation (and force old behavior)

```


# Requirements
* Windows x64 or x86 (for precompiled builds) or other supported OS,
* VC++ Redist 2017 installed (not needed if using CMake),
* a)Vita with 3.60 henkaku, PKG file and license key[klicensee(deprecated) or zRIF(recommended)] for Vita installation,
* b)PKG file for extraction purposes only.

# Compile

```
mkdir build && cd build && cmake .. && make
sudo make install # For Linux and Mac
```

# Changelog:
### 1.3.2-1
* make_key now validates input files and refuses to create key if it fails. New flag --force could be used if old behavior desired,
* QoL only release.
### 1.3.2
* Added `--queue-length` parameter to control maximum install queue length for DLCs.
* PSM support bugfix.
### 1.3.1
* Added `pm.dat` generator (required for PSM PKGs).
### 1.3.0
* Corrected directory layout for PSM in "ux" mode,
* Updated make_key to support PSM RIFs.
### 1.2.3
* Fixed bug with macOS build, thanks to @kkaazzee,
* Fixed bug in sfo parser related to string-type fields.
### 1.2.2
* Improvements in DLC unpacking mode,
* Now using command-line tools for windows build,
* Since this version x86 precompiled builds are also available.
### 1.2.1
* Corrects unpacking folder for the game patches in `ux` mode,
* Fixed bug that occured if there was more than 10 DLCs extracted in `/bgdl/t/` directory
### 1.2.0
* Added generation of `PDB` files for DLC package installation.
### 1.1.3
* Fixed bug which prevented creation of `sce_sys/package` directory contents for some PKGs.
* Changed directory layout of `ux` mode for DLC packages.
### 1.1.2
* Fixed bug with PSM PKG unpacking.
### 1.1.1
* Bug fixes.
### 1.1.0
New features:
- Support of generating fake RIFs from hex-encoded klicensee and zRIFs
- Unpacking files using ux0 hierarchy emulation
- Automatic recognition of DLC and GD packages (using pkg_info fields)
- make_key program to pack fake RIFs into zRIF format

Major refactoring of code:
- Split code over few modules, for example, key encoding and decoding done using keyflate.c
- Few utility functions (mkdirs and set of pkg_* functions mirroring stdio with transparent decryption)
- Improved code readability with structs defining various structures in pkg file

Bugfixes:
- Generated head.bin now have proper file size,
- Attempted to fix sku_flag value using drm_type of package (different solution from temp.bin),
- Other bugfixes.
### 1.0.3
* Added full support for license keys, now if you use license key it will generate fully working work.bin file,
* Added check for license, if license is not used, file work.bin will not be generated at all,
* All *.bin files are now generated in proper location `output_folder/sce_sys/packages/*.bin`
### 1.0.2
* Fixed Windows extraction, now it extract 1:1 files.
### 1.0.1
* St4rk's support for *.bin files
### 1.0.0
* St4rk Initial code

# ToDo list:
* Found out exactly how body.bin and stat.bin created,
* Add support for VitaShell 1.76 DLC promotion/refresh (instead of `/bgdl/` method), 
* Add PSX/PSP contents support to use through adrenaline. 

# Thanks
St4rkDev for his wonderful code,

TheRadziu for PR, team management and testing,

Atrexia for supporting us with this idea, 

FatalErrorX for providing us with all files necessary for debug and PoC testing,

Brandonheat8 for the icon,

kkaazzee for help with OSX support,

devnoname120 for help with PSM support.
