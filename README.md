# dump2exe
Extract Win executables from dumps, display some basic information about them.
*Why not use libpe ? Mostly for education purpose :) !*

## Compilation
1. Install the following (apt-based): `apt install libssl-dev`
2. Compile : `make`
3. Run `./bin/dump2exe --help`  

## Usage
```
./bin/dump2exe mem.dmp                  // Display info 
./bin/dump2exe -e mem.dmp               // Extract and display info
./bin/dump2exe -e -o 123456 mem.dmp     // Display info and extract bin at offset 123456
```
