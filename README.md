## Description
This script can be used to encrypt text to md5, and also try to decrypt md5 hash to text using https://md5decrypt.net/en/

## How To Use
Execute the Python script `hashmd.py` with the `-h` option, to open the script manual.

- Simple Use:

  `python hashmd.py -e 'Hello There'`
  
  Output:
  `Hash: '32b170d923b654360f351267bf440045'`
  
  `python hashmd.py -d 32b170d923b654360f351267bf440045`
  
  Output:
  
  `Trying to crack "32b170d923b654360f351267bf440045"... Please wait`
  
  `Cracked: Hello There`
  
  # How To Setup As a Command In Linux Machines
  1. Download the file `hashmd.py`.
  2. Copy the file to the directory `/usr/bin`.
  3. Rename the file to `hashmd`.
  4. Make the file executable.
  5. Now test the command by typing `hashmd --help` in the terminal emulator.
