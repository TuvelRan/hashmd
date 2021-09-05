## Description
This script is used to encrypt or decrypt the following types of hashes:
- Hex
- Binary
- MD5
- SHA1
- SHA256
- SHA384
- SHA512
- Base64

**makefile (the command installer) will come soon.**

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

## Guide:
Download `hashmd.py` Using `wget` or by downloading the repository.

```
wget https://github.com/TuvelRan/hashmd/blob/main/hashmd.py
```
Copy the file to `/usr/bin` as root.
```
sudo cp hashmd.py /usr/bin/hashmd.py
```
Rename the file to `hashmd` as root.
```
sudo mv /usr/bin/hashmd.py /usr/bin/hashmd
```
Make the file executable as root.
```
sudo chmod +x /usr/bin/hashmd
```
Test the command. If it works, Enjoy!
If you get `Bad Interpreter Error`, use the tool `dos2unix` to convert the file from dos to unix. It will remove the ^M from the first line and the error will be solved.
To install `dos2unix`:
```
sudo apt install dos2unix
```

Enjoy (-:
