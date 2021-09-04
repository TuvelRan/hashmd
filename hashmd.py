#!/usr/bin/python
import requests
import sys
import hashlib
import base64
import binascii

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def decrypt_md5(hash_to_crack):
    print(f'\n{bcolors.HEADER}MD5: {hash_to_crack}{bcolors.ENDC}')
    post_data = {
        'hash': hash_to_crack,
        'decrypt': 'Decrypt'
    }
    r = requests.post('https://md5decrypt.net/en/', data=post_data)
    response = r.text
    results = response.split(f'</span><br>{hash_to_crack} : <b>')
    try:
        value = results[1]
        value = value[0:str(value).index('</b>')]
        print(f"{bcolors.OKGREEN}Found: '{value}'{bcolors.ENDC}\n")
    except:
        print(f'{bcolors.FAIL}Sorry, but this hash is not in our database.{bcolors.ENDC}\n')

def encrypt_md5(text):
    print(f"\n{bcolors.HEADER}Text: {text}{bcolors.ENDC}\n{bcolors.WARNING}MD5:{bcolors.ENDC} {bcolors.OKGREEN}'{hashlib.md5(text.encode()).hexdigest()}'{bcolors.ENDC}\n")

def decrypt_sha256(hash_to_crack):
    print(f'\n{bcolors.HEADER}SHA256: {hash_to_crack}{bcolors.ENDC}')
    post_data = {
        'hash': hash_to_crack,
        'decrypt': 'Decrypt'
    }
    r = requests.post('https://md5decrypt.net/en/Sha256/', data=post_data)
    response = r.text
    results = response.split(f'</span><br>{hash_to_crack} : <b>')
    try:
        value = results[1]
        value = value[0:str(value).index('</b>')]
        print(f"{bcolors.OKGREEN}Found: '{value}'{bcolors.ENDC}\n")
    except:
        print(f'{bcolors.FAIL}Sorry, but this hash is not in our database.{bcolors.ENDC}\n')

def encrypt_sha256(text):
    print(f"\n{bcolors.HEADER}Text: '{text}'{bcolors.ENDC}\n{bcolors.WARNING}SHA256:{bcolors.ENDC} {bcolors.OKGREEN}'{hashlib.sha256(text.encode()).hexdigest()}'{bcolors.ENDC}\n")

def encrypt_base64(text):
    print(f"\n{bcolors.HEADER}Text: '{text}'{bcolors.ENDC}\n{bcolors.WARNING}BASE64:{bcolors.ENDC} {bcolors.OKGREEN} '{base64.b64encode(text.encode()).decode()}'{bcolors.ENDC}\n")

def decrypt_base64(hash_to_crack):
    print(f"\n{bcolors.HEADER}BASE64: '{hash_to_crack}'{bcolors.ENDC}\n{bcolors.WARNING}Text:{bcolors.ENDC} {bcolors.OKGREEN}'{base64.b64decode(hash_to_crack.encode()).decode()}'{bcolors.ENDC}\n")

def encrypt_sha1(text):
    print(f"\n{bcolors.HEADER}Text: '{text}'{bcolors.ENDC}\n{bcolors.WARNING}SHA1:{bcolors.ENDC} {bcolors.OKGREEN} '{hashlib.sha1(text.encode()).hexdigest()}'{bcolors.ENDC}\n")

def decrypt_sha1(hash_to_crack):
    print(f'\n{bcolors.HEADER}SHA1: {hash_to_crack}{bcolors.ENDC}')
    post_data = {
        'hash': hash_to_crack,
        'decrypt': 'Decrypt'
    }
    r = requests.post('https://md5decrypt.net/en/Sha1/', data=post_data)
    response = r.text
    results = response.split(f'</span><br>{hash_to_crack} : <b>')
    try:
        value = results[1]
        value = value[0:str(value).index('</b>')]
        print(f"{bcolors.OKGREEN}Found: '{value}'{bcolors.ENDC}\n")
    except:
        print(f'{bcolors.FAIL}Sorry, but this hash is not in our database.{bcolors.ENDC}\n')

def encrypt_sha384(text):
    print(f"\n{bcolors.HEADER}Text: '{text}'{bcolors.ENDC}\n{bcolors.WARNING}SHA384:{bcolors.ENDC}{bcolors.OKGREEN} '{hashlib.sha384(text.encode()).hexdigest()}'{bcolors.ENDC}\n")

def decrypt_sha384(hash_to_crack):
    print(f'\n{bcolors.HEADER}SHA384: {hash_to_crack}{bcolors.ENDC}')
    post_data = {
        'hash': hash_to_crack,
        'decrypt': 'Decrypt'
    }
    r = requests.post('https://md5decrypt.net/en/Sha384/', data=post_data)
    response = r.text
    results = response.split(f'</span><br>{hash_to_crack} : <b>')
    try:
        value = results[1]
        value = value[0:str(value).index('</b>')]
        print(f"{bcolors.OKGREEN}Found: '{value}'{bcolors.ENDC}\n")
    except:
        print(f'{bcolors.FAIL}Sorry, but this hash is not in our database.{bcolors.ENDC}\n')

def encrypt_sha512(text):
    print(f"\n{bcolors.HEADER}Text: '{text}'{bcolors.ENDC}\n{bcolors.WARNING}SHA512:{bcolors.ENDC} {bcolors.OKGREEN}'{hashlib.sha512(text.encode()).hexdigest()}'{bcolors.ENDC}\n")

def decrypt_sha512(hash_to_crack):
    print(f'\n{bcolors.HEADER}SHA512: {hash_to_crack}{bcolors.ENDC}')
    post_data = {
        'hash': hash_to_crack,
        'decrypt': 'Decrypt'
    }
    r = requests.post('https://md5decrypt.net/en/Sha512/', data=post_data)
    response = r.text
    results = response.split(f'</span><br>{hash_to_crack} : <b>')
    try:
        value = results[1]
        value = value[0:str(value).index('</b>')]
        print(f"{bcolors.OKGREEN}Found: '{value}'{bcolors.ENDC}\n")
    except:
        print(f'{bcolors.FAIL}Sorry, but this hash is not in our database.{bcolors.ENDC}\n')

def encrypt_hex(text):
    print(f"\n{bcolors.HEADER}Text: '{text}'{bcolors.ENDC}\n{bcolors.WARNING}Hex:{bcolors.ENDC} {bcolors.OKGREEN}'{str(text).encode().hex()}'{bcolors.ENDC}\n")

def decrypt_hex(text):
    try:
        print(f"\n{bcolors.HEADER}Hex: '{text}'{bcolors.ENDC}\n{bcolors.WARNING}Text:{bcolors.ENDC} {bcolors.OKGREEN}'{bytearray.fromhex(text).decode()}'{bcolors.ENDC}\n")
    except:
        print(f"\n{bcolors.HEADER}Hex: '{text}'{bcolors.ENDC}\n{bcolors.WARNING}Text:{bcolors.ENDC} {bcolors.FAIL}'String Contains Bad Symbols'{bcolors.ENDC}\n")

def encrypt_binary(text):
    print(f"\n{bcolors.HEADER}Text: '{text}'{bcolors.ENDC}\n{bcolors.WARNING}Binary:{bcolors.ENDC} {bcolors.OKGREEN}'{bin(int.from_bytes(text.encode(), 'big'))[2:]}'{bcolors.ENDC}\n")

def bin_to_ascii(string):
    if str(string).find('0b') == -1:
        string = f'0b{string}'
    n = int(string, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode()

def reverse(string):
    return string[::-1]

def decrypt_binary(text):
    print(f"\n{bcolors.HEADER}Binary: '{text}'{bcolors.ENDC}\n{bcolors.WARNING}Text:{bcolors.ENDC} {bcolors.OKGREEN}'{bin_to_ascii(text)}'{bcolors.ENDC}\n")

def print_help():
    help_msg = f'''
    {bcolors.HEADER}hashmd is used for encrypting and decrypting hashes.{bcolors.ENDC}\n
    command: hashmd {bcolors.OKBLUE}<type>{bcolors.ENDC} {bcolors.OKCYAN}<option>{bcolors.ENDC} {bcolors.OKGREEN}<text/hash>{bcolors.ENDC}\n
    {bcolors.OKBLUE}Types:{bcolors.ENDC}
    \t--auto {bcolors.FAIL}(N/A Currently){bcolors.ENDC} the script will identify and decrypt the given hash
    \t\talias: -a

    \t--hex encrypt/decrypt hex

    \t--binary encrypt/decrypt binary

    \t--md5 encrypt/decrypt md5

    \t--sha256 encrypt/decrypt sha256

    \t--sha1 encrypt/decrypt sha1

    \t--sha384 encrypt/decrypt sha384

    \t--sha512 encrypt/decrypt sha512

    \t--base64 encrypt/decrypt base64

    {bcolors.OKCYAN}Options:{bcolors.ENDC}
    \t-e Encrypt a text
    \t\talias: --encrypt

    \t-d Decrypt a hash
    \t\talias: --decrypt

    \t-h Opens this guide
    \t\talias: --help\n
    
    {bcolors.WARNING}Created By Tuvel Ran{bcolors.ENDC}
    Source: https://github.com/TuvelRan/hashmd
    '''
    print(help_msg)


def e_or_d(action):
    if action == '--encrypt' or action == '-e':
        return 'e'
    elif action == '--decrypt' or action == '-d':
        return 'd'
    return action


def handle_args(args):
    flag = args[0]

    if not args:
        return

    if len(args) > 2:
        action = args[1]
    else:
        if args[0] == '--help' or args[0] == '-h':
            print_help()
            return
        print(f'{bcolors.FAIL}Please provide the full credentials for the command.{bcolors.ENDC}\nCheck out --help for directions.')
        return

    if flag == '--md5':
        if e_or_d(action) == 'e':
            encrypt_md5(args[2])
        else:
            decrypt_md5(args[2])
    elif flag == '--sha256':
        if e_or_d(action) == 'e':
            encrypt_sha256(args[2])
        else:
            decrypt_sha256(args[2])
    elif flag == '--base64':
        if e_or_d(action) == 'e':
            encrypt_base64(args[2])
        else:
            decrypt_base64(args[2])
    elif flag == '--sha1':
        if e_or_d(action) == 'e':
            encrypt_sha1(args[2])
        else:
            decrypt_sha1(args[2])
    elif flag == '--sha384':
        if e_or_d(action) == 'e':
            encrypt_sha384(args[2])
        else:
            decrypt_sha384(args[2])
    elif flag == '--sha512':
        if e_or_d(action) == 'e':
            encrypt_sha512(args[2])
        else:
            decrypt_sha512(args[2])
    elif flag == '--hex':
        if e_or_d(action) == 'e':
            encrypt_hex(args[2])
        else:
            decrypt_hex(args[2])
    elif flag == '--binary':
        if e_or_d(action) == 'e':
            encrypt_binary(args[2])
        else:
            decrypt_binary(args[2])
    else:
        print(f'{bcolors.FAIL}"{flag}" is not a valid type.{bcolors.ENDC}\nPlease use --help to check out the options.')

args = sys.argv[1:]


if args:
    handle_args(args)
else:
    print('Incorrect use of script.\nPlease read --help (-h) for directions.')