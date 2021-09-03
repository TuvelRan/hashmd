#!/usr/bin/python
import requests
import sys
from hashlib import md5

def decrypt_hash(hash_to_crack):
    if len(hash_to_crack) != 16 and len(hash_to_crack) != 32:
        print('Please provide a valid md5 hash.')
        return
    print(f'Trying to crack "{hash_to_crack}"... Please wait')
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
        print(f'Cracked: {value}')
    except:
        print('Sorry, but this hash is not in our database.')

def encrypt_text(text):
    print(f"Hash: '{md5(text.encode()).hexdigest()}'")

def print_help():
    help_msg = '''
    hashmd(5) for encrypting and decrypting md5 hashes.\n
    \t-e Encrypt a text (the second argument)
    \t\talias: --encrypt

    \t-d (Try to) Decrypt a hash
    \t\talias: --decrypt

    \t-h Opens this guide
    \t\talias: --help\n
    Thanks for using hashmd. Enjoy!
    Created By Tuvel Ran

    Source: https://github.com/TuvelRan/hashmd
    '''
    print(help_msg)

args = sys.argv[1:]

if args:
    flag = args[0]
    if flag == '-e' or flag == '--encrypt':
        if len(args) > 1:
            encrypt_text(args[1])
        else:
            text_to_encrypt = input('Enter Text To Encrypt: ')
            encrypt_text(text_to_encrypt)
    elif flag == '-d' or flag == '--decrypt':
        if len(args) > 1:
            decrypt_hash(args[1])
        else:
            hash_to_crack = input('Hash To Crack: ')
            decrypt_hash(hash_to_crack)
    elif flag == '-h' or flag == '--help':
        print_help()
    else:
        print(f'{flag} is not a valid flag.\nPlease use --help to check out the options.')
else:
    print('Incorrect use of script.\nPlease read --help (-h) for directions.')
