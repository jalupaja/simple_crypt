#!/usr/bin/env python3

import sys
import os
import config
from Crypto.Cipher import AES
from base64 import b64encode, b64decode, binascii
from getpass import getpass

# from Crypto.Util.Padding import pad


def help():
    print(f"Usage: {config.prog_name} encrypt|decrypt [FILE]... [OPTION]")
    print(f"Encrypt/decrpt files and folders")
    print(
        f"\t-y, --delete\t\tdelete encrypted/decrypted file after saving decrypted/encrypted file"
    )
    print(
        f"\t-p, --password\t\tuse following string as a password instead of prompting for one"
    )


def print_error(text):
    print("\033[0;31mERROR: " + text + "\033[1;0m")


def __pad(text):
    if type(text) == str:
        return text + "\0" * (16 - len(text) % 16)
    elif type(text) == bytes:
        return text + b"\0" * (16 - len(text) % 16)


def __unpad(text):
    text = text.decode()
    counter = 0
    while text[-(counter + 1)] == "\0":
        counter += 1
    return text[:-counter]


def __rename_to_crypt(file):
    return file + config.encrypted_file_extension


def __rename_from_crypt(file):
    return (
        file[0 : -len(config.encrypted_file_extension)]
        if file.endswith(config.encrypted_file_extension)
        else file
    )


def __add_starting_bytes(bytes):
    return config.encrypted_file_starting_bytes + bytes


def __remove_starting_bytes(bytes):
    counter = 0
    for byte in config.encrypted_file_starting_bytes:
        if bytes[counter] != byte:
            return b""
        counter += 1
    return bytes[len(config.encrypted_file_starting_bytes) :]


def input_password(prompt):
    return getpass(prompt=prompt)


def read_file(file):
    with open(file, "br") as f:
        ret = f.read()
    return ret


def write_file(file, text):
    with open(file, "w") as f:
        f.write(text)


def encrypt(plaintext, key):
    return AES.new(__pad(key), AES.MODE_ECB).encrypt(__pad(plaintext))


def decrypt(ciphertext, key):
    return __unpad(AES.new(__pad(key), AES.MODE_ECB).decrypt(ciphertext))


def encrypt_file(file, key, delete_old, verbose_errors=True):
    try:
        plain_bytes = read_file(file)
    except PermissionError:
        print_error(f"Couldn't read from file {file}")
    else:
        cipher_bytes = __add_starting_bytes(encrypt(plain_bytes, key))
        b64enc_string = b64encode(cipher_bytes).decode()
        try:
            write_file(__rename_to_crypt(file), b64enc_string)
            # No failure in this function
            if delete_old:
                os.remove(file)
            return True
        except PermissionError:
            print_error(f"Couldn't write to file {__rename_to_crypt(file)}")
    return False  # Failure somwhere in this function


def decrypt_file(file, key, delete_old, verbose_errors=True):
    try:
        b64enc_bytes = read_file(file)
    except PermissionError:
        print_error(f"Couldn't read from file {file}")
    else:
        try:
            cipher_bytes = __remove_starting_bytes(b64decode(b64enc_bytes))
        except binascii.Error:
            cipher_bytes = b""
        if not cipher_bytes:
            if verbose_errors:
                print_error(
                    f"{file} doesn't seem to be encrypted by {config.prog_name}"
                )
        else:
            try:
                plain_bytes = decrypt(cipher_bytes, key)
            except UnicodeDecodeError:
                print_error(f"Wrong password for {file}")
            else:
                try:
                    write_file(__rename_from_crypt(file), plain_bytes)
                    # No failure in this function
                    if delete_old:
                        os.remove(file)
                    return True
                except PermissionError:
                    print_error(f"Couldn't write to file {__rename_from_crypt(file)}")
    return False  # Failure somwhere in this function


def encrypt_dir(dir, key, delete_old):
    dir_contents = os.listdir(dir)
    for c in dir_contents:
        c_path = f"{dir}/{c}"
        if os.path.isfile(c_path):
            encrypt_file(c_path, key, delete_old, False)
        elif os.path.isdir(c_path):
            encrypt_dir(c_path, key, delete_old)


def decrypt_dir(dir, key, delete_old):
    dir_contents = os.listdir(dir)
    for c in dir_contents:
        c_path = f"{dir}/{c}"
        if os.path.isfile(c_path):
            decrypt_file(c_path, key, delete_old, False)
        elif os.path.isdir(c_path):
            decrypt_dir(c_path, key, delete_old)


if __name__ == "__main__":
    delete_old = False
    password = ""
    args = sys.argv[1:]
    if len(args) <= 1:
        help()
    else:
        i = 1
        while i < len(args):
            path = args[i]
            if path in ["-y", "--delete"]:
                delete_old = True
                args.pop(i)
                i -= 1
            elif path in ["-p", "--password"]:
                args.pop(i)
                if i < len(args):
                    password = args.pop(i)
            elif not os.path.exists(path):
                print_error(f"{path} doesn't exist!")
                break
            i += 1

        if args[0] in ["-e", "--encrypt", "e", "encrypt"]:
            if not password:
                password = input_password("Input your password: ")
                password_check = input_password("Input your password again: ")
            else:
                password_check = password
            if password != password_check:
                print_error("Passwords don't match!")
            else:
                for path in args:
                    if os.path.isfile(path):
                        encrypt_file(path, password, delete_old)
                    elif os.path.isdir(path):
                        encrypt_dir(path, password, delete_old)

        elif args[0] in ["-d", "--decrypt", "d", "decrypt"]:
            if not password:
                password = input_password("Input your password: ")
            for path in args:
                if os.path.isfile(path):
                    decrypt_file(path, password, delete_old)
                elif os.path.isdir(path):
                    decrypt_dir(path, password, delete_old)
