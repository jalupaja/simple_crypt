#!/usr/bin/env python3

import sys
import os
from getpass import getpass
from base64 import b64encode, b64decode, binascii
from Crypto.Cipher import AES

import config


def print_help():
    print(f"Usage: {config.prog_name} encrypt|decrypt [FILE]... [OPTION]")
    print("Encrypt/decrpt files and folders")
    print(
        "\t-y, --delete\t\tdelete encrypted/decrypted file after saving decrypted/encrypted file"
    )
    print(
        "\t-p, --password\t\tuse following string as a password instead of prompting for one"
    )
    print(
        "\t--print\t\tprint the output instead of writing it to a file"
    )


def print_error(text):
    print("\033[0;31mERROR: " + text + "\033[1;0m")


def __pad(text):
    if isinstance(text, str):
        text = text.encode()
    pad_len = 16 - len(text) % 16
    pad_char = chr((16 - len(text) % 16) % 16).encode()
    return text + pad_char * pad_len


def __unpad(text):
    pad_char = text[-1]
    if pad_char == 0x0:
        pad_len = 16
    else:
        pad_len = pad_char
    return text[:-pad_len]


def __rename_to_crypt(file):
    return file + config.encrypted_file_extension


def __rename_from_crypt(file):
    return (
        file[0 : -len(config.encrypted_file_extension)]
        if file.endswith(config.encrypted_file_extension)
        else file
    )


def __add_starting_bytes(text):
    return config.encrypted_file_starting_bytes + text


def __remove_starting_bytes(text):
    counter = 0
    try:
        for byte in config.encrypted_file_starting_bytes:
            if text[counter] != byte:
                return b""
            counter += 1
        return text[len(config.encrypted_file_starting_bytes) :]
    except IndexError:
        return b""


def input_password(prompt):
    return getpass(prompt=prompt)


def read_file(file):
    with open(file, "br") as f:
        return f.read()


def write_file(file, text):
    if isinstance(text, bytes):
        with open(file, "bw") as f:
            f.write(text)
    else:
        with open(file, "w") as f:
            f.write(text)


def encrypt(plaintext, key):
    return AES.new(__pad(key), AES.MODE_ECB).encrypt(__pad(plaintext))


def decrypt(ciphertext, key):
    return __unpad(AES.new(__pad(key), AES.MODE_ECB).decrypt(ciphertext))


def encrypt_file(file, key, OPTION_DELETE_OLD, OPTION_PRINT, verbose_errors=True):
    try:
        plain_bytes = read_file(file)
    except PermissionError:
        print_error(f"Couldn't read from file {file}")
    else:
        cipher_bytes = __add_starting_bytes(encrypt(plain_bytes, key))
        b64enc_string = b64encode(cipher_bytes).decode()
        if OPTION_PRINT:
            print(b64enc_string)
        else:
            try:
                write_file(__rename_to_crypt(file), b64enc_string)
                # No failure in this function
                if OPTION_DELETE_OLD:
                    os.remove(file)
                return True
            except PermissionError:
                print_error(f"Couldn't write to file {__rename_to_crypt(file)}")
    return False  # Failure somwhere in this function


def decrypt_file(file, key, OPTION_DELETE_OLD, OPTION_PRINT, verbose_errors=True):
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
                if OPTION_PRINT:
                    print(plain_bytes.decode())
                else:
                    try:
                        write_file(__rename_from_crypt(file), plain_bytes)
                        # No failure in this function
                        if OPTION_DELETE_OLD:
                            os.remove(file)
                        return True
                    except PermissionError:
                        print_error(f"Couldn't write to file {__rename_from_crypt(file)}")
    return False  # Failure somwhere in this function


def encrypt_dir(input_dir, key, OPTION_DELETE_OLD, OPTION_PRINT):
    dir_contents = os.listdir(input_dir).copy()
    for c in dir_contents:
        c_path = f"{input_dir}/{c}"
        if os.path.isfile(c_path):
            encrypt_file(c_path, key, OPTION_DELETE_OLD, OPTION_PRINT, False)
        elif os.path.isdir(c_path):
            encrypt_dir(c_path, key, OPTION_DELETE_OLD, OPTION_PRINT)


def decrypt_dir(input_dir, key, OPTION_OPTION_DELETE_OLD, OPTION_PRINT):
    dir_contents = os.listdir(input_dir).copy()
    for c in dir_contents:
        c_path = f"{input_dir}/{c}"
        if os.path.isfile(c_path):
            decrypt_file(c_path, key, OPTION_DELETE_OLD, OPTION_PRINT, False)
        elif os.path.isdir(c_path):
            decrypt_dir(c_path, key, OPTION_DELETE_OLD, OPTION_PRINT)


if __name__ == "__main__":
    OPTION_DELETE_OLD = False
    OPTION_PRINT = False
    password = ""
    args = sys.argv[1:]
    if len(args) <= 1:
        print_help()
    else:
        i = 1
        while i < len(args):
            path = args[i]
            if path in ["-y", "--delete"]:
                OPTION_DELETE_OLD = True
                args.pop(i)
                i -= 1
            elif path in ["-p", "--password"]:
                args.pop(i)
                if i < len(args):
                    password = args.pop(i)
            elif path in ["--print", "print",]:
                OPTION_PRINT = True
                args.pop(i)
                i -= 1
            elif not os.path.exists(path):
                print_error(f"{path} doesn't exist!")
                break
            i += 1

        else:
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
                            encrypt_file(path, password, OPTION_DELETE_OLD, OPTION_PRINT)
                        elif os.path.isdir(path):
                            encrypt_dir(path, password, OPTION_DELETE_OLD, OPTION_PRINT)

            elif args[0] in ["-d", "--decrypt", "d", "decrypt"]:
                if not password:
                    password = input_password("Input your password: ")
                for path in args:
                    if os.path.isfile(path):
                        decrypt_file(path, password, OPTION_DELETE_OLD, OPTION_PRINT)
                    elif os.path.isdir(path):
                        decrypt_dir(path, password, OPTION_DELETE_OLD, OPTION_PRINT)

            else:
                print_help()
