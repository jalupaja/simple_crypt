# simple_crypt

A simple python script to encrypt/decrypt files and folder using AES 

## Arguments

| Argument | Explanation |
| -- | -- |
| -e, --encrypt | encrypt following files |
| -d, --decrypt | decrypt following files |
| -y, --delete | delete encrypted/decrypted file after saving decrypted/encrypted file |
| -p, --password | use following string as a password instead of prompting for one |
| --print | print the output instead of writing it to a file |

## Examples 

| Example | howto |
| -- | -- |
| Encrypt "dir/file" and "./file" | `./simple_crypt.py -e dir/file file` |
| Decrypt "file.crypt" and delete it after | `./simple_crypt.py -d -y file.crypt` |
| Decrypt "file.crypt" and print the output | `./simple_crypt.py -d print file.crypt` |
| Encrypt file with password "n0tSeqPas" | `./simple_crypt.py -e -p n0tSeqPas file`

## Installation
`pip install -r requirements.txt`

## ToDo
These todos are totally optional and just here so I remember what I could do when opening this project sometime in the future:

| ToDo |
| -- |
| allow redirection into an output file |
