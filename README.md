# simple_crypt

A simple python script to encrypt/decrypt files and folder using AES 

# Arguments

| Argument | Explanation |
| -- | -- |
| -e, --encrypt | encrypt following files |
| -y, --decrypt | decrypt following files |
| -d, --delete | delete encrypted/decrypted file after saving decrypted/encrypted file |
|-p, --password | use following string as a password instead of prompting for one |

# Examples 

| Example | howto |
| -- | -- |
| Encrypt "dir/file" and "./file" | `./simple_crypt.py -e dir/file file` |
| Decrypt "file.crypt" and delete it after | `./simple_crypt.py -d -y file.crypt` |
| Encrypt file with password "n0tSeqPas" | `./simple_crypt.py -e -p n0tSeqPas file`
