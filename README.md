desafenet
---------
desafenet is a cross platform (Linux, OSX, Windows and more) tool to handle E-SafeNet protected files. Since only a few samples were available, the implementation isn't feature complete yet. Right now it supports complete decryption of files using the LZO mode and partial reconstruction of files compressed with what we call PSUB. For the latter the first block of 512 bytes will be corrupted, while the rest of the file can be fully decrypted as well. If you happen to have lost your systems key, but still have a known plaintext sample of one of the files, (>= 1536 bytes) desafenet can also recover your key. Encryption is currently unsupported, but could be added with relative ease.

Compatible files can be identified by the following string in their header:

```0000000: 62 14 23 65 6b 00 95 01 00 00 00 01 45 2d 53 61 66 65 4e 65 74 00 00 00 4c 4f 43 4b 00 00 00 00  b.#ek.......E-SafeNet...LOCK....```

usage
---------
```
$ desafenet 
desafenet: two out of -k (key) -p (plaintext) and -c (ciphertext) required
```
decryption:
```
$ desafenet -k key.file -c encrypted.file > decrypted.file
```
key recovery:
```
$ desafenet -p decrypted.file -c encrypted.file > key.file
```