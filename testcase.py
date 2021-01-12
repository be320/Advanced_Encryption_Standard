import unittest
from aes import AES
import os

print("Enter The Key: ")
key = input()
print("Enter The Plaintext: ")
plaintext = input()

aes = AES()

cyphertext = aes.encryption(plaintext, key)
plaintext = aes.decryption(cyphertext, key)

print(cyphertext)


input("AES Developed by Ahmed Bahaa")

