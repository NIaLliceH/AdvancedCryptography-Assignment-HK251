from random import choices
from secret import key

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
ALPHABET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

class VigenereCipher:
    def __init__(self, key):
        self.key = key.lower()
        self.alphabet = ALPHABET

    def expand_key(self, text_length: int) -> str:
        key = self.key
        idx = 0
        while True:
            if text_length > len(key):
                key += key[idx]
                idx += 1
            else:
                break
        return key

    def encrypt(self, plaintext: str) -> str:
        key = self.expand_key(len(plaintext))
        ciphertext = ""
        idx = 0
        for char in plaintext:
            if char in self.alphabet:
                shift = self.alphabet.index(key[idx])
                ciphertext += self.alphabet[(self.alphabet.index(char) + shift) % 26]
                idx += 1
            else:
                if char in ALPHABET_UPPER:
                    shift = self.alphabet.index(key[idx])
                    ciphertext += self.alphabet[
                        (self.alphabet.index(char.lower()) + shift) % 26
                    ].upper()
                    idx += 1
                else:
                    ciphertext += char
        return ciphertext

def vig_encrypt(plaintext: str, key: str, file_path: str) -> str:
    cipher = VigenereCipher(key)
    c = cipher.encrypt(plaintext)
    open(file_path, "w").write(c)

if __name__ == "__main__":
    plaintext = open("plaintext.txt", "r").read()
    vig_encrypt(plaintext, key, "ciphertext.txt")