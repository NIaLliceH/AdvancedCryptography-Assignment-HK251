import math
import os
import sys
from collections import Counter

ENGLISH_FREQUENCIES = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
    'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
    'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
    'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
    'z': 0.00074
}
ALPHABET = "abcdefghijklmnopqrstuvwxyz"
ALPHABET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IC_ENGLISH = 0.067

class VigenereCipher:
    def __init__(self, key):
        self.key = key.lower()
        self.alphabet = ALPHABET

    def expand_key(self, text_length: int) -> str:
        key = self.key
        idx = 0
        key_len = len(self.key)
        while len(key) < text_length:
            key += self.key[idx]
            idx = (idx + 1) % key_len
        return key[:text_length]

    def decrypt(self, ciphertext: str) -> str:
        key = self.expand_key(len(ciphertext))
        plaintext = ""
        idx = 0
        for char in ciphertext:
            if char in self.alphabet:
                shift = self.alphabet.index(key[idx])
                plaintext += self.alphabet[(self.alphabet.index(char) - shift) % 26]
                idx += 1
            elif char in ALPHABET_UPPER:
                shift = self.alphabet.index(key[idx])
                plaintext += self.alphabet[
                    (self.alphabet.index(char.lower()) - shift) % 26
                ].upper()
                idx += 1
            else:
                plaintext += char
        return plaintext

def clean_text(text: str) -> str:
    return "".join([c.lower() for c in text if c.lower() in ALPHABET])

def calculate_ic(text: str) -> float:
    N = len(text)
    if N <= 1: return 0.0

    counts = Counter(text)
    numerator = 0.0
    for char in ALPHABET:
        count = counts.get(char, 0)
        numerator += count * (count - 1)
        
    denominator = N * (N - 1)
    
    return numerator / denominator if denominator > 0 else 0.0

def find_key_length_ic(ciphertext: str, max_key_len=40) -> int:
    cleaned_text = clean_text(ciphertext)
    key_lens_sorted = []
    
    print("Dang tinh IC de tim do dai khoa...")
    
    for key_length in range(2, max_key_len + 1):
        total_ic = 0.0
        
        for i in range(key_length):
            subgroup = cleaned_text[i::key_length]
            total_ic += calculate_ic(subgroup)
            
        average_ic = total_ic / key_length
        
        key_lens_sorted.append((key_length, average_ic, abs(average_ic - IC_ENGLISH)))

    key_lens_sorted.sort(key=lambda x: x[2])
    
    print("\nTop do dai khoa kha thi:")
    for length, avg_ic, diff in key_lens_sorted[:5]:
        print(f"Do dai {length:2d}: IC khoang {avg_ic:.5f}, lech {diff:.5f}")

    best_key_len = key_lens_sorted[0][0]
    return best_key_len

def find_best_caesar_shift(subgroup_text: str) -> str:
    best_shift = 0
    min_chi_squared = float('inf')
    
    text_len = len(subgroup_text)
    if text_len == 0:
        return 'a'

    for shift in range(26):
        chi_squared_sum = 0.0
        
        shifted_counts = Counter()
        for char in subgroup_text:
            shifted_index = (ALPHABET.index(char) - shift) % 26
            shifted_counts[ALPHABET[shifted_index]] += 1
            
        for i in range(26):
            char = ALPHABET[i]
            expected_count = ENGLISH_FREQUENCIES[char] * text_len
            observed_count = shifted_counts.get(char, 0)
            
            if expected_count == 0:
                continue
                
            difference = observed_count - expected_count
            chi_squared_sum += (difference * difference) / expected_count
            
        if chi_squared_sum < min_chi_squared:
            min_chi_squared = chi_squared_sum
            best_shift = shift
            
    return ALPHABET[best_shift]

if __name__ == "__main__":
    
    filename = "ciphertext.txt"
    
    if not os.path.exists(filename):
        print(f"Loi: Khong tim thay file '{filename}'")
        sys.exit(1)
        
    with open(filename, "r", encoding="utf-8") as f:
        challenge_ciphertext = f.read()

    print(f"Da doc {len(challenge_ciphertext)} ky tu tu {filename}")
    
    key_length_guess = find_key_length_ic(challenge_ciphertext, max_key_len=40)
    
    if key_length_guess == 0:
        print("Khong tim duoc do dai khoa hop ly.")
    else:
        print(f"\nChot do dai khoa la: {key_length_guess}\n")

        print("Di tim ki tu cua khoa:")
        
        found_key = ""
        cleaned_ciphertext_for_groups = clean_text(challenge_ciphertext)
        
        for i in range(key_length_guess):
            subgroup = cleaned_ciphertext_for_groups[i::key_length_guess]
            key_char = find_best_caesar_shift(subgroup)
            found_key += key_char
            print(f"Nhom {i+1}: ra chu '{key_char}'")
            
        print(f"\nKhoa tim duoc la: '{found_key}'\n")

        print("Bat dau giai ma...")
        cipher_solver = VigenereCipher(found_key)
        recovered_plaintext = cipher_solver.decrypt(challenge_ciphertext)
        
        print(f"Noi dung giai ma duoc:\n")
        print(recovered_plaintext)