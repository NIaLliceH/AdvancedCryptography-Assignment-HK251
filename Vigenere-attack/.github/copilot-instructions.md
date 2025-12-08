# Copilot Instructions for Vigenere Cipher Attack Project

## Project Overview
This project implements a cryptanalysis tool to break Vigenere ciphers. It includes methods to:
- Determine the key length using the Index of Coincidence (IC).
- Recover the key using frequency analysis and Chi-squared tests.
- Decrypt ciphertext using the recovered key.

The code is written in Python and focuses on educational cryptography concepts.

## Key Files
- `decrypt.py`: Contains the main logic for the Vigenere cipher attack, including:
  - `VigenereCipher` class for encryption and decryption.
  - Helper functions for text cleaning, IC calculation, and Chi-squared analysis.
  - A main program to orchestrate the attack.
- `problem-2.md`: Likely contains the problem description or assignment details.

## Developer Workflows
### Running the Program
To execute the decryption process, run the following command in the project directory:
```powershell
& C:/Users/imjus/AppData/Local/Programs/Python/Python313/python.exe decrypt.py
```
Ensure the Python interpreter is correctly configured.

### Debugging
- Use print statements to trace intermediate values, such as IC calculations or Chi-squared results.
- Focus on the `find_key_length_ic` and `find_best_caesar_shift` functions for debugging key recovery issues.

### Testing
- Test the program with different ciphertexts to ensure robustness.
- Modify the `challenge_ciphertext` variable in `decrypt.py` to test new inputs.

## Project-Specific Conventions
- **Language-Specific Comments**: Comments are written in Vietnamese to explain cryptographic concepts and code logic.
- **Constants**: Cryptographic constants like `ENGLISH_FREQUENCIES` and `IC_ENGLISH` are defined at the top of the file.
- **Helper Functions**: Functions like `clean_text` and `calculate_ic` are modular to facilitate testing and reuse.

## Integration Points
- The program does not rely on external libraries beyond Python's standard library.
- Ensure the Python environment supports `collections.Counter` and other standard modules.

## Examples
### Key Length Detection
The `find_key_length_ic` function calculates the IC for different key lengths and selects the best match:
```python
key_length_guess = find_key_length_ic(challenge_ciphertext, max_key_len=25)
```
### Key Recovery
The `find_best_caesar_shift` function uses Chi-squared analysis to recover each character of the key:
```python
key_char = find_best_caesar_shift(subgroup)
```
### Decryption
The `VigenereCipher` class decrypts the ciphertext using the recovered key:
```python
cipher_solver = VigenereCipher(found_key)
recovered_plaintext = cipher_solver.decrypt(challenge_ciphertext)
```

## Notes
- The program assumes the ciphertext is in English.
- Non-alphabetic characters in the ciphertext are preserved during decryption.

Feel free to update this file as the project evolves.