# Problem 2: Attacking the Vigenere Cipher

## Description
(vd: cryptanalysis script to recover plaintext from Vigenere cipher) 

## File structure
(vd: list of files and their purpose)
- file `vigenere.py`: encryption and decryption functions for Vigenere cipher
- file `attack.py`: functions for analyzing and attacking Vigenere cipher
- file `requirements.txt`: libraries required to run the code

## Usage instructions
(vd: how to run the attack script)
1. Ensure you have Python installed on your machine.
2. Clone the repository to your local machine.
3. Navigate to the project directory.
4. Run the attack script using the command:
    ```
    python attack.py --ciphertext <ciphertext_file> --output <output_file>
    ```
5. The recovered plaintext will be saved in the specified output file.

## Demo
(vd: example of running the attack script)
```bash
python attack.py --ciphertext encrypted.txt --output decrypted.txt
```
(demo image or screenshot can be included here)
![Demo Image](demo_image.png)