# Problem 3.3: Invalid Curve Attack on ECDH

## Description
Attack ECDH key exchange by exploiting servers that don't validate custom curve parameters. Uses small cyclic groups and Chinese Remainder Theorem to recover the 192-bit private key.

## File Structure
- `exploit.py`: Main attack script
- `crypto_utils.py`: Cryptographic utilities and custom elliptic curve implementation (from 3-2)
- `client_smc.py`: SMC protocol client (from 3-2)
- `check_key.py`: Verification script for recovered key
- `requirements.txt`: Python dependencies

## Usage

1. **Install dependencies:**
```bash
   pip install -r requirements.txt
```

2. **Configure target** in `exploit.py`:
```python
   USER_ID = "group-1"
   SERVER_URL = "https://crypto-assignment.dangduongminhnhat2003.workers.dev"
   USE_PROXY = True # if you want to view packets in BurpSuite
   PROXY_URL = "http://127.0.0.1:8080" # your BurpSuite proxy server
```

1. **Run attack:**
```bash
   python exploit.py
```

1. **Verify recovered key** in `check_key.py`:
```python
   RECOVERED_KEY = 0x4b9a95c2326135c622fa761e25bfd1a8070dc3f61e6bcc6b
```
```bash
   python check_key.py
```

## Example Output
```
[*] Searching on F_13: Order = 11, a=1, b=1, G=(0,1) -> [OK] k = 5 (mod 11)
[*] Searching on F_17: Order = 19, a=2, b=3, G=(5,1) -> [OK] k = 13 (mod 19)
...
[+] Collected enough modulo equations for 192-bit key recovery.

[+] RECOVERED PRIVATE KEY: 0x4b9a95c2326135c622fa761e25bfd1a8070dc3f61e6bcc6b
```