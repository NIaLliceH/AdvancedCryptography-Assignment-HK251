from client_smc import ClientSMC
from crypto_utils import ECPoint

class KeyCheckerClient(ClientSMC):
    def verify_server_secret(self, candidate_secret_key_int):
        if self.state == "INIT" or self.pk_server is None or self.curve is None:
            print("[!] Error: Client not authenticated. No real Public Key to compare.")
            return False

        print("="*60)

        print(f"[*] Server ECDH private key: {hex(candidate_secret_key_int)}")
        print("-" * 60)
        
        try:
            calculated_pk = self.curve.scalar_mult(candidate_secret_key_int, self.curve.G)
            
            print(f"[*] Calculated PubKey (x): {hex(calculated_pk.x)}")
            print(f"[*] Calculated PubKey (y): {hex(calculated_pk.y)}")
            
            print("-" * 60)
            print(f"[*] REAL Server PubKey (x): {hex(self.pk_server.x)}")
            print(f"[*] REAL Server PubKey (y): {hex(self.pk_server.y)}")
            print("-" * 60)

            if calculated_pk.x == self.pk_server.x and calculated_pk.y == self.pk_server.y:
                print("[SUCCESS] Public key matches!")
                return True
            else:
                print("[FAIL] Public key does NOT match.")
                return False
                
        except Exception as e:
            print(f"[!] Error during calculation: {e}")
            return False

if __name__ == "__main__":
    USER_ID = "group-1"
    SERVER_URL = "https://crypto-assignment.dangduongminhnhat2003.workers.dev"
    
    RECOVERED_KEY = 0x4b9a95c2326135c622fa761e25bfd1a8070dc3f61e6bcc6b
    if RECOVERED_KEY == 0:
        print("[!] Please fill in RECOVERED_KEY in the script before running.")
        exit()

    client = KeyCheckerClient(USER_ID, SERVER_URL)

    if client.authenticate():
        client.verify_server_secret(RECOVERED_KEY)
    else:
        print("[!] Unable to connect or authenticate with the Server.")