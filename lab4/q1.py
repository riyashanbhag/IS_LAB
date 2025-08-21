from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime
import time

class SecureCommunicationSystem:
    def __init__(self):
        self.subsystems = {}
        self.logs = []

        # Generate and fix DH parameters once for all subsystems
        self.p = getPrime(2048)
        self.g = 2

    def create_system(self, subsystem_id):
        # Generate private key for DH (random integer < p)
        private_key_int = int.from_bytes(get_random_bytes(256), 'big') % self.p
        public_key_int = pow(self.g, private_key_int, self.p)
        self.subsystems[subsystem_id] = {
            'private_key': private_key_int,
            'public_key': public_key_int,
            'shared_keys': {}  # Store shared keys with other subsystems
        }
        self.log(f"{subsystem_id} created with DH keys.")

    def log(self, message):
        self.logs.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}")
        print(message)

    def dh_key_exchange(self, sender_id, receiver_id):
        sender = self.subsystems[sender_id]
        receiver = self.subsystems[receiver_id]

        # Sender computes shared secret using receiver's public key
        shared_secret_sender = pow(receiver['public_key'], sender['private_key'], self.p)
        # Receiver computes shared secret using sender's public key
        shared_secret_receiver = pow(sender['public_key'], receiver['private_key'], self.p)

        if shared_secret_sender == shared_secret_receiver:
            # Convert to 16 bytes (AES key size)
            shared_key_bytes = shared_secret_sender.to_bytes(256, 'big')[-16:]  # take last 16 bytes
            # Store shared keys in both subsystems with the other party
            sender['shared_keys'][receiver_id] = shared_key_bytes
            receiver['shared_keys'][sender_id] = shared_key_bytes
            self.log(f"Shared key established between {sender_id} and {receiver_id}.")
        else:
            self.log("Failed to establish shared key.")

    def encrypt_message(self, sender_id, receiver_id, message):
        sender = self.subsystems.get(sender_id)
        if sender is None:
            self.log(f"Sender {sender_id} not found.")
            return None

        shared_key = sender['shared_keys'].get(receiver_id)
        if shared_key is None:
            self.log(f"No shared key found between {sender_id} and {receiver_id}.")
            return None

        cipher_aes = AES.new(shared_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
        return cipher_aes.nonce + tag + ciphertext

    def decrypt_message(self, receiver_id, sender_id, encrypted_message):
        receiver = self.subsystems.get(receiver_id)
        if receiver is None:
            self.log(f"Receiver {receiver_id} not found.")
            return None

        shared_key = receiver['shared_keys'].get(sender_id)
        if shared_key is None:
            self.log(f"No shared key found between {receiver_id} and {sender_id}.")
            return None

        nonce = encrypted_message[:16]
        tag = encrypted_message[16:32]
        ciphertext = encrypted_message[32:]

        cipher_aes = AES.new(shared_key, AES.MODE_EAX, nonce=nonce)
        try:
            original_message = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()
            self.log(f"Message decrypted for {receiver_id}.")
            return original_message
        except ValueError:
            self.log("Decryption failed: MAC check failed.")
            return None

    def revoke_key(self, subsystem_id):
        if subsystem_id in self.subsystems:
            # Remove subsystem and clear references from others
            del self.subsystems[subsystem_id]
            for subsys in self.subsystems.values():
                if subsystem_id in subsys['shared_keys']:
                    del subsys['shared_keys'][subsystem_id]
            self.log(f"Keys revoked for subsystem {subsystem_id}.")


# Usage example:
secure_system = SecureCommunicationSystem()

secure_system.create_system("Finance System")
secure_system.create_system("HR System")
secure_system.create_system("Supply Chain Management")

secure_system.dh_key_exchange("Finance System", "HR System")
secure_system.dh_key_exchange("Supply Chain Management", "HR System")
secure_system.dh_key_exchange("Supply Chain Management", "Finance System")

encrypted_msg = secure_system.encrypt_message("Finance System", "HR System", "Confidential financial report.")
original_message = secure_system.decrypt_message("HR System", "Finance System", encrypted_msg)

if original_message:
    print(f"Decrypted Message: {original_message}")
else:
    print("Failed to decrypt the message.")

secure_system.revoke_key("Finance System")
