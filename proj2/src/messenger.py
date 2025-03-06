###############################################################################
# CS 255
# 1/12/25
# 
# messenger.py
# ______________
# Please implement the functions below according to the assignment spec

# what would be a the initial root key
###############################################################################
from lib import (
    gen_random_salt,
    generate_eg,
    compute_dh,
    verify_with_ecdsa,
    hmac_to_aes_key,
    hmac_to_hmac_key,
    hkdf,
    encrypt_with_gcm,
    decrypt_with_gcm,
    gov_encryption_data_str
)

class MessengerClient:
    def __init__(self, cert_authority_public_key: bytes, gov_public_key: bytes):
        """
        The certificate authority DSA public key is used to
        verify the authenticity and integrity of certificates
        of other users (see handout and receive_certificate)
        """
        # Feel free to store data as needed in the objects below
        # and modify their structure as you see fit.
        self.ca_public_key = cert_authority_public_key
        self.gov_public_key = gov_public_key
        self.conns = {}  # data for each active connection
        self.certs = {}  # certificates of other users

        # init ElGamel key pair
        self.ElGamel_key = generate_eg()
        

    def generate_certificate(self, username: str) -> dict:
        """
        Generate a certificate to be stored with the certificate authority.
        The certificate must contain the field "username".

        Inputs:
            username: str

        Returns:
            certificate: dict

        1. Generate the necessary ElGamal key pair for key exchanges
        2. Public keys are are placed into a certificate 
        // instead of being issued certificates from CA, we just generate our own certificates
        """
        # generate a cert for self

        certificate = {
            "username": username,
            "pk": self.ElGamel_key["public"],
        }
        self.certificate = certificate
        return certificate


    def receive_certificate(self, certificate: dict, signature: bytes) -> None:
        """
        Receive and store another user's certificate.

        Inputs:
            certificate: dict
            signature: str

        Returns:
            None
        // verify the signature is valid
        // add certificate keyed by username
        
        // set up shared secret 
        """
        # verify the cert is valid
        if not verify_with_ecdsa(self.ca_public_key, str(certificate), signature):
            raise ValueError("Tampering detected!")
        
        my_username = self.certificate["username"]
        other_username = certificate["username"]
        self.certs[other_username] = certificate

        # Initialize connection for this user if not exists
        if other_username not in self.conns:
            self.conns[other_username] = {}
        shared_secret = compute_dh(self.ElGamel_key["private"], certificate["pk"])
        # the secret is also used as the root_key at the very beginning
        self.conns[other_username]["root_key"] = shared_secret
        
        salt1 = b'\x11' * 16
        salt2 = b'\xFF' * 16
        root_key1, chain_key1 = hkdf(shared_secret, salt1, "chain_key_1")
        root_key2, chain_key2 = hkdf(root_key1, salt2, "chain_key_2")

        if my_username < other_username:
            self.conns[other_username]["receiving_chain_key"] = chain_key1
            self.conns[other_username]["sending_chain_key"] = chain_key2
        else: 
            self.conns[other_username]["receiving_chain_key"] = chain_key2
            self.conns[other_username]["sending_chain_key"] = chain_key1

    def send_message(self, name: str, plaintext: str) -> tuple[dict, str]:
        """
        Generate the message to be sent to another user.

        Inputs:
            name: str
            plaintext: str

        Returns:
            (header, ciphertext): tuple(dict, str)
        """
      
        if name not in self.conns:
            raise Exception(f"Cannot send message to {name}: No connection established")
    
        if self.conns[name]["sending_chain_key"] is None:
            raise Exception(f"No sending chain established for {name}")
        
        sending_chain_key = self.conns[name]["sending_chain_key"]
        message_key = hmac_to_hmac_key(sending_chain_key, 'constant1')
        new_sending_chain_key = hmac_to_hmac_key(sending_chain_key, 'constant2')
        self.conns[name]["sending_chain_key"] = new_sending_chain_key

        iv = gen_random_salt()[:12]
        gov_iv = gen_random_salt()[:12]
        v_gov = self.ElGamel_key["public"]
        gov_key = compute_dh(self.ElGamel_key["private"], self.gov_public_key) # shared secret with the gov
        gov_key = hmac_to_aes_key(gov_key, gov_encryption_data_str)
        c_gov = encrypt_with_gcm(gov_key, message_key, gov_iv, "") # encrypt sending_chain_key use gov_iv

        header = {
            "pk": self.ElGamel_key["public"],
            "cert": self.certificate,
            "iv": iv,
            "v_gov": v_gov,      
            "c_gov": c_gov,       
            "iv_gov": gov_iv,  
            "receiver_iv": iv,  
        }

        ciphertext = encrypt_with_gcm(message_key, plaintext, iv, str(header))
        return header, ciphertext


    def receive_message(self, name: str, message: tuple[dict, str]) -> str:
        """
        Decrypt a message received from another user.

        Inputs:
            name: str
            message: tuple(dict, str)

        Returns:
            plaintext: str

        # check if the public from that user is changed. if y, then derive new key from root chain
        """
        if name not in self.conns:
            raise Exception(f"Cannot receive message from {name}: No connection established")
        
        header, ciphertext = message
        received_pk = header["pk"]    

        if header["pk"] != self.certs[name]["pk"]:
            print("============= head changed! new receiving chain! ===============\n")
            # another ratchet step, update self ElGamel key pair and update the secret
            self.certs[name]["pk"] = header["pk"]
            self.ElGamel_key = generate_eg()
            self.certificate["pk"] = self.ElGamel_key["public"]
            shared_secret = compute_dh(self.ElGamel_key["private"], header["pk"])
            self.conns[name]["root_key"] = shared_secret
        
            salt1 = b'\x11' * 16
            salt2 = b'\xFF' * 16
            root_key1, chain_key1 = hkdf(shared_secret, salt1, "chain_key_1")
            root_key2, chain_key2 = hkdf(root_key1, salt2, "chain_key_2")

            my_username = self.certificate["username"]
            if my_username < name:
                self.conns[name]["receiving_chain_key"] = chain_key1
                self.conns[name]["sending_chain_key"] = chain_key2
            else: 
                self.conns[name]["receiving_chain_key"] = chain_key2
                self.conns[name]["sending_chain_key"] = chain_key1
        
        receiving_chain_key = self.conns[name]["receiving_chain_key"]
        message_key = hmac_to_hmac_key(receiving_chain_key, 'constant1')
        new_receiving_chain_key = hmac_to_hmac_key(receiving_chain_key, 'constant2')
        self.conns[name]["receiving_chain_key"] = new_receiving_chain_key
        plaintext = decrypt_with_gcm(message_key, ciphertext, header["iv"], str(header))

        return plaintext
