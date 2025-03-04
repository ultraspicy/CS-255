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
import base64

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

        # init Double Ratchet
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
        # raise NotImplementedError("not implemented!")

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
        if not verify_with_ecdsa(self.ca_public_key, str(certificate), signature):
            raise ValueError("Tampering detected!")
        
        my_username = self.certificate["username"]
        other_username = certificate["username"]
        self.certs[other_username] = certificate
        # Initialize connection for this user if not exists
        if other_username not in self.conns:
            self.conns[other_username] = {}

        shared_secret = compute_dh(self.ElGamel_key["private"], certificate["pk"])
        self.conns[other_username]["root_key"] = shared_secret
        
        salt1 = b'\x02' * 16
        salt2 = b'\x03' * 16
        root_key1, chain_key1 = hkdf(shared_secret, salt1, "chain_key_1")
        root_key2, chain_key2 = hkdf(root_key1, salt2, "chain_key_2")

        if my_username < other_username:
            self.conns[other_username]["receiving_chain_key"] = chain_key1
            self.conns[other_username]["sending_chain_key"] = chain_key2
        else: 
            self.conns[other_username]["receiving_chain_key"] = chain_key2
            self.conns[other_username]["sending_chain_key"] = chain_key1

        
        self.conns[other_username]["root_key"] = shared_secret
        receiving_chain_key = self.conns[other_username]["receiving_chain_key"] 
        sending_chain_key = self.conns[other_username]["sending_chain_key"]

        print(f"{my_username}:{other_username} shared_secret with in bytes {encode_bytes(shared_secret)}, with len {len(shared_secret)}")
        print(f"{my_username}:{other_username} receiving_chain_key in bytes {encode_bytes(receiving_chain_key)}, with len {len(receiving_chain_key)}")
        print(f"{my_username}:{other_username} sending_chain_key in bytes {encode_bytes(sending_chain_key)}, with len {len(sending_chain_key)}")

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
        # TODO
        message_key, new_sending_chain_key = hkdf(sending_chain_key, b'\x01', "chain_to_message_key") # is fixed nonce ok? what is the input of KDF, context?
        self.conns[name]["sending_chain_key"] = new_sending_chain_key
        # encrypt_with_gcm(key: bytes, plaintext: str, iv: bytes, authenticated_data: str = "") -> bytes:
        iv = gen_random_salt()[:12]
        ciphertext = encrypt_with_gcm(message_key, plaintext, iv, name)

        # Generate IV for message encryption
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
            print("=============head changed! new receiving chain!===============")
            self.certs[name]["pk"] = header["pk"]
            shared_secret = compute_dh(self.ElGamel_key["private"], header["pk"])
            new_root_key, receiving_chain_key = hkdf(self.conns[name]["root_key"], gen_random_salt(), "key_update")
            # Update the keys for this connection
            self.conns[name]["root_key"] = new_root_key
            self.conns[name]["receiving_chain_key"] = receiving_chain_key
        
        receiving_chain_key = self.conns[name]["receiving_chain_key"]
        message_key, new_receiving_chain_key = hkdf(receiving_chain_key, b'\x01', "chain_to_message_key") # is fixed nonce ok? what is the input of KDF, context?
        self.conns[name]["receiving_chain_key"] = new_receiving_chain_key


        plaintext = decrypt_with_gcm(message_key, ciphertext, header["iv"], name)
        return plaintext


def encode_bytes(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

def decode_bytes(hex_str: str) -> bytes:
    return base64.b64decode(hex_str)


'''
. If you have not previously communicated, setup the session by generating the necessary
double ratchet keys according to the Signal spec

should we assume?


On every send, increment the sending chain
(and the root chain if necessary, according to the Signal spec).

test doesn't change public key at all
'''