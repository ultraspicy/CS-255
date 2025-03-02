###############################################################################
# CS 255
# 1/12/25
# 
# messenger.py
# ______________
# Please implement the functions below according to the assignment spec
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
        key = generate_eg()
        self.sk = key["private"]
        self.pk = key["public"]
        certificates = {
            "username": username,
            "pk": self.pk,
        }
        return certificates


    def receive_certificate(self, certificate: dict, signature: str) -> None:
        """
        Receive and store another user's certificate.

        Inputs:
            certificate: dict
            signature: str

        Returns:
            None
        """
        self.certs[dict["username"], dict]


    def send_message(self, name: str, plaintext: str) -> tuple[dict, str]:
        """
        Generate the message to be sent to another user.

        Inputs:
            name: str
            plaintext: str

        Returns:
            (header, ciphertext): tuple(dict, str)
        """
        raise NotImplementedError("not implemented!")
        header = {}
        ciphertext = ""
        return header, ciphertext


    def receive_message(self, name: str, message: tuple[dict, str]) -> str:
        """
        Decrypt a message received from another user.

        Inputs:
            name: str
            message: tuple(dict, str)

        Returns:
            plaintext: str
        """
        raise NotImplementedError("not implemented!")
        header, ciphertext = message
        plaintext = ""
        return plaintext