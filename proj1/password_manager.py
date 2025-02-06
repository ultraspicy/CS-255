from typing import Optional, Tuple

from util import dict_to_json_str, json_str_to_dict
from util import str_to_bytes, bytes_to_str, encode_bytes, decode_bytes

from Crypto.Protocol.KDF import PBKDF2
# https://pycryptodome.readthedocs.io/en/v3.21.0/src/hash/sha256.html
from Crypto.Hash import HMAC, SHA256 # https://pycryptodome.readthedocs.io/en/v3.21.0/src/hash/hmac.html
from Crypto.Cipher import AES # https://pycryptodome.readthedocs.io/en/v3.21.0/src/cipher/aes.html
from Crypto.Random import get_random_bytes

# number of iterations for PBKDF2 algorithm
PBKDF2_ITERATIONS = 100000
# we can assume no password is longer than this many characters
MAX_PASSWORD_LENGTH = 64

########## START CODE HERE ##########
# Add any extra constants you may need
########### END CODE HERE ###########


class Keychain:
    def __init__(
        self,
        ########## START CODE HERE ##########
        key=None,
        salt=None,
        kvs=None,
        password=None,
        ########### END CODE HERE ###########
    ):
        """
        Initializes the keychain using the provided information. Note that external users should
        likely never invoke the constructor directly and instead use either Keychain.new or
        Keychain.load.

        Args:
            You may design the constructor with any additional arguments you would like.
        Returns:
            None
        """
        ########## START CODE HERE ##########
        self.data = {
            # Store member variables that you intend to be public here
            # (i.e. information that will not compromise security if an adversary sees).
            # This data should be dumped by the Keychain.dump function.
            # You should store the key-value store (KVS) in the "kvs" item in this dictionary.
            "kvs": kvs if kvs is not None else {},
            "salt": salt,
        }
        self.secrets = {
            # Store member variables that you intend to be private here
            # (information that an adversary should NOT see).
            "key": key,
            "pw": password,
        }
        # raise NotImplementedError(
        #     "Delete this line once you've implemented the Keychain constructor (__init__)"
        # )
        ########### END CODE HERE ###########

    ########## START CODE HERE ##########
    # Add any helper functions you may want to add here

    ########### END CODE HERE ###########

    @staticmethod
    def new(keychain_password: str) -> "Keychain": # forward reference
        """
        Creates an empty keychain with the given keychain password.

        Args:
            keychain_password: the password to unlock the keychain
        Returns:
            A Keychain instance
        """
        ########## START CODE HERE ##########
        salt = get_random_bytes(16)
        password_bytes = str_to_bytes(keychain_password)

        # A byte string of length dkLen that can be used as key material.
        main_key = PBKDF2( 
            password=password_bytes, # The secret password to generate the key from.
            salt=salt, # A (byte) string to use for better protection from dictionary attacks.
            dkLen=32,  # cumulative length of the keys to produce, 32 for AES-256
            count=PBKDF2_ITERATIONS, # The number of iterations to carry out. 
            hmac_hash_module=SHA256
        )

        # derive hmac_key for encryption
        # TODO derive different keys from main_key
        hmac_obj = HMAC.new(main_key, digestmod=SHA256)
        cipher = AES.new(main_key, AES.MODE_EAX)

        keychain = Keychain(
            key = main_key,
            salt = salt,

        )  

        # Store salt in public data
        keychain.data["salt"] = encode_bytes(salt)

        return keychain
        ########### END CODE HERE ###########

    @staticmethod
    def load(
        keychain_password: str, repr: str, trusted_data_check: Optional[bytes] = None
    ) -> "Keychain":
        """
        Creates a new keychain from an existing key-value store.

        Loads the keychain state from the provided representation (repr). You can assume that
        the representation passed to load is well-formed (i.e., it will be a valid JSON object)
        and was generated from the Keychain.dump function.

        Use the provided `json_str_to_dict` function to convert a JSON string into a nested dictionary.

        Args:
            keychain_password: the password to unlock the keychain
            repr: a JSON-encoded serialization of the contents of the key-value store (string)
            trusted_data_check: an optional SHA-256 checksum of the KVS (bytes or None)
        Returns:
            A Keychain instance containing the data from repr
        Throws:
            ValueError: if the checksum is provided in trusted_data_check and the checksum check fails
            ValueError: if the provided keychain password is not correct for the repr (hint: this is
                thrown for you by HMAC.verify)
        """
        ########## START CODE HERE ##########
        # deserialzie the str to map, then use checksum to verify the content is authenticated
        # then regenerate the main_key from keychain_password and public data

        
        if trusted_data_check is not None:
            hash_obj = SHA256.new()
            hash_obj.update(str_to_bytes(repr))
            if hash_obj.digest() != trusted_data_check:
                raise ValueError("Checksum verification failed")
        
        data = json_str_to_dict(repr)
        print(f"data = {data}")

        salt = decode_bytes(data["salt"])
        password_bytes = str_to_bytes(keychain_password)
        main_key = PBKDF2(
            password=password_bytes,
            salt=salt,
            dkLen=32,
            count=PBKDF2_ITERATIONS,
            hmac_hash_module=SHA256
        )

        try:
            hmac_obj = HMAC.new(main_key, digestmod=SHA256)
            hmac_obj.update(salt)
            hmac_obj.verify(decode_bytes(data["tag"]))
        except ValueError:
            raise ValueError("Password verification failed")

        keychain = Keychain(
            key = main_key,
            salt = salt,
            kvs = data["kvs"],
        ) 
        
        return keychain
        ########### END CODE HERE ###########

    def dump(self) -> Tuple[str, bytes]:
        """
        Returns a JSON serialization and a checksum of the contents of the keychain that can be
        loaded back using the Keychain.load function.

        For testing purposes, please ensure that the JSON string you return contains the key
        'kvs' with your KVS dict as its value. The KVS should have one key per domain.

        Use the provided `dict_to_json_str` function to convert a nested dictionary into
        its JSON representation.

        Returns:
            A tuple consisting of (1) the JSON serialization of the contents, and (2) the SHA256
            checksum of the JSON serialization
        """
        ########## START CODE HERE ##########
        # Create an HMAC of the salt using our key
        hmac_obj = HMAC.new(self.secrets["key"], digestmod=SHA256)
        hmac_obj.update(decode_bytes(self.data["salt"]))
        verification_tag = encode_bytes(hmac_obj.digest())

        json = dict_to_json_str({
            "kvs": self.data["kvs"],
            "salt": self.data["salt"],
            "tag": verification_tag,
        })

        h = SHA256.new()
        h.update(str_to_bytes(json))
        checksum = h.digest()
        
        return json, checksum
        ########### END CODE HERE ###########

    def get(self, domain: str) -> Optional[str]:
        """
        Fetches the password corresponding to a given domain from the key-value store.

        Args:
            domain: the domain for which the password is requested
        Returns:
            The password for the domain if it exists in the KVS, or None if it does not exist
        """
        ########## START CODE HERE ##########
        hmac_obj = HMAC.new(self.secrets["key"], digestmod=SHA256)
        hmac_obj.update(str_to_bytes(domain))
        k = encode_bytes(hmac_obj.digest())

        if k in self.data["kvs"]:
            
            v = self.data["kvs"][k]
            ciphertext = decode_bytes(v['ct'])  
            tag = decode_bytes(v['tag'])
            nonce = decode_bytes(v['nonce'])

            cipher = AES.new(self.secrets["key"], AES.MODE_GCM, nonce=nonce)
            cipher.update(str_to_bytes(domain))
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return bytes_to_str(plaintext)
        return None
        ########### END CODE HERE ###########

    def set(self, domain: str, password: str):
        """
        Inserts the domain and password into the KVS. If the domain is already
        in the password manager, this will update the password for that domain.
        If it is not, a new entry in the password manager is created.

        Args:
            domain: the domain for the provided password. This domain may already exist in the KVS
            password: the password for the provided domain
        """
        ########## START CODE HERE ##########
        # store the hmac of domain
        hmac_obj = HMAC.new(self.secrets["key"], digestmod=SHA256)
        hmac_obj.update(str_to_bytes(domain))
        k = encode_bytes(hmac_obj.digest()) # Return the binary (non-printable) MAC tag of the message authenticated so far.

        # store the encryption of passward
        # wrong approach: use nonce = domain to bind the crypt(pw) with domain to def swap attack. That will 
        # lead to same domain+password will always encrypt to same ciphertext
        cipher = AES.new(self.secrets["key"], AES.MODE_GCM)
        cipher.update(str_to_bytes(domain))
        ciphertext, tag = cipher.encrypt_and_digest(str_to_bytes(password))
        v =  {
            "ct": encode_bytes(ciphertext),
            "tag": encode_bytes(tag),   
            "nonce": encode_bytes(cipher.nonce), 
        }

        self.data["kvs"][k] = v
        ########### END CODE HERE ###########

    def remove(self, domain: str) -> bool:
        """
        Removes the domain-password pair for the provided domain from the password manager.
        If the domain does not exist in the password manager, this method deos nothing.

        Args:
            domain: the domain which should be removed from the KVS, along with its password
        Returns:
            True if the domain existed in the KVS and was removed, False otherwise
        """
        ########## START CODE HERE ##########
        hmac_obj = HMAC.new(self.secrets["key"], digestmod=SHA256)
        hmac_obj.update(str_to_bytes(domain))
        k = encode_bytes(hmac_obj.digest())

        if k in self.data["kvs"]:
            del self.data["kvs"][k]
            return True
        return False
        ########### END CODE HERE ###########
