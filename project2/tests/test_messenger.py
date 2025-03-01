###############################################################################
# CS 255
# 1/12/25
# 
# test_messenger.py
# ______________
# Tests for MessengerClient defined in messenger.py
###############################################################################
import sys
import os
import unittest
import timeout_decorator
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from messenger import MessengerClient
from lib import (
    generate_ecdsa,
    generate_eg,
    sign_with_ecdsa,
    compute_dh,
    hmac_to_aes_key,
    decrypt_with_gcm,
    gov_encryption_data_str,
)


def stringify_cert(cert):
    return str(cert)

def gov_decrypt(secret, header_ct_tuple):
    header, ciphertext = header_ct_tuple
    # Ensure headers have "v_gov", "c_gov", and "iv_gov" field present to allow the gov to decrypt
    if "v_gov" not in header or "c_gov" not in header or "iv_gov" not in header:
        raise ValueError("Header must have the fields 'v_gov', 'c_gov', and 'iv_gov'")
    gov_key = compute_dh(secret, header["v_gov"])
    gov_key = hmac_to_aes_key(gov_key, gov_encryption_data_str)
    master_key = decrypt_with_gcm(gov_key, header["c_gov"], header["iv_gov"], decode_bytes=False)
    plaintext = decrypt_with_gcm(master_key, ciphertext, header["receiver_iv"], str(header))
    return plaintext


class TestFramework(unittest.TestCase):
    def setUp(self):
        # (this function runs at the start of every test)
        self.ca_key_pair = generate_ecdsa()
        self.gov_key_pair = generate_eg()
        self.alice = MessengerClient(self.ca_key_pair["public"], self.gov_key_pair["public"])
        self.bob = MessengerClient(self.ca_key_pair["public"], self.gov_key_pair["public"])
        self.claire = MessengerClient(self.ca_key_pair["public"], self.gov_key_pair["public"])
        self.dave = MessengerClient(self.ca_key_pair["public"], self.gov_key_pair["public"])
        self.alice_cert = self.alice.generate_certificate("alice")
        self.bob_cert = self.bob.generate_certificate("bob")

    @timeout_decorator.timeout(5)
    def test_import_certificate(self):  
        """
        Test: Alice successfully received Bob's certificate
        """
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.assertTrue(True)
        print("\nTest passed: Alice successfully received Bob's certificate.")

    @timeout_decorator.timeout(5)
    def test_gen_encrypted_message(self):
        """
        Test: Alice successfully sent a message
        """     
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.alice.send_message("bob", "Hello, Bob")
        self.assertTrue(True)
        print("\nTest passed: Alice successfully sent a message.")

    @timeout_decorator.timeout(5)
    def test_receive_encrypted_message(self):
        """
        Test: Bob successfully decrypted message
        """
        alice_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.alice_cert))
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.bob.receive_certificate(self.alice_cert, alice_cert_signature)
        message = "Hello, Bob"
        ciphertext = self.alice.send_message("bob", message)
        plaintext = self.bob.receive_message("alice", ciphertext)
        self.assertEqual(plaintext, message)
        print("\nTest passed: Bob successfully decrypted message.")

    @timeout_decorator.timeout(5)
    def test_conversation(self):
        """
        Test: Alice and Bob can have a conversations
        """
        alice_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.alice_cert))
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.bob.receive_certificate(self.alice_cert, alice_cert_signature)
        # Ensure Bob can receive Alice's message
        message_from_alice = "Hello, Bob"
        ciphertext_from_alice = self.alice.send_message("bob", message_from_alice)
        plaintext_from_alice = self.bob.receive_message("alice", ciphertext_from_alice)
        self.assertEqual(plaintext_from_alice, message_from_alice)
        # Ensure Alice can receive Bob's 1st message
        message_from_bob_1 = "Hello, Alice"
        ciphertext_from_bob_1 = self.bob.send_message("alice", message_from_bob_1)
        plaintext_from_bob_1 = self.alice.receive_message("bob", ciphertext_from_bob_1)
        self.assertEqual(plaintext_from_bob_1, message_from_bob_1)
        # Ensure Alice can receive Bob's 2nd message
        message_from_bob_2 = "Meet for lunch?"
        ciphertext_from_bob_2 = self.bob.send_message("alice", message_from_bob_2)
        plaintext_from_bob_2 = self.alice.receive_message("bob", ciphertext_from_bob_2)
        self.assertEqual(plaintext_from_bob_2, message_from_bob_2)
        print("\nTest passed: Alice and Bob can have a conversation.")

    @timeout_decorator.timeout(5)
    def test_government_can_decrypt(self):
        """
        Test: Government can decrypt message from Alice to Bob
        """
        alice_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.alice_cert))
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.bob.receive_certificate(self.alice_cert, alice_cert_signature)
        message = "Hello, Bob"
        ciphertext = self.alice.send_message("bob", message)
        decrypted_message = gov_decrypt(self.gov_key_pair["private"], ciphertext)
        self.assertEqual(decrypted_message, message)
        print("\nTest passed: Government can decrypt message from Alice to Bob.")

    @timeout_decorator.timeout(5)
    def test_invalid_certificates_are_rejected(self):
        """
        Test: Invalid certificates are rejected
        """
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        invalid_signature = sign_with_ecdsa(self.ca_key_pair["private"], "fake_signature")
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        with self.assertRaises(ValueError) as context:
            self.alice.receive_certificate(self.bob_cert, invalid_signature)
        self.assertEqual(str(context.exception), "Tampering detected!")
        print("\nTest passed: Invalid certificates are rejected.")

    @timeout_decorator.timeout(5)
    def test_message_replay_attack_detected(self):
        """
        Test: Message replay attacks are detected
        """
        alice_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.alice_cert))
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.bob.receive_certificate(self.alice_cert, alice_cert_signature)
        message = "Hello, Bob"
        ciphertext = self.alice.send_message("bob", message)
        plaintext = self.bob.receive_message("alice", ciphertext)
        with self.assertRaises(Exception):
            self.bob.receive_message("alice", ciphertext)
        print("\nTest passed: Message replay attacks are detected.")

    @timeout_decorator.timeout(5) 
    def test_alice_reject_messages_not_intended_recipient(self):
        """
        Test: Alice rejects messages where she is not the intended recipient
        """
        claire_cert = self.claire.generate_certificate("claire")
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        claire_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(claire_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.alice.receive_certificate(claire_cert, claire_cert_signature)
        self.bob.receive_certificate(claire_cert, claire_cert_signature)
        message = "Hello, Claire"
        ciphertext = self.bob.send_message("claire", message)
        with self.assertRaises(Exception):
            self.alice.receive_message("claire", ciphertext)
        print("\nTest passed: Alice rejects messages where she is not the intended recipient.")

    @timeout_decorator.timeout(5)
    def test_alice_send_bob_stream_messages_with_no_response(self):
        """
        Test: Alice can send bob several messages with no response
        """
        alice_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.alice_cert))
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.bob.receive_certificate(self.alice_cert, alice_cert_signature)
        message = "Hello Bob"
        ciphertext = self.alice.send_message("bob", message)
        decrypted_message = self.bob.receive_message("alice", ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Hello Bob!"
        ciphertext = self.alice.send_message("bob", message)
        decrypted_message = self.bob.receive_message("alice", ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Are you even listening to me Bob?"
        ciphertext = self.alice.send_message("bob", message)
        decrypted_message = self.bob.receive_message("alice", ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "BOB ARE YOU LISTENING TO ME??"
        ciphertext = self.alice.send_message("bob", message)
        decrypted_message = self.bob.receive_message("alice", ciphertext)
        self.assertEqual(decrypted_message, message)
        print("\nTest passed: Alice can send bob several messages with no response.")

    @timeout_decorator.timeout(5)
    def test_alice_send_bob_stream_messages_with_infrequent_response(self):
        """
        Test: Alice can send bob several messages with infrequent response
        """
        alice_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.alice_cert))
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.bob.receive_certificate(self.alice_cert, alice_cert_signature)
        for i in range(2):
            for j in range(4):
                message = f"message {j}"
                ciphertext = self.alice.send_message("bob", message) 
                decrypted_message = self.bob.receive_message("alice", ciphertext)
                self.assertEqual(decrypted_message, message)
            message = f"roger {i}"
            ciphertext = self.bob.send_message("alice", message) 
            decrypted_message = self.alice.receive_message("bob", ciphertext)
            self.assertEqual(decrypted_message, message)
        print("\nTest passed: Alice can send bob several messages with infrequent response.")

    @timeout_decorator.timeout(5)
    def test_alice_receive_multiple_certificates(self):
        """
        Test: Alice can receive several certificates
        """
        claire_cert = self.claire.generate_certificate("claire")
        alice_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.alice_cert))
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        claire_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(claire_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.alice.receive_certificate(claire_cert, claire_cert_signature)
        print("\nTest passed: Alice can receive several certificates.")

    @timeout_decorator.timeout(5)
    def test_alice_send_messages_multiple_parties(self):
        """
        Test: Alice can send messages to several people
        """
        claire_cert = self.claire.generate_certificate("claire")
        alice_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.alice_cert))
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        claire_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(claire_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.alice.receive_certificate(claire_cert, claire_cert_signature)
        self.bob.receive_certificate(self.alice_cert, alice_cert_signature)
        self.claire.receive_certificate(self.alice_cert, alice_cert_signature)
        message = "Hello, Bob"
        ciphertext = self.alice.send_message("bob", message)
        decrypted_message = self.bob.receive_message("alice", ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Hello, Claire"
        ciphertext = self.alice.send_message("claire", message)
        decrypted_message = self.claire.receive_message("alice", ciphertext)
        self.assertEqual(decrypted_message, message)
        print("\nTest passed: Alice can send messages to several people.")

    @timeout_decorator.timeout(5)
    def test_alice_receive_messages_multiple_parties(self):
        """
        Test: Alice can receive messages from several people
        """
        claire_cert = self.claire.generate_certificate("claire")
        alice_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.alice_cert))
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        claire_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(claire_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.alice.receive_certificate(claire_cert, claire_cert_signature)
        self.bob.receive_certificate(self.alice_cert, alice_cert_signature)
        self.claire.receive_certificate(self.alice_cert, alice_cert_signature)
        message = "Hello, Alice"
        ciphertext = self.bob.send_message("alice", message)
        decrypted_message = self.alice.receive_message("bob", ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Hello, Alice"
        ciphertext = self.claire.send_message("alice", message)
        decrypted_message = self.alice.receive_message("claire", ciphertext)
        self.assertEqual(decrypted_message, message)
        print("\nTest passed: Alice can receive messages from several people.")

    @timeout_decorator.timeout(5)
    def test_alice_initiate_convo_as_first_sender_another_as_first_receiver(self):
        """
        Test: Alice can start a convo and can receive a convo
        """
        claire_cert = self.claire.generate_certificate("claire")
        alice_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.alice_cert))
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        claire_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(claire_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.alice.receive_certificate(claire_cert, claire_cert_signature)
        self.bob.receive_certificate(self.alice_cert, alice_cert_signature)
        self.claire.receive_certificate(self.alice_cert, alice_cert_signature)
        message = "Hello, Bob"
        ciphertext = self.alice.send_message("bob", message)
        decrypted_message = self.bob.receive_message("alice", ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Hello, Alice"
        ciphertext = self.claire.send_message("alice", message)
        decrypted_message = self.alice.receive_message("claire", ciphertext)
        self.assertEqual(decrypted_message, message)
        print("\nTest passed: Alice can start a convo and can receive a convo.")

    @timeout_decorator.timeout(5)
    def test_alice_can_have_multiple_simultaneous_convos(self):
        """
        Test: Alice can have several simultaneous conversations
        """
        claire_cert = self.claire.generate_certificate("claire")
        dave_cert = self.dave.generate_certificate("dave")
        alice_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.alice_cert))
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        claire_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(claire_cert))
        dave_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(dave_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.alice.receive_certificate(claire_cert, claire_cert_signature)
        self.alice.receive_certificate(dave_cert, dave_cert_signature)
        self.bob.receive_certificate(self.alice_cert, alice_cert_signature)
        self.claire.receive_certificate(self.alice_cert, alice_cert_signature)
        self.dave.receive_certificate(self.alice_cert, alice_cert_signature)
        message = "Hello, Bob"
        ciphertext = self.alice.send_message("bob", message)
        decrypted_message = self.bob.receive_message("alice", ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Hello, Claire"
        ciphertext = self.alice.send_message("claire", message)
        decrypted_message = self.claire.receive_message("alice", ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Hello, Dave"
        ciphertext = self.alice.send_message("dave", message)
        decrypted_message = self.dave.receive_message("alice", ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Hello, Alice"
        ciphertext = self.bob.send_message("alice", message)
        decrypted_message = self.alice.receive_message("bob", ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Hello, Alice"
        ciphertext = self.claire.send_message("alice", message)
        decrypted_message = self.alice.receive_message("claire", ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Hello, Alice"
        ciphertext = self.dave.send_message("alice", message)
        decrypted_message = self.alice.receive_message("dave", ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Meet for lunch?"
        ciphertext = self.bob.send_message("alice", message)
        decrypted_message = self.alice.receive_message("bob", ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Meet for lunch?"
        ciphertext = self.claire.send_message("alice", message)
        decrypted_message = self.alice.receive_message("claire", ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Meet for lunch?"
        ciphertext = self.dave.send_message("alice", message)
        decrypted_message = self.alice.receive_message("dave", ciphertext)
        self.assertEqual(decrypted_message, message)
        print("\nTest passed: Alice can have several simultaneous conversations.")

    @timeout_decorator.timeout(5)
    def test_gov_can_decrypt_simultaneous_convos(self):
        """
        Test: Government can decrypt several simultaneous conversations
        """
        claire_cert = self.claire.generate_certificate("claire")
        dave_cert = self.dave.generate_certificate("dave")
        alice_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.alice_cert))
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        claire_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(claire_cert))
        dave_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(dave_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.alice.receive_certificate(claire_cert, claire_cert_signature)
        self.alice.receive_certificate(dave_cert, dave_cert_signature)
        self.bob.receive_certificate(self.alice_cert, alice_cert_signature)
        self.claire.receive_certificate(self.alice_cert, alice_cert_signature)
        self.dave.receive_certificate(self.alice_cert, alice_cert_signature)
        message = "Hello, Bob"
        ciphertext = self.alice.send_message("bob", message)
        self.bob.receive_message("alice", ciphertext)
        decrypted_message = gov_decrypt(self.gov_key_pair["private"], ciphertext)
        self.assertEqual(decrypted_message, message)
        self.assertEqual(decrypted_message, message)
        message = "Hello, Claire"
        ciphertext = self.alice.send_message("claire", message)
        self.claire.receive_message("alice", ciphertext)
        decrypted_message = gov_decrypt(self.gov_key_pair["private"], ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Hello, Dave"
        ciphertext = self.alice.send_message("dave", message)
        self.dave.receive_message("alice", ciphertext)
        decrypted_message = gov_decrypt(self.gov_key_pair["private"], ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Hello, Alice"
        ciphertext = self.bob.send_message("alice", message)
        self.alice.receive_message("bob", ciphertext)
        decrypted_message = gov_decrypt(self.gov_key_pair["private"], ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Hello, Alice"
        ciphertext = self.claire.send_message("alice", message)
        self.alice.receive_message("claire", ciphertext)
        decrypted_message = gov_decrypt(self.gov_key_pair["private"], ciphertext)
        self.assertEqual(decrypted_message, message)
        message = "Hello, Alice"
        ciphertext = self.dave.send_message("alice", message)
        self.alice.receive_message("dave", ciphertext)
        decrypted_message = gov_decrypt(self.gov_key_pair["private"], ciphertext)
        self.assertEqual(decrypted_message, message)
        print("\nTest passed: Government can decrypt several simultaneous conversations.")

    @timeout_decorator.timeout(5)
    def test_handles_shuffled_messages_in_single_stream(self):
        """
        Test: Bob can handle shuffled messages
        """
        alice_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.alice_cert))
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.bob.receive_certificate(self.alice_cert, alice_cert_signature)
        message1 = "message 1"
        ciphertext1 = self.alice.send_message("bob", message1)
        message2 = "message 2"
        ciphertext2 = self.alice.send_message("bob", message2)
        message3 = "message 3"
        ciphertext3 = self.alice.send_message("bob", message3)
        result1 = self.bob.receive_message("alice", ciphertext1)
        self.assertEqual(message1, result1)
        result2 = self.bob.receive_message("alice", ciphertext2)
        self.assertEqual(message2, result2)
        result3 = self.bob.receive_message("alice", ciphertext3)
        self.assertEqual(message3, result3)
        print("\nTest passed: Bob can handle shuffled messages.")

    @timeout_decorator.timeout(5)
    def test_handles_where_shuffling_occurs_around_DH_ratchet_steps(self):
        """
        Test: Handles messages where shuffling occurs around DH ratchet steps
        """
        alice_cert_signature =  sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.alice_cert))
        bob_cert_signature = sign_with_ecdsa(self.ca_key_pair["private"], stringify_cert(self.bob_cert))
        self.alice.receive_certificate(self.bob_cert, bob_cert_signature)
        self.bob.receive_certificate(self.alice_cert, alice_cert_signature)
        message1 = "message 1"
        ciphertext1 = self.alice.send_message("bob", message1)
        message2 = "message 2"
        ciphertext2 = self.alice.send_message("bob", message2)
        result1 = self.bob.receive_message("alice", ciphertext1)
        self.assertEqual(message1, result1)
        message = "DH ratchet"
        ciphertext = self.bob.send_message("alice", message)
        result = self.alice.receive_message("bob", ciphertext)
        self.assertEqual(message, result)
        message3 = "message 3"
        ciphertext3 = self.alice.send_message("bob", message3)
        result2 = self.bob.receive_message("alice", ciphertext2)
        self.assertEqual(message2, result2)
        result3 = self.bob.receive_message("alice", ciphertext3)
        self.assertEqual(message3, result3)
        print("\nTest passed: Handles messages where shuffling occurs around DH ratchet steps.")


if __name__ == "__main__":
    try:
        result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(TestFramework))
        if result.wasSuccessful():
            print("\nAll tests passed successfully!")
        else:
            print(f"\nSome tests failed. Failures: {len(result.failures)}, Errors: {len(result.errors)}")
    except SystemExit as e:
        print(f"Test execution terminated with exit code: {e.code}")