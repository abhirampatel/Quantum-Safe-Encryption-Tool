from braket.circuits import Circuit
from braket.devices import LocalSimulator
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def simulate_qkd_bb84():
    device = LocalSimulator()
    circuit = Circuit()

    circuit.h(0)
    circuit.h(1)

    circuit.rx(0, 1.57)
    circuit.rx(1, 1.57)

    circuit.measure(0)
    circuit.measure(1)

    result = device.run(circuit, shots=100).result()
    counts = result.measurement_counts
    shared_key = "".join([key[0] for key in counts.keys()])[:32]
    return shared_key

def aes_encrypt(key, plaintext):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, iv, encryptor.tag

def aes_decrypt(key, ciphertext, iv, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def main():
    quantum_key = simulate_qkd_bb84()
    print("Starting Quantum Key Distribution (QKD)...")
    print(f"Quantum Key (Binary String): {quantum_key}")
    required_key_length = 256
    quantum_key_padded = quantum_key.ljust(required_key_length, '0')
    aes_key = bytes(int(quantum_key_padded[i:i+8], 2) for i in range(0, required_key_length, 8))
    print(f"AES Key (Derived from Quantum Key): {aes_key.hex()}")
    plaintext = b"Quantum-safe encryption example with Amazon Braket!"
    print(f"Plaintext: {plaintext}")
    ciphertext, iv, tag = aes_encrypt(aes_key, plaintext)
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"IV: {iv.hex()}")
    print(f"Tag: {tag.hex()}")
    decrypted_text = aes_decrypt(aes_key, ciphertext, iv, tag)
    print(f"Decrypted Text: {decrypted_text}")
    assert decrypted_text == plaintext, "Decryption failed: mismatch with original plaintext"
    print("Encryption and decryption were successful.")

if __name__ == "__main__":
    main()
