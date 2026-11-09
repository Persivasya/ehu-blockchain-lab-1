## Output

![Program output](output.png)

As text:
Key: 95ce2d1a16fde76dee842c90f126aab9
Decrypted message: Consensus keeps the ledger honest
Public key (X.509/DER, Base64): MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE270CCVQGl1OA3NPjHMG90EiIxesyi1NWHcX1ooda/JBiFgVNQH9eq5zAUXm2FVD9gbvgGTBop4AL/YBwJT3vdw==
ublic key (uncompressed point, HEX): 04dbbd02095406975380dcd3e31cc1bdd04888c5eb328b53561dc5f5a2875afc906216054d407f5eab9cc05179b61550fd81bbe0193068a7800bfd8070253def77
Signature (ECDSA/SHA-256, DER, HEX): 3045022100a07675a4de43a32547ab91e12a27bb8d94036cebc0f13286abab3a98602a14b30220297fa51c01291baae8c55b5e0a3836371ab7f88159fe6b9bb8c0decb47b81404
Signature valid: true

## Key identification

1. Take the list of candidate AES-128 keys and the expected SHA-256 hash.
2. For each candidate, decode the hex string into 16 raw bytes.
3. Compute the SHA-256 digest of those bytes and format it as hex.
4. Compare the digest with the expected hash.
5. Pick the candidate with matching didgest.

## Decryption

1. Decode the ciphertext and the IV from hex into bytes.
2. Create an `AES/CBC/PKCS5Padding` cipher in decrypt mode, initialised with the identified key and the 16-byte IV.
3. Decode bytes as UTF-8.
