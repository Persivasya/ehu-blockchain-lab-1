package com.example;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class App {
  static final List<String> CANDIDATE_KEYS = List.of(
      "174f2d1a16fde76dee842c90f126aab9",
      "95ce2d1a16fde76dee842c90f126aab9",
      "95ce2d1a1691906dee842c90f126aab9");

  static final String TARGET_HASH = "26249de240f5479bee4b2b20c25bed94cd76d8c7b95708ce39a8f603545b1b88";

  static final String CIPHERTEXT_HEX = "d818117c21fa8ca1316a6698f0dba8eb7fbca565883755231973a6cd527d795c"
      + "3a604e1eb868fb625faf8811f3102c0e";
  static final String IV_HEX = "8dddd8975a61ff0ec359130f28fa218c";

  private static final HexFormat HEX = HexFormat.of();

  public static void main(String[] args) throws Exception {
    // identify key
    byte[] key = findKeyByHash(CANDIDATE_KEYS, TARGET_HASH);
    System.out.println("Key: " + HEX.formatHex(key));

    // decrypt
    String plaintext = decrypt(key, HEX.parseHex(IV_HEX), HEX.parseHex(CIPHERTEXT_HEX));
    System.out.println("Decrypted message: " + plaintext);

    // generate an Elliptic Curve key pair
    KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
    gen.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair pair = gen.generateKeyPair();
    System.out.println("Public key (X.509/DER, Base64): "
        + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
    System.out.println("ublic key (uncompressed point, HEX): "
        + uncompressedPoint((ECPublicKey) pair.getPublic()));

    // Sign the origina plaintext and verify the signature
    byte[] signature = sign(pair, plaintext);
    System.out.println("Signature (ECDSA/SHA-256, DER, HEX): " + HEX.formatHex(signature));
    System.out.println("Signature valid: " + verify(pair.getPublic(), plaintext, signature));
  }

  static byte[] findKeyByHash(List<String> candidates, String expectedHashHex) throws Exception {
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    for (String candidate : candidates) {
      byte[] keyBytes = HEX.parseHex(candidate);
      String hash = HEX.formatHex(sha256.digest(keyBytes));
      boolean match = hash.equalsIgnoreCase(expectedHashHex);
      if (match) {
        return keyBytes;
      }
    }
    throw new IllegalStateException("No candidate key matches the given hash");
  }

  static String decrypt(byte[] key, byte[] iv, byte[] ciphertext) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
  }

  static byte[] sign(KeyPair pair, String message) throws Exception {
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(pair.getPrivate());
    signer.update(message.getBytes(StandardCharsets.UTF_8));
    return signer.sign();
  }

  static boolean verify(PublicKey publicKey, String message, byte[] signature) throws Exception {
    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(publicKey);
    verifier.update(message.getBytes(StandardCharsets.UTF_8));
    return verifier.verify(signature);
  }

  static String uncompressedPoint(ECPublicKey key) {
    return "04" + pad32(key.getW().getAffineX().toByteArray())
        + pad32(key.getW().getAffineY().toByteArray());
  }

  private static String pad32(byte[] b) {
    byte[] out = new byte[32];
    int len = Math.min(b.length, 32);
    System.arraycopy(b, b.length - len, out, 32 - len, len);
    return HEX.formatHex(out);
  }
}
