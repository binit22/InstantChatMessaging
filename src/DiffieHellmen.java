import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DiffieHellmen {

	static String UTF = "UTF-8";
	static String IV = "AAAAAAAAAAAAAAAA";
	static String encryptionKey = "0123456789abcdef";

	public static void main(String[] argv) throws Exception {

		String algo = "DiffieHellman"; // Change this to RSA, DSA ...
		// Generate a 1024-bit Digital Signature Algorithm
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algo);
		keyGenerator.initialize(512);
		KeyPair kpair = keyGenerator.genKeyPair();
		PublicKey priKey = kpair.getPublic();
		kpair = keyGenerator.genKeyPair();
		PublicKey pubKey = kpair.getPublic();

		// PublicKey pubKey = kpair.getPublic();
		String frm = priKey.getFormat();
		// System.out.println("Private key format :" + frm);
		// System.out.println("Diffie-Helman Private key parameters are:" +
		// priKey);
		// frm = pubKey.getFormat();
		// System.out.println("Public key format :" + frm);
		// System.out.println("Diffie-Helman Public key parameters are:" +
		// pubKey);

		AlgorithmParameterGenerator pgen = AlgorithmParameterGenerator
				.getInstance("DH");
		pgen.init(512);
		AlgorithmParameters params = pgen.generateParameters();
		DHParameterSpec dhspec = (DHParameterSpec) params
				.getParameterSpec(DHParameterSpec.class);
		KeyPairGenerator keypairgen = KeyPairGenerator.getInstance("DH");
		KeyPairGenerator keypairgen1 = KeyPairGenerator.getInstance("DH");

		keypairgen.initialize(dhspec);

		KeyPair keyPair = keypairgen.generateKeyPair();

		ByteArrayOutputStream b = new ByteArrayOutputStream();
		ObjectOutput o = null;
		o = new ObjectOutputStream(b);
		o.writeObject(dhspec.getG());
		byte[] by = b.toByteArray();

		o.close();
		b.close();

		ByteArrayInputStream bi = new ByteArrayInputStream(by);
		ObjectInput oi = new ObjectInputStream(bi);
		BigInteger g = (BigInteger) oi.readObject();
		PrivateKey pri = keyPair.getPrivate();
		DHParameterSpec dhspec1 = new DHParameterSpec(dhspec.getP(),
				g, dhspec.getL());
		keypairgen1.initialize(dhspec1);
		KeyPair keyPair1 = keypairgen1.generateKeyPair();

		System.out.println(Arrays.toString(pri.getEncoded()));
		System.out.println(Arrays.toString(keyPair1.getPrivate().getEncoded()));

		/*
		 * 
		 * String nulll = "\0"; StringBuffer plaintext = new
		 * StringBuffer("my name is shaha");//\0\0\0\0\0\0"; /*Note null padding
		 * 
		 * int len = plaintext.length() % 16; if(len != 0) for(int i = 0; i <
		 * 16-len; i++) plaintext.append(nulll); byte[] enc =
		 * encrypt(plaintext.toString(), encryptionKey);
		 * 
		 * String original = decrypt(enc, encryptionKey);
		 * System.out.println(original);
		 */
	}

	public static byte[] encrypt(String plainText, String encryptionKey)
			throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes(UTF),
				"AES");
		cipher.init(Cipher.ENCRYPT_MODE, key,
				new IvParameterSpec(IV.getBytes(UTF)));
		return cipher.doFinal(plainText.getBytes(UTF));
	}

	public static String decrypt(byte[] cipherText, String encryptionKey)
			throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
		SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes(UTF),
				"AES");
		cipher.init(Cipher.DECRYPT_MODE, key,
				new IvParameterSpec(IV.getBytes(UTF)));
		return new String(cipher.doFinal(cipherText), UTF).trim();
	}
}