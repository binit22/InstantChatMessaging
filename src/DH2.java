import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DH2 {
	String abc;
	////
	//ldlas
	public static void main(String args[]) throws NoSuchAlgorithmException,
	InvalidParameterSpecException, InvalidAlgorithmParameterException,
	InvalidKeyException, IllegalStateException, NoSuchPaddingException,
	IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {

		String algo = "DH"; // Change this to RSA, DSA ...
		// Generate a 1024-bit Digital Signature Algorithm
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algo);
		keyGenerator.initialize(1024);

		//KeyPairGenerator keyGenerator = (KeyPairGenerator)oi.readObject();



		KeyPair kpair = keyGenerator.genKeyPair();
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		ObjectOutput o = null;
		o = new ObjectOutputStream(b);
		o.writeObject(kpair);
		byte[] by = b.toByteArray();

		o.close();
		b.close();

		ByteArrayInputStream bi = new ByteArrayInputStream(by);
		ObjectInput oi = new ObjectInputStream(bi);
		KeyPair kpair1=(KeyPair) oi.readObject();
		//	KeyPair kpair1 = keyGenerator.genKeyPair();

		PrivateKey priKey = kpair.getPrivate();
		// kpair = keyGenerator.genKeyPair();
		PrivateKey priKey1 = kpair1.getPrivate();

		PublicKey pubKey1 = kpair1.getPublic();
		PublicKey pubKey = kpair.getPublic();
		System.out.println(priKey1);
		System.out.println(priKey);

		SecretKeySpec secret_alice = combine(priKey1, pubKey);

		SecretKeySpec secret_bob = combine(priKey, pubKey1);

		System.out.println(Arrays.toString(secret_alice.getEncoded()));
		System.out.println(Arrays.toString(secret_bob.getEncoded()));

		byte shavalue[] = genSHA256(secret_alice.getEncoded());
		SecretKeySpec key = new SecretKeySpec(shavalue, "AES");
		// System.out.println(Arrays.toString(key.getEncoded()));

		String input1 = "hello";
		byte[] input = input1.getBytes();
		Cipher cipher = Cipher.getInstance("AES");
		System.out.println(new String(input));
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedMessageInBytes = cipher.doFinal(input1.getBytes());

		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedTextBytes = cipher.doFinal(encryptedMessageInBytes);
		System.out.println(new String(decryptedTextBytes));	}

	private static SecretKeySpec combine(PrivateKey private1, PublicKey public1)
			throws NoSuchAlgorithmException, InvalidKeyException,
			IllegalStateException {
		KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
		ka.init(private1);
		ka.doPhase(public1, true);
		byte[] alice_secret = ka.generateSecret();
		SecretKeySpec aes = new SecretKeySpec(alice_secret, "AES");
		return aes;

	}

	public static byte[] genSHA256(byte[] original)
			throws NoSuchAlgorithmException {

		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(original);
		byte[] digest = md.digest();

		return digest;
	}

}
