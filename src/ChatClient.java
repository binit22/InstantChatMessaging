import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ChatClient extends Thread {
	// default values
	public final static int size = 2048;
	public final static String SEMICOLON = ";;";
	public final static int pValue = 47;
	public final static int gValue = 71;
	public static String myUserName = null;
	// change these as command line arguments if different
	public static int PORT = 7000;
	public static String serverIP = "glados.cs.rit.edu";
	public static int serverPort = 5000;

	public static DatagramSocket server = null;

	public String type;
	public String toUser;
	public boolean startSend = true;

	private static PrivateKey privateKey;
	private static Object verify = new Object();
	private static String userExists = "false";

	// username, secret key
	public static Map<String, SecretKeySpec> secretKey = new HashMap<String, SecretKeySpec>();

	// start chat client
	public ChatClient(String type, String serverIP) throws IOException {
		try {
			this.type = type;

			// writeKeys();
			ChatClient.serverIP = serverIP;
			if (server == null) {
				server = new DatagramSocket(PORT);
				server.setReuseAddress(true);
			}

		} catch (SocketException e) {
			e.printStackTrace();
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	// send public key
	private void sendPublicKey() {

		byte[] sendData = null;
		DatagramPacket packet = null;
		InetAddress IPAddress = null;
		KeyPair keyPair = null;

		try {
			IPAddress = InetAddress.getByName(serverIP);

			sendData = new byte[size];
			sendData = "initialkey".getBytes();
			packet = new DatagramPacket(sendData, sendData.length, IPAddress,
					serverPort);
			server.send(packet);
			// generating p, g and public key
			BigInteger p = new BigInteger(Integer.toString(pValue));
			BigInteger g = new BigInteger(Integer.toString(gValue));
			int bitLength = 512; // 512 bits
			SecureRandom rnd = new SecureRandom();
			p = BigInteger.probablePrime(bitLength, rnd);
			g = BigInteger.probablePrime(bitLength, rnd);

			DHParameterSpec param = new DHParameterSpec(p, g);
			KeyPairGenerator kpg = KeyPairGenerator
					.getInstance("DiffieHellman");
			kpg.initialize(param);
			keyPair = kpg.generateKeyPair();
			// generate key pair
			ArrayList key = new ArrayList();

			// send other username, p, g and public key to server
			key.add(this.toUser);

			key.add(p);
			key.add(g);
			key.add(keyPair.getPublic());

			ByteArrayOutputStream b = new ByteArrayOutputStream();
			ObjectOutput o = null;
			o = new ObjectOutputStream(b);
			o.writeObject(key);
			byte[] by = b.toByteArray();

			o.close();
			b.close();

			sendData = by;
			packet = new DatagramPacket(sendData, sendData.length, IPAddress,
					serverPort);
			server.send(packet);

			privateKey = keyPair.getPrivate();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	// for sending messages
	public void send() {

		byte[] sendData = null;
		DatagramPacket packet = null;
		String sendMsg = "";
		InetAddress IPAddress = null;

		try {
			BufferedReader inFromUser = new BufferedReader(
					new InputStreamReader(System.in));

			System.out.println("Start sending messages");
			while (true) {
				// user to send to
				while (true) {
					System.out.print("\nsend to? ");
					String toUsername = inFromUser.readLine();
					readKeys();
					// get the key for that user otherwise generate one
					if (!secretKey.containsKey(toUsername)) {
						if (this.userExists(toUsername)) {
							this.toUser = toUsername;

							if (this.startSend) {
								readKeys();
								// send public key to other client and set
								// own
								// private key
								sendPublicKey();
								this.startSend = false;
							}
							break;

						} else {
							System.out.println("invalid user!");
							continue;
						}
					} else {
						this.toUser = toUsername;
						break;
					}
				}
				// message to send
				System.out.print("\nmessage? ");
				sendMsg = inFromUser.readLine();

				sendData = "message".getBytes();
				IPAddress = InetAddress.getByName(serverIP);
				packet = new DatagramPacket(sendData, sendData.length,
						IPAddress, serverPort);
				server.send(packet);
				// encrypt message and send based on secret key that is
				// generated
				readKeys();
				byte[] eMsg = encrypt(sendMsg, secretKey.get(this.toUser));

				ArrayList toSend = new ArrayList();
				toSend.add(this.toUser);
				toSend.add(eMsg);
				// System.out.println("byte encrypt : "+eMsg);

				ByteArrayOutputStream b = new ByteArrayOutputStream();
				ObjectOutput o = null;
				o = new ObjectOutputStream(b);
				o.writeObject(toSend);
				byte[] by = b.toByteArray();
				o.close();
				b.close();

				sendData = by;
				IPAddress = InetAddress.getByName(serverIP);
				packet = new DatagramPacket(sendData, sendData.length,
						IPAddress, serverPort);
				server.send(packet);
			}

		} catch (IOException ex) {
			ex.printStackTrace();
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {
			if (server != null)
				server.close();
		}
	}

	// receiving messages
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public String receive() {
		String message = "";
		try {

			byte[] receiveData = null;
			DatagramPacket packet = null;
			InetAddress IPAddress = InetAddress.getByName(serverIP);

			while (true) {
				receiveData = new byte[size];
				packet = new DatagramPacket(receiveData, receiveData.length);
				server.receive(packet);

				// message command received from either client or server or
				// bootstrap
				message = new String(packet.getData()).trim();
				// receive other users public key and time to make your own key
				if (message.contains("publickey1")) {
					receiveData = new byte[size];
					packet = new DatagramPacket(receiveData, receiveData.length);
					server.receive(packet);

					ByteArrayInputStream bi = new ByteArrayInputStream(
							receiveData);
					ObjectInput oi = new ObjectInputStream(bi);

					ArrayList ar = (ArrayList) oi.readObject();
					String user = (String) ar.get(0);
					BigInteger p = (BigInteger) ar.get(1);
					BigInteger g = (BigInteger) ar.get(2);
					PublicKey otherPublicKey = (PublicKey) ar.get(3);
					// make your own public key
					DHParameterSpec param = new DHParameterSpec(p, g);
					KeyPairGenerator kpg = KeyPairGenerator
							.getInstance("DiffieHellman");
					kpg.initialize(param);
					KeyPair kp = kpg.generateKeyPair();
					PrivateKey myPrivateKey = kp.getPrivate();

					// send
					byte[] sendData = new byte[size];
					sendData = "nextkey".getBytes();
					packet = new DatagramPacket(sendData, sendData.length,
							IPAddress, serverPort);
					server.send(packet);

					ArrayList key2 = new ArrayList();
					key2.add(user);
					key2.add(kp.getPublic());

					ByteArrayOutputStream b = new ByteArrayOutputStream();
					ObjectOutput o = null;
					o = new ObjectOutputStream(b);
					o.writeObject(key2);
					byte[] by = b.toByteArray();

					o.close();
					b.close();

					sendData = by;
					packet = new DatagramPacket(sendData, sendData.length,
							IPAddress, serverPort);
					server.send(packet);

					SecretKeySpec secretKey = combine(myPrivateKey,
							otherPublicKey);

					// generated secret key with that user
					System.out.println("\nsecret key: "
							+ Arrays.toString(secretKey.getEncoded())
							+ " \n of " + user + " \n");

					readKeys();
					ChatClient.secretKey.put(user, secretKey);
					writeKeys();

				}
				// public key of other user
				else if (message.contains("publickey2")) {
					receiveData = new byte[size];
					packet = new DatagramPacket(receiveData, receiveData.length);
					server.receive(packet);

					ByteArrayInputStream bi = new ByteArrayInputStream(
							receiveData);
					ObjectInput oi = new ObjectInputStream(bi);

					ArrayList ar = (ArrayList) oi.readObject();

					String user = (String) ar.get(0);
					PublicKey otherPublicKey = (PublicKey) ar.get(1);
					// generate secret based on the other public key and your
					// public key
					SecretKeySpec secretKey = combine(privateKey,
							otherPublicKey);
					System.out.println("secret key:: "
							+ Arrays.toString(secretKey.getEncoded()));

					readKeys();
					ChatClient.secretKey.put(user, secretKey);
					writeKeys();

				}
				// if message is received
				else if (message.contains("message")) {

					receiveData = new byte[size];
					packet = new DatagramPacket(receiveData, receiveData.length);
					server.receive(packet);

					ByteArrayInputStream bi = new ByteArrayInputStream(
							receiveData);
					ObjectInput oi = new ObjectInputStream(bi);
					ArrayList ar = (ArrayList) oi.readObject();

					readKeys();
					// decrypt it and print it
					String msg = decrypt((byte[]) ar.get(1),
							secretKey.get(ar.get(0)));
					System.out.println("\n" + ar.get(0) + ": " + msg);
				}
				// to verify user
				else if (message.contains("verified")) {
					synchronized (verify) {
						receiveData = new byte[size];
						packet = new DatagramPacket(receiveData,
								receiveData.length);
						server.receive(packet);

						userExists = new String(packet.getData()).trim();
						verify.notify();
					}
				}
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {
		}
		return message;
	}

	// to create secrey key by combindign other's public key and your private
	// key
	private SecretKeySpec combine(PrivateKey private1, PublicKey public1)
			throws NoSuchAlgorithmException, InvalidKeyException,
			IllegalStateException {

		KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
		ka.init(private1);
		ka.doPhase(public1, true);
		byte[] newsecret = ka.generateSecret();

		SecretKeySpec aes = new SecretKeySpec(newsecret, "AES");

		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(aes.getEncoded());
		byte[] digest = md.digest();
		SecretKeySpec key = new SecretKeySpec(digest, "AES");

		return key;
	}

	// sha256 on the password
	public String genSHA256(String original) throws NoSuchAlgorithmException {

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(original.getBytes());
		byte[] digest = md.digest();
		StringBuffer sb = new StringBuffer();
		for (byte b : digest) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	// to verify username and password from server
	public boolean verifyUser(String username, String password) {

		String reply = null;
		byte[] data = null;
		DatagramPacket packet = null;

		try {
			InetAddress IPAddress = InetAddress.getByName(serverIP);

			data = new byte[size];
			data = ("authenticate" + SEMICOLON + username + SEMICOLON + password)
					.getBytes();
			packet = new DatagramPacket(data, data.length, IPAddress,
					serverPort);
			server.send(packet);

			data = new byte[size];
			packet = new DatagramPacket(data, data.length);
			server.receive(packet);

			reply = new String(packet.getData()).trim();

		} catch (IOException ex) {
			ex.printStackTrace();
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		if ("true".equals(reply))
			return true;
		else
			return false;
	}

	// check if user exists from server
	public boolean userExists(String username) {

		byte[] data = null;
		DatagramPacket packet = null;
		try {
			synchronized (verify) {
				InetAddress IPAddress = InetAddress.getByName(serverIP);

				data = new byte[size];
				data = ("verify" + SEMICOLON + username).getBytes();
				packet = new DatagramPacket(data, data.length, IPAddress,
						serverPort);
				server.send(packet);

				verify.wait();
			}
			System.out.println(userExists);
		} catch (IOException ex) {
			ex.printStackTrace();
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		if ("true".equals(userExists))
			return true;
		else
			return false;
	}

	public void run() {
		if ("send".equals(this.type))
			this.send();
		else
			this.receive();
	}

	// encrypt string to bytes with AES key
	public byte[] encrypt(String input, SecretKeySpec key)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		Cipher cipher = Cipher.getInstance("AES");

		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedMessageInBytes = cipher.doFinal(input.getBytes());
		return encryptedMessageInBytes;
	}

	// decrypt message in bytes to string with AES secret key
	public String decrypt(byte[] encryptedMessageInBytes, SecretKeySpec key)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		Cipher cipher = Cipher.getInstance("AES");

		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedTextBytes = cipher.doFinal(encryptedMessageInBytes);
		return new String(decryptedTextBytes);
	}

	// usage message
	public static void usage() {
		System.err.println("java ChatClient SERVERADDRESS");
		System.err
				.println("If no SERVERADDRESS specified, default will be taken.");
		throw new IllegalArgumentException();
	}

	// main function
	public static void main(String[] args) {
		try {

			if (args.length == 1)
				serverIP = args[0];
			if (args.length > 1)
				usage();

			ChatClient clientSend = new ChatClient("send", serverIP);
			ChatClient clientReceive = new ChatClient("receive", serverIP);

			BufferedReader inFromUser = new BufferedReader(
					new InputStreamReader(System.in));

			while (true) {
				System.out.print("username :");
				String username = inFromUser.readLine();
				String password;
				Console console = null;

				if (System.console() == null) {
					System.out.print("\npassword: ");
					password = inFromUser.readLine();
				} else {
					console = System.console();
					password = new String(console.readPassword("\npassword: "));
				}

				String encryptedPwd = clientSend.genSHA256(password);

				if (clientSend.verifyUser(username, encryptedPwd)) {
					System.out.println("Authenticated.");
					myUserName = username;
					clientSend.start();
					clientReceive.start();
					break;
				} else {
					System.out.println("Could not authenticate you.");
					continue;
				}
			}
		} catch (IOException ex) {
			ex.printStackTrace();
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {

		}
	}

	// write keys to serializable file
	public static void writeKeys() throws IOException {
		if (myUserName != null) {
			FileOutputStream fout = new FileOutputStream(myUserName
					+ "secretkey.ser");
			ObjectOutputStream oos = new ObjectOutputStream(fout);

			oos.writeObject(secretKey);
			oos.close();
			fout.close();
		}
	}

	// read keys from serializable file
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static void readKeys() throws ClassNotFoundException, IOException {
		if (myUserName != null) {
			File f = new File(myUserName + "secretkey.ser");
			if (f.exists() && !f.isDirectory()) {
				InputStream file = new FileInputStream(myUserName
						+ "secretkey.ser");
				InputStream buffer = new BufferedInputStream(file);
				ObjectInputStream input1 = new ObjectInputStream(buffer);
				secretKey = (HashMap) input1.readObject();

				input1.close();
				file.close();
			} else {
				writeKeys();
			}
		}
	}
}