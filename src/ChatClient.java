import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.IOException;
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
import java.security.KeyFactory;
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

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class ChatClient extends Thread {

	public final static int size = 2048;
	public final static String SEMICOLON = ";;";
	public final static int pValue = 47;
	public final static int gValue = 71;

	public static int PORT = 7000;
	public static String serverIP = "berry.cs.rit.edu";
	public static int serverPort = 5000;

	public static DatagramSocket server = null;

	public String type;
	public String toUser;
	public boolean send;

	private static PrivateKey privateKey;

	// username, secret key
	public static Map<String, SecretKeySpec> secretKey = new HashMap<String, SecretKeySpec>();

	public ChatClient(String type, String serverIP) {
		try {
			this.type = type;
			ChatClient.serverIP = serverIP;
			if (server == null)
				server = new DatagramSocket(PORT);
		} catch (SocketException e) {
			e.printStackTrace();
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
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

			KeyFactory kfactory = KeyFactory.getInstance("DiffieHellman");

			DHPublicKeySpec kspec = (DHPublicKeySpec) kfactory.getKeySpec(
					keyPair.getPublic(), DHPublicKeySpec.class);

			ArrayList key = new ArrayList();
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
			// System.out.println("@ "+p);
			// System.out.println("# "+g);
			// System.out.println("$ "+keyPair.getPublic());

			privateKey = keyPair.getPrivate();
			// System.out.println("% "+privateKey);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	public void send() {

		byte[] sendData = null;
		DatagramPacket packet = null;
		String sendMsg = "";
		InetAddress IPAddress = null;

		try {
			BufferedReader inFromUser = new BufferedReader(
					new InputStreamReader(System.in));

			if (send) {
				if (!secretKey.containsKey(this.toUser)) {
					// send public key to other client and set own private key
					sendPublicKey();
				} else {
					secretKey.get(this.toUser);
				}
			}

			System.out.println("Start sending messages");
			while (true) {
				sendMsg = inFromUser.readLine();

				sendData = new byte[size];
				sendData = (this.toUser + SEMICOLON + sendMsg).getBytes();
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

	@SuppressWarnings("rawtypes")
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

					System.out.println("client who sent this key: " + user);
					// System.out.println("@@@ "+p);
					// System.out.println("### "+g);
					// System.out.println("$$$from client "+otherPublicKey);

					DHParameterSpec param = new DHParameterSpec(p, g);
					KeyPairGenerator kpg = KeyPairGenerator
							.getInstance("DiffieHellman");
					kpg.initialize(param);
					KeyPair kp = kpg.generateKeyPair();
					PrivateKey myPrivateKey = kp.getPrivate();

					// System.out.println("$$$generated using p g "+kp.getPublic());
					// System.out.println("%%%generated using p g "+myPrivateKey);

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
					// System.out.println("&&&&& "+Arrays.toString(secretKey.getEncoded()));
					ChatClient.secretKey.put(user, secretKey);
				}
				if (message.contains("publickey2")) {
					receiveData = new byte[size];
					packet = new DatagramPacket(receiveData, receiveData.length);
					server.receive(packet);

					ByteArrayInputStream bi = new ByteArrayInputStream(
							receiveData);
					ObjectInput oi = new ObjectInputStream(bi);

					ArrayList ar = (ArrayList) oi.readObject();
					System.out.println("!!!array list in publickey2: " + ar);

					String user = (String) ar.get(0);
					PublicKey otherPublicKey = (PublicKey) ar.get(1);

					// System.out.println("private key before combine "+Arrays.toString(privateKey.getEncoded()));
					SecretKeySpec secretKey = combine(privateKey,
							otherPublicKey);
					// System.out.println("&&& secret key "+Arrays.toString(secretKey.getEncoded()));
					ChatClient.secretKey.put(user, secretKey);
				} else if (message.contains("message")) {
					receiveData = new byte[size];
					packet = new DatagramPacket(receiveData, receiveData.length);
					server.receive(packet);

					ByteArrayInputStream bi = new ByteArrayInputStream(
							receiveData);
					ObjectInput oi = new ObjectInputStream(bi);

					ArrayList ar = (ArrayList) oi.readObject();
					System.out.println(ar);
				}
			}
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {
		}
		return message;
	}

	private SecretKeySpec combine(PrivateKey private1, PublicKey public1)
			throws NoSuchAlgorithmException, InvalidKeyException,
			IllegalStateException {
		KeyAgreement ka = KeyAgreement.getInstance("DiffieHellman");
		ka.init(private1);
		ka.doPhase(public1, true);
		byte[] alice_secret = ka.generateSecret();

		SecretKeySpec aes = new SecretKeySpec(alice_secret, "AES");

		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(aes.getEncoded());
		byte[] digest = md.digest();
		SecretKeySpec key = new SecretKeySpec(digest, "AES");

		return aes;

	}

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
			// System.out.println(reply);
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

	public boolean userExists(String username) {

		String reply = null;
		byte[] data = null;
		DatagramPacket packet = null;

		try {
			InetAddress IPAddress = InetAddress.getByName(serverIP);

			data = new byte[size];
			data = ("verify" + SEMICOLON + username).getBytes();
			packet = new DatagramPacket(data, data.length, IPAddress,
					serverPort);
			server.send(packet);

			data = new byte[size];
			packet = new DatagramPacket(data, data.length);
			server.receive(packet);

			reply = new String(packet.getData()).trim();
			// System.out.println(reply);
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

	public void run() {
		if ("send".equals(this.type))
			this.send();
		else
			this.receive();
	}

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

				// System.out.print("\npassword :");
				// String password = inFromUser.readLine();
				Console console = System.console();

				String password = new String(
						console.readPassword("\npassword: "));

				String encryptedPwd = clientSend.genSHA256(password);
				// System.out.println("\nPwd: "+encryptedPwd);
				if (clientSend.verifyUser(username, encryptedPwd)) {
					System.out.println("verified");

					while (true) {
						System.out.print("start a new chat?(yes/no)");
						String option = inFromUser.readLine();
						if ("yes".equals(option.trim())) {
							System.out.print("enter username to chat with: ");
							String toUsername = inFromUser.readLine();

							if (clientSend.userExists(toUsername)) {
								clientSend.send = true;
								clientSend.toUser = toUsername;
								clientSend.start();
								clientReceive.start();
								break;
							} else {
								System.out.println("invalid user");
								continue;
							}
						} else {
							clientReceive.start();
							// clientSend.start();
							break;
						}
					}
					break;
				} else {
					System.out.println("could not verify");
					continue;
				}
			}
			// client.start();
			// client.receive();

		} catch (IOException ex) {
			ex.printStackTrace();
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {

		}
	}

	public static void usage() {

		System.err.println("java ChatClient SERVERADDRESS");
		System.err
				.println("If no SERVERADDRESS specified, default will be taken.");
		throw new IllegalArgumentException();

	}
}
