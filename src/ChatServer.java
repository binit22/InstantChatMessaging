import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class ChatServer extends Thread {

	public final static int size = 2048;
	public final static String SEMICOLON = ";;";

	public String type;
	public Map<String, String> activeUserList = new HashMap<String, String>();
	public Map<String, String> activeIPList = new HashMap<String, String>();

	public static int PORT = 5000;
	public static int clientPort = 7000;
	public static String authServerIP = "192.168.1.10";
	public static int authServerPort = 8000;
	public static DatagramSocket server = null;

	public ChatServer(String AS) {
		try {
			authServerIP = AS;

			if (server == null)
				server = new DatagramSocket(PORT);
		} catch (SocketException e) {
			e.printStackTrace();
		}
	}

	// to login
	public String verifyUser(String user) {

		String reply = null;
		byte[] data = null;
		DatagramPacket packet = null;

		try {
			InetAddress IPAddress = InetAddress.getByName(authServerIP);

			data = new byte[size];
			data = user.getBytes();
			packet = new DatagramPacket(data, data.length, IPAddress,
					authServerPort);
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
		return reply;
	}

	// to chat with the user
	public String userExists(String username) {

		String reply = null;
		byte[] data = null;
		DatagramPacket packet = null;

		try {
			InetAddress IPAddress = InetAddress.getByName(authServerIP);

			data = new byte[size];
			data = username.getBytes();
			packet = new DatagramPacket(data, data.length, IPAddress,
					authServerPort);
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
		return reply;
	}

	// public void send(){
	//
	// try{
	// BufferedReader inFromUser = new BufferedReader(new
	// InputStreamReader(System.in));
	//
	// byte[] sendData = null;
	// DatagramPacket packet = null;
	// String sendMsg = "";
	//
	// while(true){
	// sendMsg = inFromUser.readLine();
	//
	// sendData = new byte[size];
	// sendData = sendMsg.getBytes();
	// InetAddress IPAddress = InetAddress.getByName("localhost");
	// packet = new DatagramPacket(sendData, sendData.length, IPAddress,
	// clientPort);
	// server.send(packet);
	// }
	//
	// } catch(IOException ex){
	// ex.printStackTrace();
	// } catch(Exception ex){
	// ex.printStackTrace();
	// } finally{
	// if(server != null)
	// server.close();
	// }
	// }

	public void receive() {
		String message = "";

		byte[] receiveData = null;
		DatagramPacket packet = null;

		while (true) {
			try {
				receiveData = new byte[size];
				packet = new DatagramPacket(receiveData, receiveData.length);
				System.out.println("waiting");
				server.receive(packet);

				// message command received from either client or server or
				// bootstrap
				message = new String(packet.getData()).trim();
				System.out.println(message);

				byte[] sendData = null;
				// DatagramPacket packet = null;
				String sendMsg = "";

				// authenticate from authentication server for login
				if (message != null && message.contains("authenticate")) {
					// System.out.println("authenticating");
					sendMsg = this.verifyUser(message);

					// add username and its IP address in active user list
					if ("true".equals(sendMsg)) {
						synchronized (activeUserList) {
							activeUserList.put(message.split(SEMICOLON)[1],
									packet.getAddress().getHostAddress());
							activeIPList.put(packet.getAddress()
									.getHostAddress(),
									message.split(SEMICOLON)[1]);
						}
					}

					sendData = new byte[size];
					sendData = sendMsg.getBytes();
					InetAddress IPAddress = packet.getAddress();
					packet = new DatagramPacket(sendData, sendData.length,
							IPAddress, packet.getPort());
					server.send(packet);

				}// authenticate from authentication server for chat
				else if (message != null && message.contains("verify")) {

					if (activeUserList.containsKey(message.split(SEMICOLON)[1])) {
						sendMsg = "true";
					} else
						sendMsg = this.userExists(message);

					sendData = new byte[size];
					sendData = sendMsg.getBytes();
					InetAddress IPAddress = packet.getAddress();
					packet = new DatagramPacket(sendData, sendData.length,
							IPAddress, packet.getPort());
					server.send(packet);
				}

				else if (message != null && message.contains("key")) {
					receiveData = new byte[size];
					// receive key and other username
					packet = new DatagramPacket(receiveData, receiveData.length);
					server.receive(packet);
					ByteArrayInputStream bi = new ByteArrayInputStream(
							receiveData);
					ObjectInput oi = new ObjectInputStream(bi);

					ArrayList ar = (ArrayList) oi.readObject();
					String user = (String) ar.get(0); // other username
					bi.close();
					oi.close();
					/*
					 * BigInteger p = (BigInteger) ar.get(1); BigInteger g =
					 * (BigInteger) ar.get(2); PublicKey pk = (PublicKey)
					 * ar.get(3); System.out.println(user);
					 * 
					 * System.out.println(p); System.out.println(g);
					 * System.out.println(pk);
					 */
					sendData = new byte[size];
					sendData = new String("publickey").getBytes();
					InetAddress IPAddress = InetAddress
							.getByName(activeUserList.get(user));

					System.out.println("P, G and Public Key transfer from "
							+ activeIPList.get(packet.getAddress()) + " to "
							+ user);

					packet = new DatagramPacket(sendData, sendData.length,
							IPAddress, clientPort);
					server.send(packet);

					ar.set(0, (String) activeIPList.get(packet.getAddress()));
					ByteArrayOutputStream b = new ByteArrayOutputStream();
					ObjectOutput o = new ObjectOutputStream(b);
					o.writeObject(ar);
//
					sendData = b.toByteArray();
					o.close();
					b.close();

					packet = new DatagramPacket(sendData, sendData.length,
							IPAddress, clientPort);
					server.send(packet);

				} else {
					sendData = new byte[size];
					String[] userMsg = message.split(SEMICOLON);

					sendData = (activeIPList.get(packet.getAddress()
							.getHostAddress()) + ": " + userMsg[1]).getBytes();
					InetAddress IPAddress = InetAddress
							.getByName(activeUserList.get(userMsg[0]));
					packet = new DatagramPacket(sendData, sendData.length,
							IPAddress, clientPort);
					server.send(packet);

				}

			} catch (Exception ex) {
				ex.printStackTrace();
			} finally {
			}
		}
	}

	public void run() {
		this.receive();
	}

	public static void main(String[] args) {
		if (args.length == 1)
			authServerIP = args[0];
		if (args.length > 1)
			usage();
		ChatServer receive = new ChatServer(authServerIP);
		receive.start();
		// receive.send();
		//

	}

	private static void usage() {
		System.err
				.println("java ChatServer authServerIP \nIf no authentication server is specified default it taken");
		throw new IllegalArgumentException();
	}
}
