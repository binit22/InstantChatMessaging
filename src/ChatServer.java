import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
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
	public static String authServerIP = "129.21.12.78";
	public static int authServerPort = 8000;
	public static DatagramSocket server = null;

	public ChatServer(String AS) {
		try {
			authServerIP = AS;

			if (server == null){
				server = new DatagramSocket(PORT);
				server.setReuseAddress(true);	
			}
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

	@SuppressWarnings({ "rawtypes", "unchecked" })
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
				//				System.out.println("@#$ msg received " + message);

				byte[] sendData = null;
				// DatagramPacket packet = null;
				String sendMsg = "";

				// authenticate from authentication server for login
				if (message != null && message.contains("authenticate")) {
					// System.out.println("authenticating");
					sendMsg = this.verifyUser(message);
					System.out.println(message.split(SEMICOLON)[1]
							+ " is being autheticated.");
					// add username and its IP address in active user list
					if ("true".equals(sendMsg)) {
						synchronized (activeUserList) {
							activeUserList.put(message.split(SEMICOLON)[1], packet.getAddress().getHostAddress());
							activeIPList.put(packet.getAddress().getHostAddress(), message.split(SEMICOLON)[1]);
						}
					}

					sendData = new byte[size];
					sendData = sendMsg.getBytes();
					InetAddress IPAddress = packet.getAddress();
					packet = new DatagramPacket(sendData, sendData.length, IPAddress, packet.getPort());
					server.send(packet);

				}// authenticate from authentication server for chat
				else if (message != null && message.contains("verify")) {
					InetAddress IPAddress = packet.getAddress();

					System.out.println(message.split(SEMICOLON)[1] + " is being verified.");

					if (activeUserList.containsKey(message.split(SEMICOLON)[1])) {
						sendMsg = "true";
					} else
						sendMsg = this.userExists(message);

					sendData = new byte[size];
					sendData = "verified".getBytes();
					packet = new DatagramPacket(sendData, sendData.length, IPAddress, packet.getPort());
					server.send(packet);

					sendData = new byte[size];
					sendData = sendMsg.getBytes();
					packet = new DatagramPacket(sendData, sendData.length, IPAddress, packet.getPort());
					server.send(packet);
				}

				else if (message != null && message.contains("initialkey")) {
					receiveData = new byte[size];
					String rUser = activeIPList.get(packet.getAddress().getHostAddress());

					// receive key and other username
					packet = new DatagramPacket(receiveData, receiveData.length);
					server.receive(packet);
					ByteArrayInputStream bi = new ByteArrayInputStream(receiveData);
					ObjectInput oi = new ObjectInputStream(bi);

					ArrayList ar = (ArrayList) oi.readObject();
					String user = (String) ar.get(0); // other username
					bi.close();
					oi.close();

					sendData = new byte[size];
					sendData = new String("publickey1").getBytes();
					InetAddress IPAddress = InetAddress.getByName(activeUserList.get(user));

					packet = new DatagramPacket(sendData, sendData.length,
							IPAddress, clientPort);
					System.out.println("P, G and Public Key transfer from "
							+ rUser + " to " + user);
					System.out.println(ar.get(3));
					server.send(packet);

					ar.set(0, (String) rUser);
					ByteArrayOutputStream b = new ByteArrayOutputStream();
					ObjectOutput o = new ObjectOutputStream(b);
					o.writeObject(ar);

					sendData = b.toByteArray();
					o.close();
					b.close();

					packet = new DatagramPacket(sendData, sendData.length,
							IPAddress, clientPort);
					server.send(packet);

				} else if (message != null && message.contains("nextkey")) {
					receiveData = new byte[size];
					String rUser = activeIPList.get(packet.getAddress()
							.getHostAddress());
					// receive key and other username
					packet = new DatagramPacket(receiveData, receiveData.length);
					server.receive(packet);
					ByteArrayInputStream bi = new ByteArrayInputStream(receiveData);
					ObjectInput oi = new ObjectInputStream(bi);

					ArrayList ar = (ArrayList) oi.readObject();
					String oUser = (String) ar.get(0);
					ar.set(0, (String) rUser);
					bi.close();
					oi.close();

					InetAddress IPAddress = InetAddress.getByName(activeUserList.get(oUser));

					sendData = new byte[size];
					sendData = new String("publickey2").getBytes();

					packet = new DatagramPacket(sendData, sendData.length,IPAddress, clientPort);
					System.out.println("Public Key transfer from " + rUser + " to " + oUser);
					System.out.println(ar.get(1));
					server.send(packet);

					ByteArrayOutputStream b = new ByteArrayOutputStream();
					ObjectOutput o = new ObjectOutputStream(b);
					o.writeObject(ar);

					sendData = b.toByteArray();
					o.close();
					b.close();

					packet = new DatagramPacket(sendData, sendData.length, IPAddress, clientPort);
					server.send(packet);

				} else if (message != null && message.contains("message")) {
					packet = new DatagramPacket(receiveData, receiveData.length);
					server.receive(packet);

					ByteArrayInputStream bi = new ByteArrayInputStream(receiveData);
					ObjectInput oi = new ObjectInputStream(bi);

					ArrayList ar = (ArrayList) oi.readObject();
					String oUser = (String) ar.get(0);
					bi.close();
					oi.close();

					InetAddress IPAddress = InetAddress.getByName(activeUserList.get(oUser));

					String rUser = activeIPList.get(packet.getAddress().getHostAddress());
					ar.set(0, rUser);
					sendData = "message".getBytes();
					packet = new DatagramPacket(sendData, sendData.length, IPAddress, clientPort);
					server.send(packet);

					ByteArrayOutputStream b = new ByteArrayOutputStream();
					ObjectOutput o = new ObjectOutputStream(b);
					o.writeObject(ar);
					o.close();
					b.close();
					
					sendData = b.toByteArray();
					packet = new DatagramPacket(sendData, sendData.length, IPAddress, clientPort);
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
		System.err.println("java ChatServer authServerIP \nIf no authentication server is specified default it taken");
		throw new IllegalArgumentException();
	}
}
