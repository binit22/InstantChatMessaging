import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;


public class ChatClient extends Thread{

	public final static int size = 2048;
	public static int PORT = 7000;
	public static String serverIP = "localhost";
	public static int serverPort = 5000;
	public static String authServerIP = "192.168.1.10";
	public static int authServerPort = 8000;

	public static DatagramSocket server = null;

	public String type;

	public ChatClient(String type){
		try {
			this.type = type;
			if(server == null)
				server = new DatagramSocket(PORT);
		} catch (SocketException e) {e.printStackTrace();}
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

	public boolean verifyUser(String username, String password){

		String reply = null;
		byte[] data = null;
		DatagramPacket packet = null;

		try{
			InetAddress IPAddress = InetAddress.getByName(serverIP);

			data = new byte[size];
			data = ("authenticate;;"+username+";;"+password).getBytes();
			packet = new DatagramPacket(data, data.length, IPAddress, serverPort); 
			server.send(packet);

			data = new byte[size];
			packet = new DatagramPacket(data, data.length); 
			server.receive(packet);

			reply = new String(packet.getData()).trim();
			//			System.out.println(reply);
		} catch(IOException ex){
			ex.printStackTrace();
		} catch(Exception ex){
			ex.printStackTrace();
		}

		if(packet != null && "true".equals(reply))
			return true;
		else
			return false;
	}

	public boolean userExists(String username){

		String reply = null;
		byte[] data = null;
		DatagramPacket packet = null;

		try{
			InetAddress IPAddress = InetAddress.getByName(serverIP);

			data = new byte[size];
			data = ("verify;;"+username).getBytes();
			packet = new DatagramPacket(data, data.length, IPAddress, serverPort); 
			server.send(packet);

			data = new byte[size];
			packet = new DatagramPacket(data, data.length); 
			server.receive(packet);

			reply = new String(packet.getData()).trim();
			//			System.out.println(reply);
		} catch(IOException ex){
			ex.printStackTrace();
		} catch(Exception ex){
			ex.printStackTrace();
		}

		if(packet != null && "true".equals(reply))
			return true;
		else
			return false;
	}

	public void send(){

		try{
			BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));

			byte[] sendData = null;
			DatagramPacket packet = null;
			String sendMsg = "";

			System.out.println("Start sending messages");
			while(true){
				sendMsg = inFromUser.readLine();

				sendData = new byte[size];
				sendData = sendMsg.getBytes();
				InetAddress IPAddress = InetAddress.getByName(serverIP); 
				packet = new DatagramPacket(sendData, sendData.length, IPAddress, serverPort); 
				server.send(packet);
			}

		} catch(IOException ex){
			ex.printStackTrace();
		} catch(Exception ex){
			ex.printStackTrace();
		} finally{
			if(server != null)
				server.close();
		}
	}

	public String receive(){
		String message = "";
		try{

			byte[] receiveData = null;
			DatagramPacket receivePacket = null;

			while(true){
				receiveData = new byte[size]; 
				receivePacket = new DatagramPacket(receiveData, receiveData.length); 
				server.receive(receivePacket); 

				// message command received from either client or server or bootstrap
				message = new String(receivePacket.getData()).trim(); 
				System.out.println(message);
			}
		} catch(Exception ex){
			ex.printStackTrace();
		} finally{
		}
		return message;
	}

	public void run(){
		if("send".equals(this.type))
			this.send();
		else
			this.receive();
	}

	public static void main(String[] args) {
		try{
			ChatClient clientSend = new ChatClient("send");
			ChatClient clientReceive = new ChatClient("receive");
			
			BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));

			while(true){ 
				System.out.print("username :");
				String username = inFromUser.readLine();

				System.out.print("\npassword :");
				String password = inFromUser.readLine();

				String encryptedPwd = clientSend.genSHA256(password);
				//				System.out.println("\nPwd: "+encryptedPwd);
				if(clientSend.verifyUser(username, encryptedPwd)){
					System.out.println("verified");

					while(true){
						System.out.print("start a new chat?(yes/no)");
						String option = inFromUser.readLine();
						if("yes".equals(option.trim())){
							System.out.print("enter username to chat with: ");
							String toUsername = inFromUser.readLine();
							if(clientSend.userExists(toUsername)){
								//								System.out.println("start chatting");
								clientSend.start();
								break;
							} else{
								System.out.println("invalid user");
								continue;
							}
						}
						else{
							clientReceive.start();
							break;
						}
					}
					break;
				}else{
					System.out.println("could not verify");
					continue;
				}
			}			
//			client.start();
//			client.receive();

		} catch(IOException ex){
			ex.printStackTrace();
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally{

		}
	}
}
