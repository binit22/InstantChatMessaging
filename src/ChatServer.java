import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;


public class ChatServer extends Thread {

	public String type;
	public static int PORT = 5000;
	public static int clientPort = 7000;
	public static String authServerIP = "192.168.1.10";
	public static int authServerPort = 8000;

	public DatagramSocket server = null;

	public final static int size = 2048;

	public ChatServer(){
		try {
			server = new DatagramSocket(PORT);
		} catch (SocketException e) {
			e.printStackTrace();
		}
	}

	public String verifyUser(String user){

		String reply = null;
		byte[] data = null;
		DatagramPacket packet = null;

		try{
			InetAddress IPAddress = InetAddress.getByName(authServerIP);

			data = new byte[size];
			data = user.getBytes();
			packet = new DatagramPacket(data, data.length, IPAddress, authServerPort); 
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
		return reply;
	}

	public String userExists(String username){

		String reply = null;
		byte[] data = null;
		DatagramPacket packet = null;

		try{
			InetAddress IPAddress = InetAddress.getByName(authServerIP);

			data = new byte[size];
			data = username.getBytes();
			packet = new DatagramPacket(data, data.length, IPAddress, authServerPort); 
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
		return reply;
	}

	public void send(){

		try{
			BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));

			byte[] sendData = null;
			DatagramPacket packet = null;
			String sendMsg = "";

			while(true){
				sendMsg = inFromUser.readLine();

				sendData = new byte[size];
				sendData = sendMsg.getBytes();
				InetAddress IPAddress = InetAddress.getByName("localhost"); 
				packet = new DatagramPacket(sendData, sendData.length, IPAddress, clientPort); 
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
			DatagramPacket packet = null;

			while(true){
				receiveData = new byte[size]; 
				packet = new DatagramPacket(receiveData, receiveData.length); 
				server.receive(packet);

				// message command received from either client or server or bootstrap
				message = new String(packet.getData()).trim(); 
//				System.out.println(message);

				byte[] sendData = null;
				//				DatagramPacket packet = null;
				String sendMsg = "";

				// authenticate from authentication server
				if(message != null && message.contains("authenticate")){

					sendMsg = this.verifyUser(message);

					sendData = new byte[size];
					sendData = sendMsg.getBytes();
					InetAddress IPAddress = packet.getAddress(); 
					packet = new DatagramPacket(sendData, sendData.length, IPAddress, packet.getPort()); 
					server.send(packet);
				}
				else if(message != null && message.contains("verify")){
					sendMsg = this.userExists(message);

					sendData = new byte[size];
					sendData = sendMsg.getBytes();
					InetAddress IPAddress = packet.getAddress(); 
					packet = new DatagramPacket(sendData, sendData.length, IPAddress, packet.getPort()); 
					server.send(packet);
				}

			}
		} catch(Exception ex){
			ex.printStackTrace();
		} finally{
		}
		return message;
	}

	public void run(){
		this.receive();
	}

	public static void main(String[] args) {
		ChatServer receive = new ChatServer();
		receive.start();
		receive.send();

	}
}
