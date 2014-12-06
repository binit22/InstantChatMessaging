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
	
	public DatagramSocket server = null;
	
	public final static int size = 2048;
			
	public ChatServer(){
		try {
			server = new DatagramSocket(PORT);
	//amsd		
		} catch (SocketException e) {
			e.printStackTrace();
		}
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
			this.receive();
	}

	public static void main(String[] args) {
		ChatServer receive = new ChatServer();
		receive.start();
		receive.send();
		
	}
}
