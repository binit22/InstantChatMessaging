import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class Message extends Thread{

	public String type;
	public static int PORT = 7000;
	public static int serverPort = 5000;
	public DatagramSocket server = null;
	
	public final static int size = 2048;
			
	public Message(){
		try {
			server = new DatagramSocket(PORT);
			
		} catch (SocketException e) {
			e.printStackTrace();
		}
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
			this.send();
	}

	public static void main(String[] args) {
		Message client = new Message();
		client.start();
		client.receive();
		
	}
}
