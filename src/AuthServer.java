import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.ResultSet;
import java.security.NoSuchAlgorithmException;
import java.sql.Statement;
import java.util.Scanner;

public class AuthServer extends Thread {
	String serverAdd;
	String sqlHost;
	String sqlUsername;
	String sqlPassword;
	DatagramSocket ds;
	int size = 2048;

	public AuthServer(String serverAdd, String sqlHost, String sqlUsername,
			String sqlPassword,int PORT) throws SocketException {
		this.serverAdd = serverAdd;
		this.sqlHost = sqlHost;
		this.sqlPassword = sqlPassword;
		this.sqlUsername = sqlUsername;
		ds = new DatagramSocket(PORT);
	}



	public String authUser(String user, String pass)
			throws ClassNotFoundException, SQLException {
		Connection connect = null;
		Statement statement = null;
		ResultSet resultSet = null;
		boolean found = false;
		Class.forName("com.mysql.jdbc.Driver");
		connect = DriverManager
				.getConnection("jdbc:mysql://" + sqlHost + "/test?" + "user="
						+ sqlUsername + "&password=" + sqlPassword);
		statement = connect.createStatement();
		resultSet = statement
				.executeQuery("select count(1) as cnt from chat.userinfo where username='"
						+ user + "' and password='" + pass + "';");
		System.out
				.println("select count(1) as cnt from chat.userinfo where username='"
						+ user + "' and password='" + pass + "';");
		while (resultSet.next()) {

			if (resultSet.getInt("cnt") == 1)
				found = true;
		}
		if (found)
			return "true";
		else
			return "false";
	}

	public static void main(String[] args) throws ClassNotFoundException,
			SQLException, NoSuchAlgorithmException, SocketException {

		String host = "localhost:3307";
		String uname = "root";
		String pass = "";
		String server = "";
		if (args.length == 4) {
			host = args[1];
			uname = args[2];
			pass = args[3];
		}
		if (args.length > 1 && args.length < 4)
			usage();
		
		Scanner sc=new Scanner(System.in);
		System.out.println("Enter port to listen on:");
		int PORT=Integer.parseInt(sc.nextLine());
		
		AuthServer as = new AuthServer(server, host, uname, pass,PORT);
		as.start();
		// if (as.authUser("binit", "1630937c3d00b4f4b153599d93469963"))
		// System.out.println("found binit");
		// System.out.println(as.genSHA256("sadhvani"));
	}

	/**
	 * Print usage message
	 */
	public static void usage() {
		System.err.println("USAGE:");
		System.err
				.println("java AuthServer serverAddress sqlhost sqlusername sqlpassword");
		System.err
				.println("OR\njava AuthServer serverAddress\n(default values are taken for the rest)");

		System.err.println("OR\njava AuthServer\n(default values are taken)");
		throw new IllegalArgumentException();
	}

	public void receive() throws IOException, ClassNotFoundException,
			SQLException {
		byte[] receiveData = null;
		byte[] sendData = null;

		DatagramPacket receivePacket = null;
		DatagramPacket sendPacket = null;

		while (true) {
			String uname = "";
			String pass = "";
			receiveData = new byte[size];
			receivePacket = new DatagramPacket(receiveData, receiveData.length);

			ds.receive(receivePacket);
			System.out.println(receivePacket.getAddress().toString()
					+ " server connected.");
			uname = new String(receivePacket.getData()).trim();
			receiveData = new byte[size];

			receivePacket = new DatagramPacket(receiveData, receiveData.length);
			pass = new String(receivePacket.getData()).trim();
			sendData = new byte[size];
			sendData = authUser(uname, pass).getBytes();
			System.out.println(authUser(uname, pass));
			sendPacket = new DatagramPacket(sendData, sendData.length,
					receivePacket.getAddress(), 7000);
			ds.send(sendPacket);
			ds.close();

		}
	}

	public void run() {
		try {
			this.receive();
		} catch (IOException | ClassNotFoundException | SQLException e) {
			e.printStackTrace();
		}

	}
}