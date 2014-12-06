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
	int serverPort = 7000;

	/**
	 * 
	 * Constructor to set all variables for
	 */
	public AuthServer(String serverAdd, String sqlHost, String sqlUsername,
			String sqlPassword, int PORT, int serverPort)
			throws SocketException {
		this.serverAdd = serverAdd;
		this.sqlHost = sqlHost;
		this.sqlPassword = sqlPassword;
		this.sqlUsername = sqlUsername;
		// set port number for socket
		ds = new DatagramSocket(PORT);
		this.serverPort = serverPort;
	}

	/**
	 * 
	 * Function to verify if user exits
	 */
	public String verifyUser(String user) throws ClassNotFoundException,
			SQLException {
		Connection connect = null;
		Statement statement = null;
		ResultSet resultSet = null;
		boolean found = false;
		// mysql jdbc driver
		Class.forName("com.mysql.jdbc.Driver");
		// mysql connect
		connect = DriverManager
				.getConnection("jdbc:mysql://" + sqlHost + "/test?" + "user="
						+ sqlUsername + "&password=" + sqlPassword);
		statement = connect.createStatement();
		// check for user count
		resultSet = statement
				.executeQuery("select count(1) as cnt from chat.userinfo where username='"
						+ user + "';");
		while (resultSet.next()) {
			// if user is found count will be 1
			if (resultSet.getInt("cnt") == 1)
				found = true;
		}
		// return true or false based on count
		if (found)
			return "true";
		else
			return "false";
	}

	/**
	 * 
	 * Function to authenticate username and password
	 */
	public String authUser(String user, String pass)
			throws ClassNotFoundException, SQLException {
		Connection connect = null;
		Statement statement = null;
		ResultSet resultSet = null;
		boolean found = false;
		// mysql jdbc driver
		Class.forName("com.mysql.jdbc.Driver");
		// mysql connect
		connect = DriverManager
				.getConnection("jdbc:mysql://" + sqlHost + "/test?" + "user="
						+ sqlUsername + "&password=" + sqlPassword);
		statement = connect.createStatement();
		// check for user count
		resultSet = statement
				.executeQuery("select count(1) as cnt from chat.userinfo where username='"
						+ user + "' and password='" + pass + "';");
		// if username and password is correct the count will be 1
		while (resultSet.next()) {

			if (resultSet.getInt("cnt") == 1)
				found = true;
		}

		// return true or false based on the count
		if (found)
			return "true";
		else
			return "false";
	}

	/**
	 * Main function
	 */
	public static void main(String[] args) throws ClassNotFoundException,
			SQLException, NoSuchAlgorithmException, SocketException {
		// default values
		String host = "localhost:3307";
		String uname = "root";
		String pass = "";
		String server = "";
		// mysql arguments
		if (args.length == 3) {
			host = args[0];
			uname = args[1];
			pass = args[2];
		}
		if (args.length != 0 && args.length < 3)
			usage();

		Scanner sc = new Scanner(System.in);
		System.out.println("Enter port to listen on:");
		int PORT = Integer.parseInt(sc.nextLine());
		System.out.println("Enter server port number:");
		int serP = Integer.parseInt(sc.nextLine());
		System.out.println("Enter server IP:");
		server = sc.nextLine();
		AuthServer as = new AuthServer(server, host, uname, pass, PORT, serP);
		as.start();

	}

	/**
	 * Print usage message
	 */
	public static void usage() {
		System.err.println("USAGE:");
		System.err.println("java AuthServer sqlhost sqlusername sqlpassword");

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
			String unamepass = "";
			receiveData = new byte[size];
			receivePacket = new DatagramPacket(receiveData, receiveData.length);

			ds.receive(receivePacket);
			/*
			 * System.out.println(receivePacket.getAddress().toString()
			 * .substring(1) + " server connected.");
			 */
			if (receivePacket.getAddress().toString().substring(1)
					.equals(serverAdd)) {
				unamepass = new String(receivePacket.getData()).trim();
				String u[] = unamepass.split(";;");
				if (u[0].equals("authenticate")) {
					sendData = new byte[size];

					sendData = authUser(u[1], u[2]).trim().getBytes();
					if (authUser(u[1], u[2]).trim().equals("true"))
						System.out.println("User " + u[1] + " authenticated.");
					else
						System.out.println("User " + u[1]
								+ " cannot be authenticated.");

					sendPacket = new DatagramPacket(sendData, sendData.length,
							receivePacket.getAddress(), serverPort);
					ds.send(sendPacket);
				}

				else if (u[0].equals("verify")) {
					sendData = new byte[size];

					sendData = verifyUser(u[1]).trim().getBytes();
					if (verifyUser(u[1]).equals("true"))
						System.out.println("User " + u[1] + " verified.");
					else
						System.out.println("User " + u[1]
								+ " cannot be verified.");

					sendPacket = new DatagramPacket(sendData, sendData.length,
							receivePacket.getAddress(), serverPort);
					ds.send(sendPacket);
				}

			} else {
				System.out.println("Invalid server "
						+ receivePacket.getAddress().toString().substring(1));
				sendData = new byte[size];

				sendData = new String("Invalid server").getBytes();

				sendPacket = new DatagramPacket(sendData, sendData.length,
						receivePacket.getAddress(), serverPort);
				ds.send(sendPacket);
			}
		}
	}

	public void run() {
		try {
			System.out.println("Authenticaion Server is alive.");
			this.receive();
		} catch (IOException | ClassNotFoundException | SQLException e) {
			e.printStackTrace();
		}

	}
}