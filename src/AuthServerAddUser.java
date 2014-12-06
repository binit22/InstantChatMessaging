import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.ResultSet;
import java.sql.Statement;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class AuthServerAddUser {

	public static void main(String args[]) throws NoSuchAlgorithmException, ClassNotFoundException, SQLException {
		Scanner sc = new Scanner(System.in);
		boolean found=false;
		
		String host = "localhost:3307";
		String uname = "root";
		String pass = "";
		if (args.length == 4) {
			host = args[0];
			uname = args[1];
			pass = args[2];
		}
		
		
		System.out.println("Enter username: ");
		String userName = sc.nextLine();
		System.out.println("Enter password: ");
		String password = genSHA256(sc.nextLine());
		Connection connect = null;
		Statement statement = null;
		Class.forName("com.mysql.jdbc.Driver");
		connect = DriverManager
				.getConnection("jdbc:mysql://" + host + "/test?" + "user="
						+ uname + "&password=" + pass);
		statement = connect.createStatement();
		ResultSet resultSet = statement
				.executeQuery("select count(1) as cnt from chat.userinfo where username='"
						+ userName+"';");
	
		while (resultSet.next()) {

			if (resultSet.getInt("cnt") == 1)
				found = true;
		}
		
		if(found){
			
			System.out.println(userName+" already exits.");
		}
	
		else{
			statement
			.execute("INSERT INTO chat.userinfo (username,password) VALUES('"
					+ userName+"','"+password+"');");
			System.out.println(userName+" successfully inserted.");

		}
	}

	public static String genSHA256(String original)
			throws NoSuchAlgorithmException {

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(original.getBytes());
		byte[] digest = md.digest();
		StringBuffer sb = new StringBuffer();
		for (byte b : digest) {
			sb.append(String.format("%02x", b & 0xff));
		}

		return sb.toString();
	}

}
