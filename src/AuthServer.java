import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class AuthServer {
	public static void main(String[] args) throws ClassNotFoundException,
			SQLException {
		Connection connect = null;
		Statement statement = null;
		PreparedStatement preparedStatement = null;
		ResultSet resultSet = null;
		
		String host = "localhost:3307";
		String username = "root";
		String password = "";
		if(args.length==3){
			host = args[0];
			 username = args[1];
			 password = args[2];
		}
		
			
		Class.forName("com.mysql.jdbc.Driver");
		connect = DriverManager
				.getConnection("jdbc:mysql://localhost:3307/test?"
						+ "user="+username+"&password="+password);
		statement = connect.createStatement();
		resultSet = statement
				.executeQuery("select count(1) as cnt from chat.userinfo where username='binit' and password='1630937c3d00b4f4b153599d93469963'");
		
	}
}