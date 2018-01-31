package testing;

import java.sql.*;

public class Test {
	public static void main(String[] args) {
		Date temp = new Date(4);
		System.out.println(temp);
		// variables for HANA db connection
		Connection connection = null;
		String myname = "ETD_TEST_CLIENT";
		String mysecret = "Initial04";
		// variables to store information about current log
		String userIdActing = "";
		String timeStamp = "";
		try { // opening connection to HANA db
			connection = DriverManager.getConnection("jdbc:sap://ld3796.wdf.sap.corp:30015/?autocommit=false", myname,
					mysecret);
		} catch (SQLException e) {
			System.err.println("Connection Failed. User/Passwd Error?");
			return;
		}
		if (connection != null) {
			try {
				System.out.println("Connection to HANA successful!");
				Statement stmt = connection.createStatement();
				// todo get current log
				timeStamp = "20.01.2018 03:00:00.0";
				// analysis: log at unusual time?
				ResultSet resultSet = stmt.executeQuery(
						"SELECT COUNT (\"UserIdActing\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
								+ "WHERE \"UserIdActing\" IS NOT NULL AND \"TimestampOfStart\" BETWEEN '20.01.2018 01:00:00.0' AND '20.01.2018 03:00:00.0'");
				resultSet.next();
				String numberOfRecentLogs = resultSet.getString(1);
				System.out.println("Number of logs: " + numberOfRecentLogs);
			} catch (SQLException e) {
				System.err.println("Query failed!");
			}
		}
	}
}
