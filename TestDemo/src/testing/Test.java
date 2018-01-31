package testing;

import java.sql.*;

public class Test {
	public static void main(String[] args) {
		Date temp = new Date(0);
		System.out.println(temp);
		// variables for HANA db connection
		Connection connection = null;
		String myname = "ETD_TEST_CLIENT";
		String mysecret = "Initial04";
		// variables to store information about current log
		String systemIdActor;
		String timeStamp;
		String systemIdActing;
		try { // opening connection to HANA db
			connection = DriverManager.getConnection("jdbc:sap://ld3796.wdf.sap.corp:30015/?autocommit=false", myname,
					mysecret);
		} catch (SQLException e) {
			System.err.println("Error: Connection Failed");
			return;
		}
		if (connection != null) {
			try {
				System.out.println("Connection to HANA successful!");
				Statement stmt = connection.createStatement();
				// todo get current log
				// ResultSet resultSetCurrentlog = stmt.executeQuery(
				// "SELECT DISTINCT \"Id\", \"Timestamp\", \"AttackName\",
				// \"CorrelationId\", \"EventLogType\", \"EventSourceId\",
				// \"GenericAction\","
				// + "\"GenericPurpose\", \"GenericRiskLevel\",
				// \"GenericScore\", \"NetworkIPAddressTarget\",
				// \"NetworkIPAddressInitiator\", \"NetworkPortTarget\",
				// \"NetworkProtocol\""
				// + "\"NetworkPortInitiator\", \"ResourceName\",
				// \"SystemIdTarget\", \"SystemIdInitiator\",
				// \"SystemTypeTarget\", \"SystemTypeInitiator\""
				// + " FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
				// + "WHERE \"UserIdActing\" IS NOT NULL AND
				// \"TimestampOfStart\" BETWEEN '20.01.2018 01:00:00.0' AND
				// '20.01.2018 03:00:00.0'");

				timeStamp = "20.01.2018 03:00:00.0"; // test data
				systemIdActor = "YI3/000";

				// analysis: log at unusual time?
				ResultSet resultSet = stmt.executeQuery(
						"SELECT COUNT (\"SystemIdActor\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
								+ "WHERE \"SystemIdActor\" = '" + systemIdActor
								+ "' AND \"TimestampOfStart\" BETWEEN '31.01.2018 12:00:00.0' AND '31.01.2018 14:00:00.0'");
				resultSet.next();
				String numberOfRecentLogs = resultSet.getString(1);
				System.out.println("Number of logs 2 hours (median): " + Integer.parseInt(numberOfRecentLogs)/120);
				ResultSet resultSetLast10Minutes = stmt.executeQuery(
						"SELECT COUNT (\"SystemIdActor\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
								+ "WHERE \"SystemIdActor\" = '" + systemIdActor
								+ "' AND \"TimestampOfStart\" BETWEEN '31.01.2018 13:50:00.0' AND '31.01.2018 14:00:00.0'");
				resultSetLast10Minutes.next();
				String numberOfRecentLogs10Minutes = resultSetLast10Minutes.getString(1);
				System.out.println("Number of logs 10 minutes (median): " + Integer.parseInt(numberOfRecentLogs10Minutes)/10);
				// analysis_ login into unusual system?
			} catch (SQLException e) {
				System.err.println("Query failed!");
			}
		}
	}
}
