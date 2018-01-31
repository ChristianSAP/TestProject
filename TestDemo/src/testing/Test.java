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
		String timeStamp = "20.01.2018 03:00:00.0";
		String systemIdActor = "YI3/000";
		String userIdActor = "00505695007C1ED786A8AB36D6125FF6";
		try { // opening connection to HANA db
			connection = DriverManager.getConnection("jdbc:sap://ld3796.wdf.sap.corp:30015/?autocommit=false", myname,
					mysecret);
		} catch (SQLException e) {
			System.err.println("Error: Connection Failed");
			return;
		}
		// todo get log to analysis, do something with the result! -> score
		//analysisUnusualTime(connection, systemIdActor, timeStamp, userIdActor);
		analysisUnusualSystem(connection, systemIdActor, timeStamp, userIdActor);

	}

	// analysis: log at unusual time? (based on System ID, not User ID!)
	public static boolean analysisUnusualTime(Connection connection, String systemIdActor, String timeStamp, String userIdActor) {
		boolean restPeriod = false;
		long numberOfLogsTwoHours;
		long numberOfLogsTenMinutes;
		double medianTwoHours;
		double medianTenMinutes;

		if (connection != null) {
			try {
				Statement stmt = connection.createStatement();

				ResultSet resultSet = stmt.executeQuery(
						"SELECT COUNT (\"UserIdActing\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
								+ "WHERE \"UserIdActing\" = '" + userIdActor 
								+ "' AND \"Timestamp\" BETWEEN '31.01.2018 12:00:00.0' AND '31.01.2018 14:00:00.0'");
				resultSet.next();
				numberOfLogsTwoHours = Integer.parseInt(resultSet.getString(1));
				medianTwoHours = (numberOfLogsTwoHours / 120) * 0.5;

				ResultSet resultSetLast10Minutes = stmt.executeQuery(
						"SELECT COUNT (\"UserIdActing\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
								+ "WHERE \"UserIdActing\" = '" + userIdActor
								+ "' AND \"Timestamp\" BETWEEN '31.01.2018 13:50:00.0' AND '31.01.2018 14:00:00.0'");
				resultSetLast10Minutes.next();
				numberOfLogsTenMinutes = Integer.parseInt(resultSetLast10Minutes.getString(1));
				medianTenMinutes = numberOfLogsTenMinutes / 10;
				
				if (medianTenMinutes < medianTwoHours) {
					restPeriod = true;
				} else {
					restPeriod = false;
				}

			} catch (SQLException e) {
				System.err.println("Query failed!");
			}
		}
		System.out.println(restPeriod);
		return restPeriod;
	}

	public static boolean analysisUnusualSystem(Connection connection, String systemIdActor, String timeStamp,
			String userIdActor) {
		boolean unusualSystem = true;
		long numberOfLogins;
		if (connection != null) {
			try {
				Statement stmt = connection.createStatement();
				ResultSet resultSet = stmt.executeQuery("SELECT COUNT (\"UserIdActing\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
						+ "WHERE \"SystemIdActor\" = '" + systemIdActor
						+ "' AND \"Timestamp\" BETWEEN '01.11.2017 00:00:00.0' AND '31.01.2018 00:00:00.0' AND \"UserIdActor\" = '" + userIdActor + "'");
				resultSet.next();
				numberOfLogins = Integer.parseInt(resultSet.getString(1));
				System.out.println(numberOfLogins);
				
				if(numberOfLogins > 1){
					unusualSystem = false;
				} else {
					unusualSystem = true;
				}
				
				
			} catch (SQLException e) {
				System.err.println("Query failed!");
			}
		}
		return unusualSystem;
	}
}

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
