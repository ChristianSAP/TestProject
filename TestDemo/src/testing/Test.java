package testing;

import java.sql.*;

public class Test {
	public static void main(String[] args) {
		// variables for HANA db connection
		Connection connection = null;
		String myname = "ETD_TEST_CLIENT";
		String mysecret = "Initial04";
		// variables to store information about current log
		String timeStamp = "20.01.2018 03:00:00.0";
		String systemIdActor = "$T3/000";
		String userIdActor = "552F9FEC6D382BA3E10000000A4CF109";
		try { // opening connection to HANA db
			connection = DriverManager.getConnection("jdbc:sap://ld3796.wdf.sap.corp:30015/?autocommit=false", myname,
					mysecret);
		} catch (SQLException e) {
			System.err.println("Error: Connection Failed");
			return;
		}
		// todo get log to analysis, do something with the result! -> score
		// analysisUnusualTime(connection, systemIdActor, timeStamp,
		// userIdActor);
		analysisUnusualSystem(connection, systemIdActor, timeStamp, userIdActor);

	}

	// analysis: log at unusual time? (based on System ID, not User ID!)
	public static boolean analysisUnusualTime(Connection connection, String systemIdActor, String timeStamp,
			String userIdActor) {
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
				ResultSet resultSet = stmt.executeQuery(
						"SELECT \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"TechnicalLogEntryType\", \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"SystemIdActor\","
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"Timestamp\", \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"UserIdActing\","
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"eventName.name\""
								+ "FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\""
								+ "INNER JOIN \"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\" "
								+ "ON \"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"id\" = \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"TechnicalLogEntryType\""
								+ "WHERE \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"SystemIdActor\" = '"
								+ systemIdActor + "' AND "
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"UserIdActing\" = '" + userIdActor + "' AND"
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"eventName.name\" = 'UserLogon' AND "
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"Timestamp\" BETWEEN '01.11.2017 00:00:00.0' AND '31.01.2018 00:00:00.0'");
				// numberOfLogins = Integer.parseInt(resultSet.getString(1));
				while (resultSet.next()) {
					for (int i = 0; i <= resultSet.getMetaData().getColumnCount(); i++) {
						if (i > 1) {
							System.out.print(",  ");
							String columnValue = resultSet.getString(i);
							System.out.print(columnValue + " " + resultSet.getMetaData().getColumnName(i));

						}
						System.out.println("");
					}
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
