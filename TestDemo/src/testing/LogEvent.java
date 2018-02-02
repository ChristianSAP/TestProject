package testing;

import java.sql.*;

public class LogEvent {
	// variables for HANA db connection
	static Connection connection = null;
	static String myname = "ETD_TEST_CLIENT";
	static String mysecret = "Initial04";
	// variables to store information about current log
	String timeStamp;
	String systemIdActor;
	String userIdActor;
	String networkHostnameTarget;
	String networkIPAddressTarget;
	long requestResponseSize;
	String subnetIdInitiator;
	String subnetIdActor;
	String subnetIdTarget;

	int score;

	public LogEvent(String timeStamp, String systemIdActor, String userIdActor, String networkHostnameTarget,
			String networkIPAddressTarget, long requestResponseSize, String subnetIdInitiator, String subnetIdActor,
			String subnetIdTarget) {
		this.timeStamp = timeStamp;
		this.systemIdActor = systemIdActor;
		this.userIdActor = userIdActor;
		this.networkHostnameTarget = networkHostnameTarget;
		this.networkIPAddressTarget = networkIPAddressTarget;
		this.requestResponseSize = requestResponseSize;
		this.subnetIdActor = subnetIdActor;
		this.subnetIdInitiator = subnetIdInitiator;
		this.subnetIdTarget = subnetIdTarget;
		this.score = 0;
	}

	public static void main(String[] args) {

		try { // opening connection to HANA db
			connection = DriverManager.getConnection("jdbc:sap://ld3796.wdf.sap.corp:30015/?autocommit=false", myname,
					mysecret);
		} catch (SQLException e) {
			System.err.println("Error: Connection Failed");
			return;
		}
		// todo get log to analysis, do something with the result! -> score
		// test data =======>
		LogEvent logEvent = new LogEvent("20.01.2018 03:00:00.0", "$T3/000", "552F9FEC6D382BA3E10000000A4CF109", "",
				"33.76.134.255", 789, "BF96E0572011F351E11700000A600446", "BF96E0572011F351E11700000A600446", null);
		logEvent.analysisLogEventAPT();
		System.out.println("Score: " + logEvent.score);
		// <======
	}

	public int analysisLogEventAPT() {
		if (analysisUnusualProtocol())
			score++;
		System.out.println(score);
		if (analysisUnusualSystem())
			score++;
		System.out.println(score);
		if (analysisUnusualTime())
			score++;
		System.out.println(score);
		if (analysisUnusualHostOrIp())
			score++;
		System.out.println(score);
		if (requestResponseSize != 0) {
			if (analysisUnusuallyLowNumberOfBytes())
				score++;
		}
		System.out.println(score);
		if (analysisUnusualSubnetConnection())
			score++;
		System.out.println(score);

		return score;
	}

	// analysis: log at unusual time? (based on User ID!)
	private boolean analysisUnusualTime() {
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
		// System.out.println(restPeriod);
		return restPeriod;
	}

	// returns true, if the user has never successfully logged onto the system
	// before
	private boolean analysisUnusualSystem() {
		boolean unusualSystem = true;
		long numberOfLogins;
		if (connection != null) {
			try {
				Statement stmt = connection.createStatement();
				ResultSet resultSet = stmt.executeQuery(
						"SELECT TOP 1 COUNT(\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"TechnicalLogEntryType\"), \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"SystemIdActor\","
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"Timestamp\", \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"UserIdActing\","
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"eventName.name\""

								+ "FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\""
								+ "INNER JOIN \"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\" "
								+ "ON \"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"id\" = \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"TechnicalLogEntryType\""

								+ "WHERE \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"SystemIdActor\" = '"
								+ systemIdActor + "' AND "
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"UserIdActing\" = '" + userIdActor
								+ "' AND"
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"eventName.name\" = 'UserLogon' AND "
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"Timestamp\" BETWEEN '01.11.2017 00:00:00.0' AND '31.01.2018 00:00:00.0'"
								+ "GROUP BY \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"SystemIdActor\","
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"Timestamp\", \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"UserIdActing\","
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"eventName.name\"");
				// numberOfLogins = Integer.parseInt(resultSet.getString(1));
				resultSet.next();
				numberOfLogins = Long.parseLong(resultSet.getString(1));
				// System.out.println(numberOfLogins);
				if (numberOfLogins > 0) {
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

	private boolean analysisUnusualProtocol() {
		boolean unusualProtocol = false;
		if (connection != null) {
			// ja was?
		}
		return unusualProtocol;
	}

	private boolean analysisUnusualHostOrIp() {
		boolean unusualHost = false;
		long numberOfFormerConnections;

		if (connection != null) {
			try {
				if (networkIPAddressTarget != null && networkHostnameTarget == "") {

					Statement stmt = connection.createStatement();
					ResultSet resultSet = stmt.executeQuery(
							"SELECT COUNT (\"UserIdActing\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
									+ "WHERE \"UserIdActing\" = '" + userIdActor
									+ "' AND \"NetworkIPAddressTarget\" = '" + networkIPAddressTarget
									+ "' AND \"NetworkHostnameTarget\" IS NULL");
					resultSet.next();
					numberOfFormerConnections = Long.parseLong(resultSet.getString(1));
					// System.out.println(numberOfFormerConnections);

					if (numberOfFormerConnections > 0) {
						unusualHost = false;
					} else {
						unusualHost = true;
					}

				} else if (networkIPAddressTarget == "" && networkHostnameTarget != null) {

					Statement stmt = connection.createStatement();
					ResultSet resultSet = stmt.executeQuery(
							"SELECT COUNT(\"UserIdActing\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
									+ "WHERE \"UserIdActing\" = '" + userIdActor
									+ "' AND \"NetworkIPAddressTarget\" IS NULL");
					resultSet.next();
					numberOfFormerConnections = Long.parseLong(resultSet.getString(1));
					// System.out.println(numberOfFormerConnections);

					if (numberOfFormerConnections > 0) {
						unusualHost = false;
					} else {
						unusualHost = true;
					}

				} else if (networkIPAddressTarget != null && networkHostnameTarget != null) {

					Statement stmt = connection.createStatement();
					ResultSet resultSet = stmt.executeQuery(
							"SELECT COUNT(\"UserIdActing\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
									+ "WHERE \"UserIdActing\" = '" + userIdActor
									+ "' AND \"NetworkIPAddressTarget\" = '" + networkIPAddressTarget
									+ "' AND \"NetworkHostnameTarget\" IS NULL");

					numberOfFormerConnections = Long.parseLong(resultSet.getString(1));
					// System.out.println(numberOfFormerConnections);

					if (numberOfFormerConnections > 0) {
						unusualHost = false;
					} else {
						unusualHost = true;
					}

				} else {
					System.err.println("Failed, no IP Address or Hostname.");
				}

			} catch (SQLException e) {
				System.err.println("Query failed!");
			}
		}
		return unusualHost;
	}

	private boolean analysisUnusuallyLowNumberOfBytes() {
		boolean lowNumberOfBytes = false;
		if (connection != null) {
			try {
				Statement stmt = connection.createStatement();

				// is this calculation valid? Check it out!
				ResultSet resultSet = stmt.executeQuery(
						"SELECT AVG(\"ResourceResponseSize\")  - STDDEV(\"ResourceResponseSize\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\""
								+ "WHERE \"UserIdActing\" = '" + userIdActor + "'"
								+ " AND \"ResourceResponseSize\" IS NOT NULL");
				resultSet.next();
				if (this.requestResponseSize <= Double.parseDouble(resultSet.getString(1))) {
					lowNumberOfBytes = true;
				} else {
					lowNumberOfBytes = false;
				}

			} catch (SQLException e) {
				System.err.println("Query failed!");
			}

		}
		return lowNumberOfBytes;
	}

	private boolean analysisUnusualSubnetConnection() {
		boolean unusualSubnetConnection = false;
		if (connection != null) {
			try {
				// unusual subnetidinitiator?
				Statement stmt = connection.createStatement();
				if (subnetIdInitiator != null) {
					ResultSet resultSet = stmt.executeQuery(
							"SELECT COUNT(\"UserIdActing\")  FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\""
									+ "WHERE  \"UserIdActing\" = '" + userIdActor
									+ "' AND \"NetworkSubnetIdInitiator\" = '" + subnetIdInitiator + "'");
					resultSet.next();
					if (Integer.parseInt(resultSet.getString(1)) < 2) {
						unusualSubnetConnection = true;
						System.out.println("case 1");
					} else {
						unusualSubnetConnection = false;
						// unusual subnetidinitiator and actor?
						if (subnetIdActor != null) {

							ResultSet resultSetCase2 = stmt.executeQuery(
									"SELECT COUNT(\"UserIdActing\")  FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\""
											+ "WHERE  \"UserIdActing\" = '" + userIdActor
											+ "' AND \"NetworkSubnetIdInitiator\" = '" + subnetIdInitiator
											+ "' AND \"NetworkSubnetIdActor\" = '" + subnetIdActor + "'");
							resultSetCase2.next();
							if (Integer.parseInt(resultSetCase2.getString(1)) < 2) {
								unusualSubnetConnection = true;
								System.out.println("case 2");
							} else {
								unusualSubnetConnection = false;

							}
						}
						// unusual subnetidinitiator and target?
						if (subnetIdTarget != null && unusualSubnetConnection != true) {
							ResultSet resultSetCase3 = stmt.executeQuery(
									"SELECT COUNT(\"UserIdActing\")  FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\""
											+ "WHERE  \"UserIdActing\" = '" + userIdActor
											+ "' AND \"NetworkSubnetIdInitiator\" = '" + subnetIdInitiator
											+ "' AND \"NetworkSubnetIdTarget\" = '" + subnetIdTarget + "'");
							resultSetCase3.next();
							if (Integer.parseInt(resultSetCase3.getString(1)) < 2) {
								unusualSubnetConnection = true;
								System.out.println("case 3");
							} else {
								unusualSubnetConnection = false;
								// unusual subnetidinitiator, target and actor?
								if (subnetIdActor != null) {
									ResultSet resultSetCase4 = stmt.executeQuery(
											"SELECT COUNT(\"UserIdActing\")  FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\""
													+ "WHERE  \"UserIdActing\" = '" + userIdActor
													+ "' AND \"NetworkSubnetIdInitiator\" = '" + subnetIdInitiator
													+ "' AND \"NetworkSubnetIdTarget\" = '" + subnetIdTarget + "'"
													+ " AND \"NetworkSubnetIdActor\" = '" + subnetIdActor + "'");
									resultSetCase4.next();
									if (Integer.parseInt(resultSetCase4.getString(1)) < 2) {
										unusualSubnetConnection = true;
										System.out.println("case 4");
									} else {
										unusualSubnetConnection = false;
									}
								}
							}

						}
					}
				}
			} catch (SQLException e) {
				System.err.println("Query failed!");
			}

		}
		return unusualSubnetConnection;
	}
}
