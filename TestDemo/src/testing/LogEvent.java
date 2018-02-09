package testing;

import java.sql.*;
import java.time.LocalDateTime;

/**
 * This class analyzes whether a log is unusual in a way that could give
 * conclusions/indications about a possible APT/malware infection
 * 
 * @author D067608
 * @version 07.02.2018
 * 
 */

/*
 * To Do: - windows log von servern subnetze qualifizieren direkte tcp -
 * kommunikation: protokolle ausschließen, nachlesen was browser macht - insert
 * ungewöhnliches protokoll bspw fdp - 2 routinen: letzte 2/3 minuten -> alle
 * 2/3 minuten ausführen für vergangene zukunft - siehe Kommentare Quelltext -
 * Loop Routine: alle 3 Minuten mit delay; while schleife in main, stoppbar
 * machen (eg file erzeugen & überprüfen, ob dieses existiert. wenn ja dann
 * löschen&stoppen) -> Konsolenbefehl starten, stoppen - Score: Indicator
 * erzeugen (score > 3 oder machine learning) in Log.Events Tabelle mit
 * "EventLogType" = 'Indicator'
 */
public class LogEvent {
	// variables for HANA db connection
	static Connection connection = null;
	static String myname = "ETD_TEST_CLIENT";
	static String mysecret = "Initial04";
	// variables to store information about current log
	LocalDateTime timeStamp;
	String systemIdActor;
	String userIdActor;
	String networkHostnameTarget;
	String networkIPAddressTarget;
	String networkIPAddressActor;
	String networkIPAddressInitiator;
	long requestResponseSize;
	String subnetIdInitiator;
	String subnetIdActor;
	String subnetIdTarget;
	int score;

	public LogEvent(Timestamp timeStamp, String systemIdActor, String userIdActor, String networkHostnameTarget,
			String networkIPAddressTarget, long requestResponseSize, String subnetIdInitiator, String subnetIdActor,
			String subnetIdTarget, String networkIPAddressActor, String networkIPAddressInitiator) {
		this.timeStamp = this.convertToEntityAttribute(timeStamp);
		this.systemIdActor = systemIdActor;
		this.userIdActor = userIdActor;
		this.networkHostnameTarget = networkHostnameTarget;
		this.networkIPAddressTarget = networkIPAddressTarget;
		this.requestResponseSize = requestResponseSize;
		this.subnetIdActor = subnetIdActor;
		this.subnetIdInitiator = subnetIdInitiator;
		this.subnetIdTarget = subnetIdTarget;
		this.networkIPAddressActor = networkIPAddressActor;
		this.networkIPAddressInitiator = networkIPAddressInitiator;
		this.score = 0;
	}

	@Override
	public String toString() {
		return "[Timestamp: " + timeStamp + "\nSystemIdActor: " + systemIdActor + "\nUserIdActing: " + userIdActor
				+ "\nNetworkHostnameTarget: " + networkHostnameTarget + "\nNetworkIPAddressTarget: "
				+ networkIPAddressTarget + "\nNatworkIPAddressActor: " + networkIPAddressActor
				+ "\nNetworkIPAddressInitiator: " + networkIPAddressInitiator + "\nResourceResponseSize:"
				+ requestResponseSize + "\nSubnetIdInitiator: " + subnetIdInitiator + "\nSubnetIdActor: "
				+ subnetIdActor + "\nSubnetIdTarget: " + subnetIdTarget + "\nScore: " + score + "]\n";
	}

	public static void main(String[] args) {

		try { // opening connection to HANA db
			connection = DriverManager.getConnection("jdbc:sap://ld3796.wdf.sap.corp:30015/?autocommit=false", myname,
					mysecret);
		} catch (SQLException e) {
			System.err.println("Error: Connection Failed");
			return;
		}
		// testing starts here, not needed when used productively?!
		// fake test data =======>
		// LogEvent logEvent = new LogEvent(java.util.Date("2018-01-20
		// 03:00:00.000000000"), "$T3/000", "552F9FEC6D382BA3E10000000A4CF109",
		// null, "33.76.141.255", 789, "BF96E0572011F351E11700000A600446",
		// "BF96E0572011F351E11700000A600446",
		// null, null, "33.76.141.50");
		// System.out.println("Fake example:");
		// logEvent.analysisLogEventAPT();
		// logEvent.analysisUnusualPortscanning();
		// System.out.println("Score: " + logEvent.score);
		// <======

		// test with real logs =========>
		LogEvent[] realLogEvents = createLogEvents(2);
		for (int i = 0; i < realLogEvents.length; i++) {
			System.out.println("\nNext LogEvent:");
			realLogEvents[i].analysisLogEventAPT();
			// System.out.println(realLogEvents[i].score);
		}
		// System.out.println(realLogEvents[0].timeStamp.);
		// <==============

	}

	// Note that this will use the system default time zone. Alternative:
	// LocalDateTime.ofInstant(new Instant(ts), ZoneId.of("UTC"));
	public Timestamp convertToDatabaseColumn(LocalDateTime ldt) {
		return Timestamp.valueOf(ldt);
	}

	public LocalDateTime convertToEntityAttribute(Timestamp ts) {
		if (ts != null) {
			return ts.toLocalDateTime();
		}
		return null;
	}

	// it's necessary to check whether '%s' or similar wrongly mapped data is
	// written in the table
	// die letzten fünf minuten oder so anschauen
	public static LogEvent[] createLogEvents(int numberOfLogs) {
		LogEvent[] logEvents = new LogEvent[numberOfLogs];
		try {
			Statement stmt = connection.createStatement();

			ResultSet resultSet = stmt.executeQuery("SELECT TOP " + numberOfLogs
					+ " \"Timestamp\", \"SystemIdActor\", CAST(\"UserIdActing\" AS VARCHAR), \"NetworkHostnameTarget\","
					+ "\"NetworkIPAddressTarget\", \"ResourceResponseSize\", CAST(\"NetworkSubnetIdInitiator\" AS VARCHAR), CAST(\"NetworkSubnetIdActor\" AS VARCHAR), "
					+ "CAST(\"NetworkSubnetIdTarget\" AS VARCHAR),    \"NetworkIPAddressActor\", \"NetworkIPAddressInitiator\", CAST(\"Id\" AS VARCHAR) "
					+ "FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" WHERE \"NetworkIPAddressTarget\" IS NOT NULL AND SUBSTRING(\"NetworkIPAddressTarget\", 0, 1) <> '%'"
					+ "AND SUBSTRING(\"NetworkIPAddressTarget\", 0, 1) <> '(' AND SUBSTRING(\"NetworkIPAddressTarget\", 0, 1) <> '%' AND \"SystemIdActor\" = '$T3/000'");
			// = 'f' AND SUBSTRING(\"NetworkIPAddressInitiator\", 0, 1) = 'f'");
			// <> '(' AND \"SystemIdActor\" = '$T3/000';");
			// AND SUBSTRING(\"NetworkIPAddressTarget\", 0, 2) <> 'fe'
			for (int i = 0; i < logEvents.length; i++) {
				resultSet.next();
				long responseSize;
				if (resultSet.getString(6) == null) {
					responseSize = 0;
				} else {
					responseSize = resultSet.getLong(6);
				}
				logEvents[i] = new LogEvent(resultSet.getTimestamp(1), resultSet.getString(2), resultSet.getString(3),
						resultSet.getString(4), resultSet.getString(5), responseSize, resultSet.getString(7),
						resultSet.getString(8), resultSet.getString(9), resultSet.getString(10),
						resultSet.getString(11));
			}

		} catch (SQLException e) {
			System.err.println("Error: Query  Failed @CreateLogEvents");
		}
		for (int i = 0; i < logEvents.length; i++) {
			System.out.println(logEvents[i]);
		}
		return logEvents;
	}

	public int analysisLogEventAPT() {
		if (analysisUnusualProtocol())
			score++;
		System.out.println(score + ", protocol");
		if (analysisUnusualSystem())
			score++;
		System.out.println(score + ", system");
		if (analysisUnusualTime())
			score++;
		System.out.println(score + ", time");
		if (analysisUnusualHostOrIp())
			score++;
		System.out.println(score + ", host&/ IP");
		if (requestResponseSize != 0) {
			if (analysisUnusuallyLowNumberOfBytes())
				score++;
		}
		System.out.println(score + ", bytes");
		if (analysisUnusualSubnetConnection())
			score++;
		System.out.println(score + ",subnet");
		if (analysisUnusualPortscanning())
			score++;
		System.out.println(score + ", portscanning");

		return score;
	}

	// analysis: log at unusual time? (based on User ID!)
	// use activity in last 2 hours and last 10 minutes
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
								+ "WHERE \"UserIdActing\" = '" + userIdActor + "' AND \"Timestamp\" BETWEEN '"
								+ this.convertToDatabaseColumn(timeStamp.minusHours(2)) + "' AND '"
								+ this.convertToDatabaseColumn(timeStamp) + "';");
				// '31.01.2018 12:00:00.0' AND '31.01.2018 14:00:00.0'");
				resultSet.next();
				numberOfLogsTwoHours = resultSet.getInt(1);
				medianTwoHours = (numberOfLogsTwoHours / 120) * 0.5;

				ResultSet resultSetLast10Minutes = stmt.executeQuery(
						"SELECT COUNT (\"UserIdActing\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
								+ "WHERE \"UserIdActing\" = '" + userIdActor + "' AND \"Timestamp\" BETWEEN '"
								+ this.convertToDatabaseColumn(timeStamp.minusHours(2)) + "' AND '"
								+ this.convertToDatabaseColumn(timeStamp) + "';");
				// '31.01.2018 13:50:00.0' AND '31.01.2018 14:00:00.0'");
				resultSetLast10Minutes.next();
				numberOfLogsTenMinutes = resultSetLast10Minutes.getInt(1);
				medianTenMinutes = numberOfLogsTenMinutes / 10;

				if (medianTenMinutes < medianTwoHours) {
					restPeriod = true;
				} else {
					restPeriod = false;
				}

			} catch (SQLException e) {
				System.err.println("Query failed! @TimeAnalysis");
			}
		}
		// System.out.println(restPeriod);
		return restPeriod;
	}

	// returns true, if the user has never successfully logged onto the system
	// before
	// erweiterung: unerfolgreiche anmeldung
	private boolean analysisUnusualSystem() {
		// todo also check failed logins?
		boolean unusualSystem = false;
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
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"Timestamp\" BETWEEN '"
								+ this.convertToDatabaseColumn(timeStamp.minusMonths(3)) + "' AND '"
								+ this.convertToDatabaseColumn(timeStamp) + "'"
								// '01.11.2017 00:00:00.0' AND '06.02.2018
								// 00:00:00.0'"
								+ "GROUP BY \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"SystemIdActor\","
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"Timestamp\", \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"UserIdActing\","
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"eventName.name\"");
				// numberOfLogins = Integer.parseInt(resultSet.getString(1));
				resultSet.next();
				// System.out.println(resultSet.getInt(1));
				numberOfLogins = resultSet.getLong(1);
				System.out.println(numberOfLogins);
				if (numberOfLogins > 0) {
					unusualSystem = false;
				} else {
					unusualSystem = true;
				}

			} catch (SQLException e) {
				System.err.println("Query failed! @SystemAnalysis");
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

	// wenn der host später öfter genommen wird dann ist es nicht ungewöhnlich
	// analyse für "älktere" daten, eg vor einer stunde/tag; vergangene zukunft;
	// 3 wochen oder so in vergangenheit; ggf zusätzlich
	// -> ist es plötzlich normal geworden?
	private boolean analysisUnusualHostOrIp() {
		boolean unusualHost = false;
		long numberOfFormerConnections;

		if (connection != null) {
			try {
				if (networkIPAddressTarget != null && networkHostnameTarget == null) {
					System.out.println("ip given; no hostname");
					Statement stmt = connection.createStatement();
					ResultSet resultSet = stmt.executeQuery(
							"SELECT COUNT (\"UserIdActing\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
									+ "WHERE \"UserIdActing\" = '" + userIdActor
									+ "' AND \"NetworkIPAddressTarget\" = '" + networkIPAddressTarget
									+ "' AND \"NetworkHostnameTarget\" IS NULL");
					resultSet.next();
					numberOfFormerConnections = resultSet.getLong(1);
					System.out.println(numberOfFormerConnections);

					if (numberOfFormerConnections > 0) {
						unusualHost = false;
					} else {
						unusualHost = true;
					}

				} else if (networkIPAddressTarget == null && networkHostnameTarget != null) {
					System.out.println("no ip; hostname given");
					Statement stmt = connection.createStatement();
					ResultSet resultSet = stmt.executeQuery(
							"SELECT COUNT(\"UserIdActing\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
									+ "WHERE \"UserIdActing\" = '" + userIdActor
									+ "' AND \"NetworkIPAddressTarget\" IS NULL AND \"NetworkHostnameTarget\" = '"
									+ networkHostnameTarget + "'");
					resultSet.next();
					numberOfFormerConnections = resultSet.getLong(1);
					System.out.println(numberOfFormerConnections);

					if (numberOfFormerConnections > 0) {
						unusualHost = false;
					} else {
						unusualHost = true;
					}

				} else if (networkIPAddressTarget != null && networkHostnameTarget != null) {
					System.out.println("ip given; hostname given");
					Statement stmt = connection.createStatement();
					ResultSet resultSet = stmt.executeQuery(
							"SELECT COUNT(\"UserIdActing\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
									+ "WHERE \"UserIdActing\" = '" + userIdActor
									+ "' AND \"NetworkIPAddressTarget\" = '" + networkIPAddressTarget
									+ "' AND \"NetworkHostnameTarget\" = '" + networkHostnameTarget + "';");

					resultSet.next();
					numberOfFormerConnections = resultSet.getLong(1);
					System.out.println(numberOfFormerConnections);

					if (numberOfFormerConnections > 0) {
						unusualHost = false;
					} else {
						unusualHost = true;
					}

				} else {
					System.err.println("Failed, no IP Address and/or Hostname.");
				}

			} catch (SQLException e) {
				System.err.println("Query failed! @ IP/HostAnalysis");
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
						"SELECT AVG(\"ResourceResponseSize\") * 0.1  FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\""
								+ "WHERE \"UserIdActing\" = '" + userIdActor + "'"
								+ " AND \"ResourceResponseSize\" IS NOT NULL");
				// - STDDEV(\"ResourceResponseSize\")
				resultSet.next();
				if (this.requestResponseSize <= resultSet.getDouble(1)) {
					lowNumberOfBytes = true;
				} else {
					lowNumberOfBytes = false;
				}

			} catch (SQLException e) {
				System.err.println("Query failed! @ByteAnalysis");
			}

		}
		return lowNumberOfBytes;
	}

	// wenns danach oft aufgerufen wird dann ist es nciht ungewöhnlich.
	// t in der vergangenheit wählen für vergangene zukunft
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
					if (resultSet.getInt(1) < 2) {
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
							if (resultSetCase2.getInt(1) < 2) {
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
							if (resultSetCase3.getInt(1) < 2) {
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
									if (resultSetCase4.getInt(1) < 2) {
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
				System.err.println("Query failed! @SubnetAnalysis");
			}

		}
		return unusualSubnetConnection;
	}

	private boolean analysisUnusualPortscanning() {
		/*
		 * todo check whether these IPs frequently have contact and not only
		 * once, check for subnet as well
		 */
		boolean unusualPortScanning = false;
		if (connection != null) {
			try {
				if (networkIPAddressTarget != null) {
					Statement stmt = connection.createStatement();
					if (networkIPAddressInitiator != null) {
						// check for portscanning from the initiator IP address
						if (this._checkUnusualPortscanning("initiator", stmt)) {
							// portscanning from the initiator IP
							unusualPortScanning = true;
							return unusualPortScanning;
						} else { // check for portscanning from the actor IP
							if (networkIPAddressActor != null) {
								return this._checkUnusualPortscanning("actor", stmt);
							} else {
								// no portscanning from initiator or actor ip
								// address
								unusualPortScanning = false;
								return unusualPortScanning;
							}
						}
					} else { // no initiator IP address given
						if (networkIPAddressActor != null) {
							return this._checkUnusualPortscanning("actor", stmt);
						} else {
							System.err.println("IP analysis impossible: actor and initiator IP is missing.");
						}
					}
				} else {
					System.err.println("IP analysis impossible: target IP is missing.");
				}

			} catch (SQLException e) {
				System.err.println("Query failed! @PortscanningAnalysis");
			}
		}
		return unusualPortScanning;
	}

	// ipAddress should either contain "actor" or "initiator"
	// transform ipv4 address into ipv6 adress
	private boolean _checkUnusualPortscanning(String ipAddress, Statement stmt) {
		boolean unusualPortScanning = false;
		String ipName = null;
		String comparableIPAddress = null;
		String[] ip_compare = null;
		String[] ip_target;

		// check whether the Target Ip is in Ipv4 or ipv6 format
		// muss man eigentlich noch nach herkunft gruppieren
		// vergangene zukunft; gibts in der zukunft mehr als n wenn es jetzt in
		// der vergangenheit nicht mehr als n gab
		if (networkIPAddressTarget.length() <= 15) { // IPv4
			System.out.println("IPv4");
			ip_target = networkIPAddressTarget.split("\\.");
			if (ipAddress == "actor" && networkIPAddressActor.length() <= 15) {
				ip_compare = networkIPAddressActor.split("\\.");
				ipName = "NetworkIPAddressActor";
				comparableIPAddress = networkIPAddressActor;
			} else if (ipAddress == "initiator" && networkIPAddressInitiator.length() <= 15) {
				ip_compare = networkIPAddressInitiator.split("\\.");
				ipName = "NetworkIPAddressInitiator";
				comparableIPAddress = networkIPAddressInitiator;
			} else {
				System.err.println(
						"Error: ipAddress does not contain \"actor\" or \"initiator\" or has a different IP format");
				return false;
			}

			//
			if (Integer.parseInt(ip_compare[0]) == Integer.parseInt(ip_target[0])
					&& Integer.parseInt(ip_compare[1]) == Integer.parseInt(ip_target[1])
					&& Integer.parseInt(ip_compare[2]) == Integer.parseInt(ip_target[2])
					&& Integer.parseInt(ip_compare[3]) != Integer.parseInt(ip_target[3])) {
				// first 3 numbers of ip identical, last
				// different
				// compare past connections: IP Scanning?
				try {
					String ip_substring = ip_compare[0] + "." + ip_compare[1] + "." + ip_compare[2] + ".";
					int substring_length = ip_substring.length();
					int deviceIPLength = ip_compare[3].length();
					ResultSet resultSet = stmt.executeQuery("SELECT COUNT(\"" + ipName
							+ "\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" " + "WHERE \"" + ipName + "\" = '"
							+ comparableIPAddress + "' AND SUBSTRING(\"NetworkIPAddressTarget\", 0, " + substring_length
							+ ") = '" + ip_substring + "' AND SUBSTRING(\"NetworkIPAddressTarget\", "
							+ (substring_length + 1) + ", " + deviceIPLength + ") <> '" + ip_compare[3]
							+ "' AND \"Timestamp\" BETWEEN '" + this.convertToDatabaseColumn(timeStamp.minusWeeks(1))
							+ "' AND '" + this.convertToDatabaseColumn(timeStamp) + "';");
					// 24.01.2018 00:00:00.0' AND '31.01.2018 00:00:00.0'");
					resultSet.next();
					if (resultSet.getInt(1) > 4) {
						unusualPortScanning = true;
					} else {
						unusualPortScanning = false;
					}

				} catch (SQLException e) {
					System.err.println("Query failed! @PortscanningAnalysisInnerMethod");
				}
			} else {
				// ip addresses aren't neighboring addresses
				unusualPortScanning = false;
			}
		} else { // IPv6
			System.out.println("IPv6");
			ip_target = networkIPAddressTarget.split(":");
			if (ipAddress == "actor" && networkIPAddressActor.length() > 15) {
				ip_compare = networkIPAddressActor.split(":");
				ipName = "NetworkIPAddressActor";
				comparableIPAddress = networkIPAddressActor;
			} else if (ipAddress == "initiator" && networkIPAddressInitiator.length() > 15) {
				ip_compare = networkIPAddressInitiator.split(":");
				ipName = "NetworkIPAddressInitiator";
				comparableIPAddress = networkIPAddressInitiator;
			} else {
				System.err.println(
						"Error: ipAddress does not contain \"actor\" or \"initiator\" or has a different IP format");
				return false;
			}
			// ============== //this is probably working, test!
			if (Integer.parseInt(ip_compare[0]) == Integer.parseInt(ip_target[0])
					&& Integer.parseInt(ip_compare[1]) == Integer.parseInt(ip_target[1])
					&& Integer.parseInt(ip_compare[2]) == Integer.parseInt(ip_target[2])
					&& Integer.parseInt(ip_compare[3]) == Integer.parseInt(ip_target[3]) // ^network;
																							// device
																							// >
					&& (Integer.parseInt(ip_compare[4]) != Integer.parseInt(ip_target[4])
							|| Integer.parseInt(ip_compare[5]) != Integer.parseInt(ip_target[5])
							|| Integer.parseInt(ip_compare[6]) != Integer.parseInt(ip_target[6])
							|| Integer.parseInt(ip_compare[7]) != Integer.parseInt(ip_target[7]))) {
				// first 4 numbers of IP identical (network) at least one of the
				// last 4 numbers differs (device)
				// compare past connections: IP Scanning?
				try {
					String ip_substring = ip_compare[0] + ":" + ip_compare[1] + ":" + ip_compare[2] + ":"
							+ ip_compare[3];
					String ip_device = ip_compare[4] + ":" + ip_compare[5] + ":" + ip_compare[6] + ":" + ip_compare[7];
					int substring_length = ip_substring.length();
					int deviceIPLength = ip_device.length();
					ResultSet resultSet = stmt.executeQuery("SELECT COUNT(\"" + ipName
							+ "\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" " + "WHERE \"" + ipName + "\" = '"
							+ comparableIPAddress + "' AND SUBSTRING(\"NetworkIPAddressTarget\", 0, " + substring_length
							+ ") = '" + ip_substring + "' AND SUBSTRING(\"NetworkIPAddressTarget\", "
							+ (substring_length + 1) + ", " + deviceIPLength + ") <> '" + ip_device
							+ "' AND \"Timestamp\" BETWEEN '" + this.convertToDatabaseColumn(timeStamp.minusWeeks(1))
							+ "' AND '" + this.convertToDatabaseColumn(timeStamp) + "';");
					// BETWEEN '24.01.2018 00:00:00.0' AND '31.01.2018
					// 00:00:00.0'");
					resultSet.next();
					if (resultSet.getInt(1) > 4) {
						unusualPortScanning = true;
					} else {
						unusualPortScanning = false;
					}

				} catch (SQLException e) {
					System.err.println("Query failed! @PortscanningAnalysisInnerMethod");
				}
			} else {
				// ip addresses aren't neighboring addresses
				unusualPortScanning = false;
			}
			// ==============
		}

		return unusualPortScanning;
	}

}

// while (resultSet.next()) {
// for (int i = 0; i <= resultSet.getMetaData().getColumnCount();
// i++) {
// if (i > 0) {
// String columnValue = resultSet.getString(i);
// System.out.print(resultSet.getMetaData().getColumnName(i) + ": "
// + columnValue);
// System.out.print(", ");
//
// }
// System.out.println("");
// }
// }
