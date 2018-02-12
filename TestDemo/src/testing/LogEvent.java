package testing;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.IOException;
import java.sql.*;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;

import sun.usagetracker.UsageTrackerClient;

/**
 * This class analyzes whether a log is unusual in a way that could give
 * conclusions/indications about a possible APT/malware infection
 * 
 * @author D067608
 * @version 07.02.2018
 * 
 */

/*
 * TODO: - windows log von servern subnetze qualifizieren direkte tcp -
 * kommunikation: protokolle ausschließen, nachlesen was browser macht - insert
 * ungewöhnliches protokoll bspw fdp - while schleife in main, stoppbar machen
 * (eg file erzeugen & überprüfen, ob dieses existiert (aktuell einfah für zeit
 * t gestarttet). wenn ja dann löschen&stoppen) -> Konsolenbefehl starten,
 * stoppen ; check if numAnalyzed is incremented at correct times; create
 * indicators; use IPAddress when useridacting is not given
 * 
 * erledigt: - 2 routinen: letzte 2/3 minuten -> alle 2/3 minuten ausführen für
 * vergangene zukunft: wird alle 3 Minuten für die letzten 3 minuten ausgeführt
 * - Loop Routine: alle 3 Minuten mit delay; - wenn mehr als 100 IP verbindungen
 * von der ip zu nachbar ips waren ist es nicht mehr ungewöhnlich
 * 
 * halb: - Score: Indicator erzeugen (score > 3 oder machine learning) in
 * Log.Events Tabelle mit "EventLogType" = 'Indicator'; wird aktuell in Janas
 * private Tabelle eingefügt correlationId nutzen um mehrere indikatoren zu
 * verbinden
 * 
 */
public class LogEvent {
	// lower limit for score
	int lowerScoreLimit = 3;
	// variables for HANA db connection
	static Connection connection = null;
	static String myname = "ETD_TEST_CLIENT";
	static String mysecret = "Initial04";
	// variables for running the program with delay
	private final static ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
	static Runnable executeAnalysis = null;
	static ScheduledFuture<?> handlerAnalysis = null;
	static Runnable executeAnalysisPastFuture = null;
	static ScheduledFuture<?> handlerAnalysisPastFuture = null;
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
	double score;
	String logEventId;
	int numAnalyzed;
	boolean unusualHostOrIp;
	boolean unusualSystem;
	boolean unusualSubnetConnection;
	boolean unusualProtocol;
	boolean unusualTime;
	boolean unusualLowNumOfBytes;
	boolean unusualPortscanning;
	String protocol;

	public LogEvent(Timestamp timeStamp, String systemIdActor, String userIdActor, String networkHostnameTarget,
			String networkIPAddressTarget, long requestResponseSize, String subnetIdInitiator, String subnetIdActor,
			String subnetIdTarget, String networkIPAddressActor, String networkIPAddressInitiator, String logEventId,
			String protocol) {
		this.timeStamp = convertToEntityAttribute(timeStamp);
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
		this.logEventId = logEventId;
		numAnalyzed = 0;
		this.protocol = protocol;
	}

	@Override
	public String toString() {
		return "[Timestamp: " + timeStamp + "\nID: " + logEventId + "\nSystemIdActor: " + systemIdActor
				+ "\nUserIdActing: " + userIdActor + "\nNetworkHostnameTarget: " + networkHostnameTarget
				+ "\nNetworkIPAddressTarget: " + networkIPAddressTarget + "\nNatworkIPAddressActor: "
				+ networkIPAddressActor + "\nNetworkIPAddressInitiator: " + networkIPAddressInitiator
				+ "\nResourceResponseSize:" + requestResponseSize + "\nSubnetIdInitiator: " + subnetIdInitiator
				+ "\nSubnetIdActor: " + subnetIdActor + "\nSubnetIdTarget: " + subnetIdTarget + "\nScore: " + score
				+ "]\n";
	}

	public static void main(String[] args) {
		try { // opening connection to HANA db
			connection = DriverManager.getConnection("jdbc:sap://ld3796.wdf.sap.corp:30015/?autocommit=false", myname,
					mysecret);
		} catch (SQLException e) {
			System.err.println("Error: Connection Failed");
			return;
		}

		// VERSION A of running the program: with delay:
		executeAnalysis = new Runnable() {
			public void run() { // get logs of last 3 minutes & analyze them
				LinkedList<LogEvent> logEventList = getLogEvents(3,
						convertToEntityAttribute(new Timestamp(System.currentTimeMillis())), null);

				for (int i = 0; i < logEventList.size(); i++) {
					logEventList.get(i).analysisLogEventAPT();
				}
			}
		};

		executeAnalysisPastFuture = new Runnable() {
			public void run() { // get indicator logs beween 2h ago and 4h ago
								// and analyze them
				LinkedList<LogEvent> logEventList = getLogEvents(60 * 2,
						convertToEntityAttribute(new Timestamp(System.currentTimeMillis())).minusHours(2),
						" AND \"EventLogType\" = 'Indicator'");
				for (int i = 0; i < logEventList.size(); i++) {
					logEventList.get(i).analyzePastFuture();
				}

			}
		};
		// every 5 minutes the logs of the past 3 minutes are analyzed
		handlerAnalysis = scheduler.scheduleAtFixedRate(executeAnalysis, 0, 3, MINUTES);
		// every 2h the indicator logs that are 2 - 4h old are analyzed
		handlerAnalysisPastFuture = scheduler.scheduleAtFixedRate(executeAnalysisPastFuture, 0, 2 * 60, MINUTES);

		// program is stopped after 10 minutes
		scheduler.schedule(new Runnable() {
			public void run() {
				handlerAnalysis.cancel(true);
				handlerAnalysisPastFuture.cancel(true);
			}
		}, 10, MINUTES);

		// VERSION B of running the program: n logs (does not execute analysis
		// of the past future
		/*
		 * LogEvent[] realLogEvents = createLogEvents(n); for (int i = 0; i <
		 * realLogEvents.length; i++) { System.out.println("\nNext LogEvent:");
		 * realLogEvents[i].analysisLogEventAPT(); //
		 * System.out.println(realLogEvents[i].score); }
		 */
		// System.out.println(realLogEvents[0].timeStamp.);
	}

	/**
	 * analyses whether a host/IP/subnet connection that was once unusual has
	 * become usual. We save the timestamp in a temp variable and overwrite it
	 * with the current timestamp for analyse purpose
	 */
	// TODO analyze future past of portscanning: does the number of pings
	// increase?
	public void analyzePastFuture() {
		// 1. What makes this log unusual
		// 2. did that thing become usual within the last 2h?
		// 3. if so, this is no longer an indicator -> delete entry/change
		// EventLogType
		LocalDateTime tempTS = this.timeStamp;
		if (analysisLogEventAPT() >= lowerScoreLimit) {
			// TODO verify that this is actually an APT indicator. If it isn't
			// we can't just delete it later!
			this.timeStamp = LocalDateTime.now().minusHours(1);
			if (unusualHostOrIp) {
				if (!analysisUnusualHostOrIp()) {
					unusualHostOrIp = false;
					score--;
				}
			}
			if (unusualSubnetConnection) {
				if (!analysisUnusualSubnetConnection()) {
					unusualSubnetConnection = false;
					score--;
				}
			}

			if (score >= lowerScoreLimit) {
				this.timeStamp = tempTS;
				Statement stmt;
				try {
					stmt = connection.createStatement();
					stmt.executeQuery("DELETE FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" WHERE \"Id\" = '"
							+ logEventId + "';");
				} catch (SQLException e) {
					System.err.println(
							"ERROR: Could not update table entry to no longer be an indicator." + e.getMessage());
				}

			}
		}

	}

	/**
	 * Note that this will use the system default time zone. Alternative:
	 * LocalDateTime.ofInstant(new Instant(ts), ZoneId.of("UTC")); to avoid this
	 * problem we use minusHours(1) but this only works in UTC+1 time zone
	 */
	public static Timestamp convertToDatabaseColumn(LocalDateTime ldt) {
		return Timestamp.valueOf(ldt.minusHours(1));
	}

	public static LocalDateTime convertToEntityAttribute(Timestamp ts) {
		if (ts != null) {
			return ts.toLocalDateTime().minusHours(1);
		}
		return null;
	}

	public static LinkedList<LogEvent> getLogEvents(int minutes, LocalDateTime end, String condition) {
		Timestamp timestamp = convertToDatabaseColumn(end);
		LinkedList<LogEvent> logEventList = new LinkedList<>();
		long responseSize;
		try {
			Statement stmt = connection.createStatement();

			ResultSet resultSet = stmt.executeQuery("SELECT "
					+ " \"Timestamp\", \"SystemIdActor\", CAST(\"UserIdActing\" AS VARCHAR), \"NetworkHostnameTarget\","
					+ "\"NetworkIPAddressTarget\", \"ResourceResponseSize\", CAST(\"NetworkSubnetIdInitiator\" AS VARCHAR), CAST(\"NetworkSubnetIdActor\" AS VARCHAR), "
					+ "CAST(\"NetworkSubnetIdTarget\" AS VARCHAR),    \"NetworkIPAddressActor\", \"NetworkIPAddressInitiator\", CAST(\"Id\" AS VARCHAR), \"NetworkProtocol\" "
					+ "FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" WHERE SUBSTRING(\"NetworkIPAddressTarget\", 0, 1) <> '%'"
					+ "AND SUBSTRING(\"NetworkIPAddressTarget\", 0, 1) <> '(' AND \"Timestamp\" BETWEEN '"
					+ convertToDatabaseColumn(convertToEntityAttribute(timestamp).minusMinutes(5)) + "' AND '"
					+ timestamp + "'" + condition);

			while (resultSet.next()) {
				if (resultSet.getString(6) == null) {
					responseSize = 0;
				} else {
					responseSize = resultSet.getLong(6);
				}
				logEventList.add(new LogEvent(resultSet.getTimestamp(1), resultSet.getString(2), resultSet.getString(3),
						resultSet.getString(4), resultSet.getString(5), responseSize, resultSet.getString(7),
						resultSet.getString(8), resultSet.getString(9), resultSet.getString(10),
						resultSet.getString(11), resultSet.getString(12), resultSet.getString(13)));
			}

		} catch (SQLException e) {
			System.err.println("Error: Query  Failed @getLogEvents");
		}

		return logEventList;
	}

	/**
	 * it's necessary to check whether '%s' or similar wrongly mapped data is
	 * written in the table die letzten fünf minuten oder so anschauen
	 */

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
						resultSet.getString(11), resultSet.getString(12), resultSet.getString(13));
			}

		} catch (SQLException e) {
			System.err.println("Error: Query  Failed @CreateLogEvents");
		}
		for (int i = 0; i < logEvents.length; i++) {
			System.out.println(logEvents[i]);
		}
		return logEvents;
	}

	/**
	 * Calls all analysis methods creates an indicator when the total score is
	 * GE 3 (-> ML possible) TODO could use ML for determining how high a
	 * high/unusual score is
	 * 
	 * @return total score of analysis
	 */

	public double analysisLogEventAPT() {

		if (analysisUnusualProtocol()) {
			score++;
			unusualProtocol = true;
		}

		score += analysisUnusualSystem();

		if (analysisUnusualTime()) {
			score++;
			unusualTime = true;
		}

		if (analysisUnusualHostOrIp()) {
			score++;
			unusualHostOrIp = true;
		}

		if (requestResponseSize != 0) {
			if (analysisUnusuallyLowNumberOfBytes())
				score++;
			unusualLowNumOfBytes = true;
		}

		if (analysisUnusualSubnetConnection()) {
			score++;
			unusualSubnetConnection = true;
		}

		if (analysisUnusualPortscanning()) {
			score++;
			unusualPortscanning = true;
		}

		if (score >= lowerScoreLimit) {
			try {
				Statement stmt = connection.createStatement();
				// TODO create indicator in sap_sec_mon log.events table
				// TODO connect this indicator with past indicators with a
				// correlationId
				stmt.executeQuery("INSERT INTO \"PFEFFERJA\".\"Log.Events::Indicators\" (\"Id\", \"Timestamp\","
						+ "\"SystemIdActor\", \"UserIdActing\", \"NetworkHostnameTarget\", \"NetworkIPAddressTarget\", \"ResourceResponseSize\", "
						+ "\"SubnetIdActor\", \"SubnetIdInitiator\", \"SubnetIdTarget\", \"NetworkIPAddressActor\", \"NetworkIPAddressInitiator\", "
						+ "\"Score\", \"NumberOfAnalysedFactors\")" + "(" + logEventId + "," + timeStamp + ","
						+ systemIdActor + "," + userIdActor + "," + networkHostnameTarget + "," + networkIPAddressTarget
						+ "," + requestResponseSize + "," + subnetIdActor + "," + subnetIdInitiator + ","
						+ subnetIdTarget + "," + networkIPAddressActor + "," + networkIPAddressInitiator + "," + score
						+ "," + numAnalyzed + ")");
			} catch (SQLException e) {
				System.err.println("Error: Could not create indicator;" + e.getMessage());
			}
		}

		return score;
	}

	/**
	 * analysis: log at unusual time? (based on User ID!); uses activity in last
	 * 2 hours and last 10 minutes
	 */
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
								+ convertToDatabaseColumn(timeStamp.minusHours(2)) + "' AND '"
								+ convertToDatabaseColumn(timeStamp) + "';");
				// '31.01.2018 12:00:00.0' AND '31.01.2018 14:00:00.0'");
				resultSet.next();
				numberOfLogsTwoHours = resultSet.getInt(1);
				medianTwoHours = (numberOfLogsTwoHours / 120) * 0.5;

				ResultSet resultSetLast10Minutes = stmt.executeQuery(
						"SELECT COUNT (\"UserIdActing\") FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
								+ "WHERE \"UserIdActing\" = '" + userIdActor + "' AND \"Timestamp\" BETWEEN '"
								+ convertToDatabaseColumn(timeStamp.minusHours(2)) + "' AND '"
								+ convertToDatabaseColumn(timeStamp) + "';");
				resultSetLast10Minutes.next();
				numberOfLogsTenMinutes = resultSetLast10Minutes.getInt(1);
				medianTenMinutes = numberOfLogsTenMinutes / 10;

				if (medianTenMinutes < medianTwoHours) {
					restPeriod = true;
				} else {
					restPeriod = false;
				}
				numAnalyzed++;
			} catch (SQLException e) {
				System.err.println("Query failed! @TimeAnalysis");
			}
		}
		return restPeriod;
	}

	private double analysisUnusualSystem() {
		boolean unusualSystem = false;
		long numberOfLogins;
		double logonScore = 0;
		if (connection != null) {
			try {
				Statement stmt = connection.createStatement();
				// check whether this is a logon
				ResultSet resultSetLogon = stmt.executeQuery(
						"SELECT \"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"eventName.name\""
								+ " FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\""
								+ " INNER JOIN \"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\" "
								+ " ON \"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"id\" = \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"TechnicalLogEntryType\""
								+ " WHERE \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"Id\" = '" + logEventId + "'");
				resultSetLogon.next();
				if (resultSetLogon.getString(1).substring(0, 8) == "UserLogon") {
					// this log contains a successful/failed logon
					if (resultSetLogon.getString(1).length() != 9) {
						// it's a failed logon
						_analysisFailedSystemLogons();
					} else {
						ResultSet resultSet = stmt.executeQuery(
								"SELECT TOP 1 COUNT(\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"TechnicalLogEntryType\"), \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"SystemIdActor\","
										+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"Timestamp\", \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"UserIdActing\","
										+ "\"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"eventName.name\""

										+ "FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\""
										+ "INNER JOIN \"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\" "
										+ "ON \"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"id\" = \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"TechnicalLogEntryType\""

										+ "WHERE \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"SystemIdActor\" = '"
										+ systemIdActor + "' AND "
										+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"UserIdActing\" = '"
										+ userIdActor + "' AND"
										+ "\"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"eventName.name\" = 'UserLogon' AND "
										+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"Timestamp\" BETWEEN '"
										+ convertToDatabaseColumn(timeStamp.minusMonths(3)) + "' AND '"
										+ convertToDatabaseColumn(timeStamp) + "'"
										+ "GROUP BY \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"SystemIdActor\","
										+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"Timestamp\", \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"UserIdActing\","
										+ "\"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"eventName.name\"");
						resultSet.next();
						numberOfLogins = resultSet.getLong(1);
						System.out.println(numberOfLogins);
						if (numberOfLogins > 0) {
							unusualSystem = false;
						} else {
							unusualSystem = true;
							logonScore = 1;
						}
					}
				}

				numAnalyzed++;
			} catch (SQLException e) {
				System.err.println("Query failed! @SystemAnalysis. This was not a Logon");
			}
		}
		return logonScore;
	}

	private double _analysisFailedSystemLogons() {
		int numberOfFailedLogins = 0;
		double failScore = 0;
		if (connection != null) {
			try {
				Statement stmt = connection.createStatement();
				ResultSet resultSet = stmt.executeQuery(
						"SELECT TOP 1 COUNT(\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"TechnicalLogEntryType\")"

								+ "FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\""
								+ "INNER JOIN \"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\" "
								+ "ON \"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"id\" = \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"TechnicalLogEntryType\""

								+ "WHERE \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"UserIdActing\" = '"
								+ userIdActor
								+ "' AND (SUBSTRING(\"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"eventName.name\", 0, 9) = 'UserLogon' OR "
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"eventName.name\" = 'UserAuthorizationCheckFail')"
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"eventName.name\" <> 'UserLogon' AND "
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"Timestamp\" BETWEEN '"
								+ convertToDatabaseColumn(timeStamp.minusMonths(3)) + "' AND '"
								+ convertToDatabaseColumn(timeStamp) + "'"
								+ "GROUP BY \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"SystemIdActor\","
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"Timestamp\", \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\".\"UserIdActing\","
								+ "\"SAP_SEC_MON\".\"sap.secmon.db::KnowledgeBase.LogEntryType\".\"eventName.name\"");
				resultSet.next();
				numberOfFailedLogins = resultSet.getInt(1);
				System.out.println(numberOfFailedLogins);
				if (numberOfFailedLogins < 100) {
					// in case of many failed logins it's likely that
					// a program is failing, this is no sign of an APT
					if (numberOfFailedLogins == 1) {
						failScore = 0.1;
					} else if (numberOfFailedLogins == 2) {
						failScore = 0.3;
					} else if (numberOfFailedLogins > 3) {
						unusualSystem = true;
						if (numberOfFailedLogins > 10) {
							failScore = 1;
						} else if (numberOfFailedLogins > 5) {
							failScore = 0.6;
						}

					}
				}
				numAnalyzed++;
			} catch (SQLException e) {
				System.err.println("Query failed! @FailedLogonSystemAnalysis");
			}
		}
		return failScore;
	}

	/**
	 * Checks, whether the protocol itself is unusual for a specific user (if
	 * given) or generally TODO unusual protocol in combination with other stuff
	 */

	private boolean analysisUnusualProtocol() {
		boolean unusualProtocol = false;
		if (connection != null) {
			try {
				Statement stmt = connection.createStatement();
				ResultSet resultSet = stmt
						.executeQuery("SELECT COUNT (*) FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" "
								+ "WHERE \"UserIdActing\" = '" + userIdActor + "'" + " AND \"NetworkProtocol\" = '"
								+ protocol + "'"); // TODO continue this
			} catch (Exception e) {
				System.err.println("Query failed @unusualProtocol");
			}
		}
		return unusualProtocol;
	}

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
					numAnalyzed++;
				} else {
					System.err.println("Failed, no IP Address and/or Hostname.");
				}

			} catch (SQLException e) {
				System.err.println("Query failed! @ IP/HostAnalysis");
			}
		}
		return unusualHost;
	}

	// TODO use ML for determining an unusually low number of bytes
	private boolean analysisUnusuallyLowNumberOfBytes() {
		boolean lowNumberOfBytes = false;
		if (connection != null) {
			try {
				Statement stmt = connection.createStatement();
				ResultSet resultSet = stmt.executeQuery(
						"SELECT AVG(\"ResourceResponseSize\") * 0.1  FROM \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\""
								+ "WHERE \"UserIdActing\" = '" + userIdActor + "'"
								+ " AND \"ResourceResponseSize\" IS NOT NULL");
				resultSet.next();
				if (this.requestResponseSize <= resultSet.getDouble(1)) {
					lowNumberOfBytes = true;
				} else {
					lowNumberOfBytes = false;
				}
				numAnalyzed++;
			} catch (SQLException e) {
				System.err.println("Query failed! @ByteAnalysis");
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
				numAnalyzed++;
			} catch (SQLException e) {
				System.err.println("Query failed! @SubnetAnalysis");
			}

		}
		return unusualSubnetConnection;
	}

	// TODO check whether these IPs frequently have contact and not only
	// once, check for subnet as well
	private boolean analysisUnusualPortscanning() {
		boolean unusualPortScanning = false;
		if (connection != null) {
			try {
				if (networkIPAddressTarget != null) {
					Statement stmt = connection.createStatement();
					if (networkIPAddressInitiator != null) {
						numAnalyzed++;
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
							numAnalyzed++;
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
	// TODO transform ipv4 address into ipv6 adress
	// TODO group by origin, are there more than x connections in the past
	// future when there were <= x connections in the past
	private boolean _checkUnusualPortscanning(String ipAddress, Statement stmt) {
		boolean unusualPortScanning = false;
		String ipName = null;
		String comparableIPAddress = null;
		String[] ip_compare = null;
		String[] ip_target;

		// check whether the Target Ip is in Ipv4 or ipv6 format
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
							+ "' AND \"Timestamp\" BETWEEN '" + convertToDatabaseColumn(timeStamp.minusWeeks(1))
							+ "' AND '" + convertToDatabaseColumn(timeStamp) + "';");
					resultSet.next();
					if (resultSet.getInt(1) > 4 && resultSet.getInt(1) < 100) {
						unusualPortScanning = true;
					} else {
						unusualPortScanning = false;
					}
					numAnalyzed++;
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
							+ "' AND \"Timestamp\" BETWEEN '" + convertToDatabaseColumn(timeStamp.minusWeeks(1))
							+ "' AND '" + convertToDatabaseColumn(timeStamp) + "';");
					// BETWEEN '24.01.2018 00:00:00.0' AND '31.01.2018
					// 00:00:00.0'");
					resultSet.next();
					if (resultSet.getInt(1) > 4 && resultSet.getInt(1) < 100) {
						unusualPortScanning = true;
					} else {
						unusualPortScanning = false;
					}
					numAnalyzed++;
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
