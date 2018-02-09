package testing;

import java.sql.*;
import static java.util.concurrent.TimeUnit.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;

public class LogOutageDetection {
	static Connection connection = null;
	static String myname = "ETD_TEST_CLIENT";
	static String mysecret = "Initial04";
	private final static ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

	public static void main(String[] args) throws InterruptedException {
		boolean execute = true;
		try { // open connection to HANA db
			connection = DriverManager.getConnection("jdbc:sap://ld3796.wdf.sap.corp:30015/?autocommit=false", myname,
					mysecret);
		} catch (SQLException e) {
			System.err.println("Error: Connection Failed");
			return;
		}
		final Runnable execution = new Runnable() {
			public void run() {
				executeLogOutageDetection();
			}
		};

		final ScheduledFuture<?> beeperHandle = scheduler.scheduleAtFixedRate(execution, 0, 5, SECONDS); //MINUTES);
		scheduler.schedule(new Runnable() {
			public void run() {
				beeperHandle.cancel(true);
			}
		}, 60 * 60, SECONDS);

	}

	public static void executeLogOutageDetection() {
		try {
			Statement stmt = connection.createStatement();
			// check for log outages
			System.out.println("Log Outages:");
			ResultSet resultSet = stmt.executeQuery(
					"select distinct( concat( \"LE\".\"EventLogType\", concat( ',', \"LE\".\"TechnicalLogCollectorName\" ) ) ), count(*) "
							+ "from \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" as \"LE\" "
							+ "where \"LE\".\"Timestamp\" between add_seconds ( CURRENT_UTCTIMESTAMP, -3600 ) and add_seconds ( CURRENT_UTCTIMESTAMP, -300 ) "
							+ "and \"LE\".\"EventLogType\" is not null "
							+ "and \"LE\".\"TechnicalLogCollectorName\" is not null "
							+ "and concat( \"LE\".\"EventLogType\", concat( ',', \"LE\".\"TechnicalLogCollectorName\" ) ) not in ( "
							+ "select "
							+ "distinct( concat( \"LE\".\"EventLogType\", concat( ',', \"LE\".\"TechnicalLogCollectorName\" ) ) ) "
							+ "from \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" as \"LE\" "
							+ "where \"LE\".\"Timestamp\" between add_seconds ( CURRENT_UTCTIMESTAMP, -300 ) and CURRENT_UTCTIMESTAMP "
							+ "and \"LE\".\"EventLogType\" is not null "
							+ "and \"LE\".\"TechnicalLogCollectorName\" is not null ) "
							+ "group by ( concat( \"LE\".\"EventLogType\", concat( ',', \"LE\".\"TechnicalLogCollectorName\" ) ) ) "
							+ "order by count(*) desc");

			while (resultSet.next()) {
				for (int i = 0; i <= resultSet.getMetaData().getColumnCount(); i++) {
					if (i > 0) {
						String columnValue = resultSet.getString(i);
						System.out.println(columnValue);

					}
					// System.out.println("");
				}
			}

			// check for log comebacks
			System.out.println("\nLog Comebacks:");
			ResultSet resultSetCB = stmt.executeQuery(
					"select distinct( concat( \"LE\".\"EventLogType\", concat( ',', \"LE\".\"TechnicalLogCollectorName\" ) ) ), count(*) "
							+ "from \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" as \"LE\" "
							+ "where \"LE\".\"Timestamp\" between add_seconds ( CURRENT_UTCTIMESTAMP, -300 ) and  CURRENT_UTCTIMESTAMP "
							+ "and \"LE\".\"EventLogType\" is not null "
							+ "and \"LE\".\"TechnicalLogCollectorName\" is not null "
							+ "and concat( \"LE\".\"EventLogType\", concat( ',', \"LE\".\"TechnicalLogCollectorName\" ) ) not in ( "
							+ "select "
							+ "distinct( concat( \"LE\".\"EventLogType\", concat( ',', \"LE\".\"TechnicalLogCollectorName\" ) ) ) "
							+ "from \"SAP_SEC_MON\".\"sap.secmon.db::Log.Events\" as \"LE\" "
							+ "where \"LE\".\"Timestamp\" between add_seconds ( CURRENT_UTCTIMESTAMP, -600 ) and add_seconds ( CURRENT_UTCTIMESTAMP, -300 ) "
							+ "and \"LE\".\"EventLogType\" is not null "
							+ "and \"LE\".\"TechnicalLogCollectorName\" is not null ) "
							+ "group by ( concat( \"LE\".\"EventLogType\", concat( ',', \"LE\".\"TechnicalLogCollectorName\" ) ) ) "
							+ "order by count(*) desc");

			while (resultSetCB.next()) {
				for (int i = 0; i <= resultSetCB.getMetaData().getColumnCount(); i++) {
					if (i > 0) {
						String columnValue = resultSetCB.getString(i);
						System.out.println(columnValue);

					}
				}
			}
			System.out.println("################################################################");
		} catch (SQLException e) {
			System.err.println("Query failed.");
			System.out.println(e.getMessage());
		}
	}

}
