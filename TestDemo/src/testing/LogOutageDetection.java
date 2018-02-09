package testing;

import java.sql.*;
import static java.util.concurrent.TimeUnit.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;

public class LogOutageDetection {
	// variables for HANA db connection
	static Connection connection = null;
	static String myname = "ETD_TEST_CLIENT";
	static String mysecret = "Initial04";
	// variables for periodic execution
	private final static ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
	static Runnable execution = null;
	static ScheduledFuture<?> handler = null;

	public static void main(String[] args) throws InterruptedException {
		// open connection to HANA db
		try {
			connection = DriverManager.getConnection("jdbc:sap://ld3796.wdf.sap.corp:30015/?autocommit=false", myname,
					mysecret);
		} catch (SQLException e) {
			System.err.println("Error: HANA DB Connection Failed");
			return;
		}

		// execute executeLogOutageDetection every 5 Minutes (Seconds)
		execution = new Runnable() {
			public void run() {
				try {
					executeLogOutageDetection();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		};
		handler = scheduler.scheduleAtFixedRate(execution, 0, 5, SECONDS);
		// MINUTES);

		scheduler.schedule(new Runnable() {
			public void run() {
				handler.cancel(true);
			}
		}, 60, SECONDS);

	}

	public static void executeLogOutageDetection() throws IOException {
		// get writer to write on CSV file LogFalloutData
		Writer writer = null;
		try {
			writer = getCSVFileWriter();
		} catch (IOException ioe) {
			System.err.println("Error: Cannot get file: " + ioe.getMessage());
		}

		// write header lines in CSV file
		writer.write("Timestamp;TechnicalLogColumnName;LogEvent;TimeOfFallout;TimeOfResurrection;Score;Okay;Reason");
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
				Timestamp timestamp = new Timestamp(System.currentTimeMillis());
				writer.write("\n" + timestamp + ";");
				for (int i = 1; i <= resultSet.getMetaData().getColumnCount(); i++) {
					if (i == 1) {
						String[] columnValue = resultSet.getString(i).split(",");
						writer.write(columnValue[1] + ";" + columnValue[0] + ";");
					} else {
						String columnValue = resultSet.getString(i);
						writer.write(";;" + columnValue + ";");
					}

					String columnValue = resultSet.getString(i);
					System.out.println(columnValue);

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
		writer.close();
	}

	public static Writer getCSVFileWriter() throws IOException {
		File file = new File("C:/Users/D067608/git/TestProject2/LogFalloutData.csv");
		FileWriter writer = new FileWriter(file);
		return writer;
	}

}
