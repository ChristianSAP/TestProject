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
	static Writer writer;

	public static void main(String[] args) throws InterruptedException, IOException {
		// open connection to HANA db
		try {
			connection = DriverManager.getConnection("jdbc:sap://ld3796.wdf.sap.corp:30015/?autocommit=false", myname,
					mysecret);
		} catch (SQLException e) {
			System.err.println("Error: HANA DB Connection Failed");
			return;
		}

		execution = new Runnable() {
			public void run() {
				try {
					executeLogOutageDetection(getCSVFileWriter());
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
					System.err.println("Error in method: " + e.getMessage());
				}
			}
		};
		handler = scheduler.scheduleAtFixedRate(execution, 0, 5, MINUTES);
		// MINUTES);

		scheduler.schedule(new Runnable() {
			public void run() {

				handler.cancel(true);
			}
		}, 4*60, MINUTES);

	}

	public static void executeLogOutageDetection(Writer writer) throws IOException {

		try {
			Statement stmt = connection.createStatement();
			// check for log outages
			System.out.println("Log Outages:");
			ResultSet resultSet = stmt.executeQuery(
					"select distinct( concat( \"LE\".\"EventLogType\", concat( ',', \"LE\".\"TechnicalLogCollectorName\" ) ) ), count(*), MAX(\"LE\".\"Timestamp\") "
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
				// write data to csv file
				Timestamp timestamp = new Timestamp(System.currentTimeMillis());
				writer.write(timestamp + ";");
				String[] columnValue = resultSet.getString(1).split(",");
				writer.write(columnValue[1] + ";" + columnValue[0] + ";");
				String TSofFallout = resultSet.getString(3);
				writer.write(TSofFallout + ";");
				String score = resultSet.getString(2);
				writer.write(";;;\n");
				// print out on system
				for (int i = 1; i <= resultSet.getMetaData().getColumnCount(); i++) {
					String columnValue11 = resultSet.getString(i);
					System.out.println(columnValue11);

					// System.out.println("");
				}
			}

			// check for log comebacks
			System.out.println("\nLog Comebacks:");
			ResultSet resultSetCB = stmt.executeQuery(
					"select distinct( concat( \"LE\".\"EventLogType\", concat( ',', \"LE\".\"TechnicalLogCollectorName\" ) ) ), count(*), MIN(\"LE\".\"Timestamp\")"
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
				// save in CSV file
				Timestamp timestamp = new Timestamp(System.currentTimeMillis());
				writer.write(timestamp + ";");
				String[] columnValue = resultSetCB.getString(1).split(",");
				writer.write(columnValue[1] + ";" + columnValue[0] + ";");
				String score = resultSetCB.getString(2);
				String TSofResurrection = resultSetCB.getString(3);
				writer.write(";" +TSofResurrection + ";;;\n");
				// print out 
				for (int i = 1; i <= resultSetCB.getMetaData().getColumnCount(); i++) {
					String columnValue11 = resultSetCB.getString(i);
					System.out.println(columnValue11);
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
		FileWriter writer = new FileWriter(file, true);
		return writer;
	}

}
