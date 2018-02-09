package testing;

import java.sql.*;

public class LogOutageDetection {
	static Connection connection = null;
	static String myname = "ETD_TEST_CLIENT";
	static String mysecret = "Initial04";

	public static void main(String[] args) {
		boolean execute = true;
		try { // open connection to HANA db
			connection = DriverManager.getConnection("jdbc:sap://ld3796.wdf.sap.corp:30015/?autocommit=false", myname,
					mysecret);
		} catch (SQLException e) {
			System.err.println("Error: Connection Failed");
			return;
		}
		
		while (execute) {
			executeLogOutageDetection();
			execute = false;
		}

	}

	public static void executeLogOutageDetection() {
		try {
			Statement stmt = connection.createStatement();
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
						System.out.print(columnValue);
						System.out.print(", ");

					}
					System.out.println("");
				}
			 }
		} catch (SQLException e) {
			System.err.println("Query failed.");
			System.out.println(e.getMessage());
		}
	}

}
