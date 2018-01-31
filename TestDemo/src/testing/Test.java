package testing;

import java.sql.*;

public class Test {
       public static void main(String[] args) {
    	   //ich hab hier was geädbnet!!!!
             Connection connection = null;
             String myname = "ETD_TEST_CLIENT";
             String mysecret= "Initial04";
             try {                  
                connection = DriverManager.getConnection(
                   "jdbc:sap://ld3796.wdf.sap.corp:30015/?autocommit=false",myname,mysecret);                  
             } catch (SQLException e) {
                System.err.println("Connection Failed. User/Passwd Error?");
                return;
             }
             if (connection != null) {
                try {
                   System.out.println("Connection to HANA successful!");
                   Statement stmt = connection.createStatement();
                   ResultSet resultSet = stmt.executeQuery("Select 'hello world' from dummy");
                   resultSet.next();
                   String hello = resultSet.getString(1);
                   System.out.println(hello);
              } catch (SQLException e) {
                 System.err.println("Query failed!");
              }
            }
          }
       }
