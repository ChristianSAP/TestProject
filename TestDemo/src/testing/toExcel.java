package testing;

import java.io.*;

/**
 * this class is 100% useless and was created in the process of programming the class LogOutageDetection
 * @author D067608
 *
 */
public class toExcel {
	public static void main(String[] args) {
		File file = new File("C:/Users/D067608/git/TestProject2/LogFalloutData.csv");
		try {
			writeData(file);
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
	}

	public static void writeData(File logFalloutData) throws IOException {
		FileReader reader;
		FileWriter writer;

		reader = new FileReader(logFalloutData);
		writer = new FileWriter(logFalloutData);

		writer.write("\n100");
		writer.append("T");
		
		reader.close();
		writer.close();
	}

}
