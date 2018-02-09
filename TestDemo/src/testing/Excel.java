package testing;

import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.poi.xssf.usermodel.XSSFCell;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

public class Excel {
	public static void main(String[] args) throws IOException {
		XSSFWorkbook workbook = new XSSFWorkbook();
		XSSFSheet sheet = workbook.createSheet("First Sheet");
		int index = 0;
		XSSFRow row = sheet.createRow(0);
		row.createCell(0).setCellValue("Timestamp");
		row.createCell(1).setCellValue("Technical Log Columnname");
		row.createCell(2).setCellValue("Log Event");
		row.createCell(3).setCellValue("Ausfallzeit");
		row.createCell(4).setCellValue("Wiederstartzeit");
		row.createCell(5).setCellValue("Score");
		row.createCell(6).setCellValue("Okay?");
		row.createCell(7).setCellValue("Grund");

		for (int i = 0; i < 7; i++) {
			sheet.autoSizeColumn(i);
		}

		for (int i = index + 1; i < 5; i++) {
			XSSFRow rowAuto = sheet.createRow(i);
			for (int j = 0; j < 8; j++) {
				XSSFCell bill = rowAuto.createCell(j);
				if (j == 6) {
					if (rowAuto.getCell(i).getStringCellValue() != null)
						bill.setCellValue("X");
					continue;
				}
				if (j == 7) {
					continue;
				}

				bill.setCellValue("Hallo");
			}

			index++;
		}
		index++;

		System.out.println(index);
		workbook.write(new FileOutputStream("Excel.xlsx"));
		workbook.close();

	}
}
