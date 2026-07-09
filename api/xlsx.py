from io import BytesIO

from django.http import HttpResponse
from openpyxl import Workbook

XLSX_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def xlsx_response(filename, sheet_name, headers, rows):
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = str(sheet_name)[:31] or "Sheet1"
    sheet.append(list(headers))
    for row in rows:
        sheet.append(["" if value is None else value for value in row])

    output = BytesIO()
    workbook.save(output)
    output.seek(0)
    response = HttpResponse(output.getvalue(), content_type=XLSX_CONTENT_TYPE)
    response["Content-Disposition"] = f"attachment; filename={filename}"
    return response
