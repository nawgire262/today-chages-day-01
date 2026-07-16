import schedule
import time

from report_generator import ReportGenerator

reporter = ReportGenerator()

def create_daily_report():

    reporter.generate_pdf_report()
    reporter.generate_excel_report()

    print("Daily Report Generated")


schedule.every().day.at("18:00").do(
    create_daily_report
)

while True:

    schedule.run_pending()

    time.sleep(60)