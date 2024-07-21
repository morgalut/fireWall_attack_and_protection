import schedule
import time
import requests  # Make sure this library is installed

def periodic_test():
    try:
        response = requests.get('http://localhost:5000/test')
        print(response.json())
    except Exception as e:
        print(f"Error occurred: {e}")

schedule.every(5).minutes.do(periodic_test)

while True:
    schedule.run_pending()
    time.sleep(1)
