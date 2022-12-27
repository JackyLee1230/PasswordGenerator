import tkinter as tk
from tkinter.constants import END
import string
import os
import re
from secrets import choice
from datetime import datetime


ENGLISH_UPPER = list(string.ascii_uppercase)
ENGLISH_LOWER = list(string.ascii_lowercase)
NUMERICAL = list(string.digits)
SYMBOLS = ['@', '#', '$', '%', '&', '_']


class RandomGen:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("\"Random\" Password Generator")
        self.window.geometry("500x500")
        self.label_frame = tk.LabelFrame(
            self.window, text="Enter the length of the desired password")
        self.label_frame.pack(pady=20)

        self.length_input = tk.Entry(
            self.label_frame, width=20, bg="#91d2e6", fg="red")
        self.length_input.pack(padx=40, pady=30)

        self.feedback = tk.Label(self.window)

        self.password_result = tk.Entry(
            self.window, text="", width=50)
        self.password_result.pack(pady=20)
        self.password_result.configure(state="disabled")
        self.password_result["justify"] = "center"

        self.user_frame = tk.LabelFrame(
            self.window, text="Enter your password for strength check!")
        self.user_frame.pack(pady=20)

        self.user_password = tk.Entry(
            self.user_frame, show="*", width=20, bg="#ffffff")
        self.user_password.pack(padx=40, pady=30)

        self.button_frame = tk.Frame(self.window)
        self.button_frame.pack(pady=20)

        self.generate_button = tk.Button(
            self.button_frame, text="Generate Password", command=self.generate_random_password)
        self.generate_button.grid(row=1, column=0, padx=10)

        self.copy_button = tk.Button(self.button_frame,
                                     text="Copy Password", command=self.copy_password)
        self.copy_button.grid(row=1, column=1, padx=10)

        self.save_button = tk.Button(self.button_frame,
                                     text="Save Password", command=self.save_password)
        self.save_button.grid(row=1, column=2, padx=20)

        if self.password_result.get() == "":
            self.save_button["state"] = "disabled"
        else:
            self.save_button["state"] = "normal"

        self.add_time_value = tk.BooleanVar()
        self.add_time_value.set(False)

        self.add_time_button = tk.Checkbutton(
            self.button_frame, text="Add Time In File", var=self.add_time_value)
        self.add_time_button.grid(row=0, column=1, padx=20)

        self.hide_password_value = tk.BooleanVar()
        self.hide_password_value.set(True)

        self.hide_password_button = tk.Checkbutton(
            self.button_frame, text="Hide Password Entry", var=self.hide_password_value, command=self.hide_password_toggle)
        self.hide_password_button.grid(row=0, column=0, padx=20)

        self.clear_passwordFile_button = tk.Button(
            self.button_frame, text="Clear Password File", command=self.clear_password_file)
        self.clear_passwordFile_button.grid(row=2, column=1, padx=20)

        self.user_password_button = tk.Button(self.button_frame,
                                              text="Check Your Password", command=self.user_password_strength_checker)
        self.user_password_button.grid(row=3, column=1, padx=20)

        self.window.mainloop()

    def hide_password_toggle(self):
        if self.hide_password_value.get() == False:
            self.user_password.configure(show="")
        else:
            self.user_password.configure(show="*")

    def password_strength_checker(self, password):
        if password == None or password == "":
            return
        length_ok = len(password) >= 8
        digit_ok = re.search(r"\d", password) is not None
        uppercase_ok = re.search(r"[A-Z]", password) is not None
        lowercase_ok = re.search(r"[a-z]", password) is not None
        symbol_ok = re.search(
            r"[%&!#$'()*+,-./[\\\]^_`{|}~"+r'"]', password) is not None
        if (length_ok and digit_ok and uppercase_ok and lowercase_ok and symbol_ok):
            return True
        else:
            return False

    def user_password_strength_checker(self):
        if self.user_password.get() == "":
            self.feedback = tk.Label(
                self.window, fg="blue", text="Enter a password!")
            self.feedback.place(x=200, y=300)
            return
        if self.password_strength_checker(self.user_password.get()) == True:
            self.feedback = tk.Label(
                self.window, fg="blue", text="Password strong enough!")
            self.feedback.place(x=180, y=300)
        else:
            self.feedback = tk.Label(
                self.window, fg="red", text="Password not strong enough")
            self.feedback.place(x=170, y=300)
            print("not safe")

    def generate_random_password(self):
        try:
            password_length = int(self.length_input.get())
            if self.password_result.get() != "":
                self.feedback.destroy()
            data = SYMBOLS + ENGLISH_LOWER + ENGLISH_UPPER + NUMERICAL
            if password_length < 8:
                self.feedback = tk.Label(
                    self.window, fg="red", text="Password must be at least 8 characters long")
                self.feedback.place(x=110, y=100)
                return
            password = ''.join(choice(data) for _ in range(password_length))
            if self.password_strength_checker(password) == True:
                self.password_result.configure(state="normal")
                self.password_result.delete(0, END)
                self.password_result.insert(0, password)
                self.password_result.configure(state="disabled")
            else:
                self.generate_random_password()
            self.save_button["state"] = "normal"
        except ValueError:
            self.feedback = tk.Label(self.window, fg="red",
                                     text="Please enter number of characters")
            self.feedback.place(x=158, y=100)

    def copy_password(self):
        self.window.clipboard_clear()
        self.window.clipboard_append(self.password_result.get())

    def save_password(self):
        with open(os.getcwd() + "\passwords.txt", "a+") as f:
            if self.add_time_value.get() == False:
                f.write(self.password_result.get() + "\n")
                print("False")
            else:
                f.write(datetime.now().strftime("%d/%m/%Y %H:%M:%S ") +
                        self.password_result.get() + "\n")
                print("true")
        self.save_button["state"] = "disabled"

    def clear_password_file(self):
        with open(os.getcwd() + "\passwords.txt", "w+") as f:
            f.write("")


if __name__ == '__main__':
    RandomGen().window.mainloop()
