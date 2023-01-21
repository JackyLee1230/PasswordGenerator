import customtkinter as ctk
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
SYMBOLS = ["@", "#", "$", "%", "&", "_"]


class RandomGen:
    def __init__(self):
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        # self.window = tk.Tk()
        self.window = ctk.CTk()
        self.window.title('"Random" Password Generator')
        self.window.geometry("520x500")

        # Length of Password Input Label
        label_frame_text = tk.StringVar(
            value="Enter the length of the desired password"
        )
        self.label_frame2 = ctk.CTkLabel(
            self.window,
            textvariable=label_frame_text,
            width=120,
            height=25,
            fg_color=("lightblue", "black"),
            text_color=("white", "white"),
            corner_radius=8,
        )
        # self.label_frame2.place(relx=100, rely=0.5, anchor=tk.CENTER)
        self.label_frame2.grid(row=0, column=0, padx=10, pady=10)

        # Length of Password Input
        self.length_input = ctk.CTkEntry(
            self.label_frame2,
            width=450,
            height=40,
            border_width=1,
            placeholder_text="Length of the Generated Password (Integer)",
            text_color="silver",
        )
        self.length_input.grid(row=1, column=0, padx=10, pady=10)

        # Password Result Label
        self.password_result = ctk.CTkEntry(
            self.window,
            width=450,
            placeholder_text="Generated Password",
        )
        self.password_result.configure(state="disabled")
        self.password_result["justify"] = "center"
        self.password_result.grid(row=1, column=0, padx=10, pady=0)

        # Check Password Strength Label Frame
        label_frame_text = tk.StringVar(value="Enter your password for strength check!")
        self.label_frame2 = ctk.CTkLabel(
            self.window,
            textvariable=label_frame_text,
            width=120,
            height=25,
            fg_color=("lightblue", "black"),
            text_color=("white", "white"),
            corner_radius=8,
        )
        self.label_frame2.grid(row=2, column=0, padx=10, pady=10)

        self.user_frame = ctk.CTkFrame(self.window, width=450, height=40)
        self.user_frame.grid(row=3, column=0, padx=10, pady=10)
        self.user_password = ctk.CTkEntry(
            self.user_frame, width=450, placeholder_text="Enter Password"
        )
        self.user_password.grid(row=0, column=1, padx=10, pady=10)

        # Button Frame
        self.button_frame = ctk.CTkFrame(self.window, width=450, height=40)
        self.button_frame.grid(row=5, column=0, padx=10, pady=10)

        # generate password button
        self.generate_button = ctk.CTkButton(
            self.button_frame,
            text="Generate Password",
            command=self.generate_random_password,
        )
        self.generate_button.grid(row=2, column=0, padx=10)

        # copy password button
        self.copy_button = ctk.CTkButton(
            self.button_frame, text="Copy Password", command=self.copy_password
        )
        self.copy_button.grid(row=2, column=1, padx=10)

        # save password button
        self.save_button = ctk.CTkButton(
            self.button_frame, text="Save Password", command=self.save_password
        )
        self.save_button.grid(row=2, column=2, padx=10)

        if self.password_result.get() == "":
            self.save_button["state"] = "disabled"
        else:
            self.save_button["state"] = "normal"

        self.add_time_value = tk.BooleanVar()
        self.add_time_value.set(False)
        self.add_time_button = ctk.CTkSwitch(
            self.button_frame,
            text="Add Time In File",
            variable=self.add_time_value,
            onvalue="on",
            offvalue="off",
            width=100,
            height=30,
            corner_radius=8,
        )
        self.add_time_button.grid(row=0, column=1, padx=10, pady=10)

        self.hide_password_value = tk.BooleanVar()
        self.hide_password_value.set(False)

        self.hide_password_button = ctk.CTkSwitch(
            self.button_frame,
            text="Hide Password Entry",
            variable=self.hide_password_value,
            onvalue=True,
            offvalue=False,
            width=100,
            height=30,
            corner_radius=8,
            command=self.hide_password_toggle,
        )
        self.hide_password_button.grid(row=0, column=0, padx=10, pady=10)

        self.clear_password_file_button = ctk.CTkButton(
            self.button_frame,
            text="Clear Password File",
            command=self.clear_password_file,
        )
        self.clear_password_file_button.grid(row=1, column=1, padx=10, pady=10)

        self.user_password_button = ctk.CTkButton(
            self.button_frame,
            text="Check Your Password",
            command=lambda: self.user_password_strength_checker(w=self.window),
        )
        self.user_password_button.grid(row=3, column=1, padx=10, pady=10)

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
        symbol_ok = (
            re.search(r"[%&!#$'()*+,-./[\\\]^_`{|}~" + r'"]', password) is not None
        )
        if length_ok and digit_ok and uppercase_ok and lowercase_ok and symbol_ok:
            return True
        else:
            return False

    def user_password_strength_checker(self, w):
        new_window = ctk.CTkToplevel(w)
        new_window.title("Password Checker")
        new_window.geometry("300x100")
        if self.user_password.get() == "":
            self.new_label = ctk.CTkLabel(
                new_window, text="Please Input A Password!", anchor=tk.CENTER
            )
            self.close_btn = ctk.CTkButton(
                new_window, text="Close", command=new_window.destroy
            ).pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)
            self.new_label.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
            return
        if self.password_strength_checker(self.user_password.get()) == True:
            self.new_label = ctk.CTkLabel(
                new_window, text="Good Password!", anchor=tk.CENTER
            )
            self.close_btn = ctk.CTkButton(
                new_window, text="Close", command=new_window.destroy
            ).pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)
            self.new_label.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        else:
            self.new_label = ctk.CTkLabel(
                new_window,
                text="This is not a very Safe and Secure Password!",
                anchor=tk.CENTER,
            )
            self.close_btn = ctk.CTkButton(
                new_window, text="Close", command=new_window.destroy
            ).pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)
            self.new_label.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    def generate_random_password(self):
        try:
            password_length = int(self.length_input.get())
            if self.password_result.get() != "":
                self.feedback.destroy()
            data = SYMBOLS + ENGLISH_LOWER + ENGLISH_UPPER + NUMERICAL
            if password_length < 8:
                self.feedback = tk.Label(
                    self.window,
                    fg="red",
                    text="Password must be at least 8 characters long",
                )
                self.feedback.place(x=110, y=100)
                return
            password = "".join(choice(data) for _ in range(password_length))
            if self.password_strength_checker(password) == True:
                self.password_result.configure(state="normal")
                self.password_result.delete(0, END)
                self.password_result.insert(0, password)
                self.password_result.configure(state="disabled")
            else:
                self.generate_random_password()
            self.save_button["state"] = "normal"
        except ValueError:
            self.feedback = tk.Label(
                self.window, fg="red", text="Please enter number of characters"
            )
            self.feedback.place(x=158, y=100)

    def copy_password(self):
        self.window.clipboard_clear()
        self.window.clipboard_append(self.password_result.get())

    def save_password(self):
        with open(os.getcwd() + "\passwords.txt", "a+") as f:
            if self.add_time_value.get() == False:
                f.write(self.password_result.get() + "\n")
            else:
                f.write(
                    datetime.now().strftime("%d/%m/%Y %H:%M:%S ")
                    + self.password_result.get()
                    + "\n"
                )
        self.save_button["state"] = "disabled"

    def clear_password_file(self):
        with open(os.getcwd() + "\passwords.txt", "w+") as f:
            f.write("")


if __name__ == "__main__":
    RandomGen().window.mainloop()
