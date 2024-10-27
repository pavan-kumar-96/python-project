import random
import tkinter as tk
import pyperclip

def generate_password():
    password_length = int(length_entry.get())
    
    # Define character sets based on user choices
    uppercase_letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    lowercase_letters = 'abcdefghijklmnopqrstuvwxyz'
    digits = '0123456789'
    special_chars = '!@#$%^&*()_+-=[]{}|;:,.<>/?`~'

    character_set = ''
    if uppercase_var.get():
        character_set += uppercase_letters
    if lowercase_var.get():
        character_set += lowercase_letters
    if digits_var.get():
        character_set += digits
    if special_chars_var.get():
        character_set += special_chars

    # Ensure at least one character from each selected set
    password = ''
    for char_set in [uppercase_letters, lowercase_letters, digits, special_chars]:
        if char_set in character_set:
            password += random.choice(char_set)

    # Fill the remaining password length with random characters
    for _ in range(password_length - len(password)):
        password += random.choice(character_set)

    # Shuffle the password for added randomness
    password_list = list(password)
    random.shuffle(password_list)
    password = ''.join(password_list)

    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

def copy_password():
    password = password_entry.get()
    pyperclip.copy(password)

# Create the GUI
root = tk.Tk()
root.title("Advanced Password Generator")

# Password length label and entry
length_label = tk.Label(root, text="Password Length:")
length_label.pack()
length_entry = tk.Entry(root)
length_entry.pack()

# Checkbox for character sets
uppercase_var = tk.BooleanVar()
lowercase_var = tk.BooleanVar()
digits_var = tk.BooleanVar()
special_chars_var = tk.BooleanVar()

uppercase_check = tk.Checkbutton(root, text="Uppercase", variable=uppercase_var)
lowercase_check = tk.Checkbutton(root, text="Lowercase", variable=lowercase_var)
digits_check = tk.Checkbutton(root, text="Digits", variable=digits_var)
special_chars_check = tk.Checkbutton(root, text="Special Characters", variable=special_chars_var)

uppercase_check.pack()
lowercase_check.pack()
digits_check.pack()
special_chars_check.pack()

# Generate and Copy buttons
generate_button = tk.Button(root, text="Generate Password", command=generate_password)
copy_button = tk.Button(root, text="Copy Password", command=copy_password)

generate_button.pack()
copy_button.pack()

# Password display
password_label = tk.Label(root, text="Generated Password:")
password_label.pack()
password_entry = tk.Entry(root, width=40)
password_entry.pack()

root.mainloop()