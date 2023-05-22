
from tkinter import *
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_data():
    title = my_title_entry.get()
    secret = my_secret_text.get(1.0, END)
    key = my_key_entry.get()

    if not title or not secret or not key:
        messagebox.showwarning("Error", "Please fill in all fields.")
    else:      
        secret_encrypted = encode(key, secret)

        filename ="Secrets"
        with open(filename, "a") as file:
            file.write(title + "\n")
            file.write(secret_encrypted + "\n")
        messagebox.showinfo("Success", "Data saved.")
        
        my_title_entry.delete(0,END)
        my_secret_text.delete(1.0, END)
        my_key_entry.delete(0, END)

def decrypt_button():
    secret_encrypted = my_secret_text.get(1.0, END)
    key_decrypted = my_key_entry.get()

    if not secret_encrypted or not key_decrypted:
        messagebox.showwarning("Error")
    else:
        secret_decrypted = decode(key_decrypted,secret_encrypted)
        my_secret_text.delete(1.0, END)
        my_secret_text.insert(1.0, secret_decrypted)

window = Tk()
window.title("Secret Notes")
window.minsize(width=350, height=350)

image_path= r"c:\Users\knox0\OneDrive\Masaüstü\Secret\resim.png"
image =PhotoImage(file=image_path)
image_label = Label(image=image,width=200,height=200)
image_label.pack()

my_label = Label(text="Enter your title")
my_label.pack()

my_title_entry = Entry()
my_title_entry.pack()

my_label2 = Label(text="Entr your secret")
my_label2.pack()

my_secret_text = Text(width=25,height=20)
my_secret_text.pack()

my_key_label = Label(text="Entr master key")
my_key_label.pack()

my_key_entry =Entry()
my_key_entry.pack()

save_button = Button(text="Save and Enrypt", width=15, height=1, command=save_data)
save_button.pack()

decrypt = Button(text="Decrypt", width=10, height=1,command=decrypt_button)
decrypt.pack()

window.mainloop()

