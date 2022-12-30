from tkinter import*
from tkinter import ttk
import tkinter as tk
from tkinter.filedialog import *
import tkinter.messagebox

import pandas as pd
import hashlib
import os
import os.path
from Crypto import Random
from Crypto.Cipher import AES



def enc_file(input_data,key,iv,filepath):
	cfb_cipher = AES.new(key, AES.MODE_CFB, iv)
	enc_data = cfb_cipher.encrypt(input_data)

	enc_file = open(filepath+".enc", "wb")
	enc_file.write(enc_data)
	enc_file.close()

	
def dec_file(input_data,key,iv,filepath):
	cfb_decipher = AES.new(key, AES.MODE_CFB, iv)
	plain_data = cfb_decipher.decrypt(input_data)

	output_file = open(filepath[:-4], "wb")
    
	output_file.write(plain_data)
	output_file.close()
def pass_alert():
   tkinter.messagebox.showinfo("Password Alert","Please enter a password.")

def encrypt():

    global file_path_e
    enc_pass = passg.get()
    if enc_pass == "":
        pass_alert()
    else:
    
        filename = tkinter.filedialog.askopenfilename()
        file_path_e = os.path.dirname(filename)
        hash=hashlib.sha256(enc_pass.encode()) 
        p = hash.digest()
        key = p
        iv = p.ljust(16)[:16]
        print("Encoding key is: ",key)
        getkey.set(key)
        input_file = open(filename,'rb')
        input_data = input_file.read()
        input_file.close()
        enc_file(input_data,key,iv,filename)
        os.remove(filename)
        tkinter.messagebox.showinfo("Encryption Alert","Encryption ended successfully. File stored ")

def decrypt():

    global file_path_e
    enc_pass = passg.get()
    if enc_pass == "":
        pass_alert()
    else:
        filename = tkinter.filedialog.askopenfilename()
        file_path_e = os.path.dirname(filename)
        #GENERATE KEY & INITIALIZATION VECTOR
        hash=hashlib.sha256(enc_pass.encode()) 
        p = hash.digest()
        key = p
        iv = p.ljust(16)[:16]
        input_file = open(filename,'rb')
        input_data = input_file.read()
        input_file.close()
        dec_file(input_data,key,iv,filename)
        os.remove(filename)
        tkinter.messagebox.showinfo("Decryption Alert","Decryption ended successfully File Stored ")

def get_encrypt_string():
    enc_pass = passg.get()
    raw =textgEn.get("1.0",tk.END)
    print (raw)
    msg = raw.encode("utf-8")
    hash=hashlib.sha256(enc_pass.encode()) 
    p = hash.digest()
    key = p
    iv = p.ljust(16)[:16]
    getkey.set(key)
    aes = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = aes.encrypt(msg)
    # print (ciphertext)
    # ciphertext = StringVar()
    textgDe.delete("1.0", tk.END)
    textgDe.insert("1.0",ciphertext) 
   


def get_decrypt_string():
    # enc_pass = passg.get()
    # cipher =textgDe.get("1.0",tk.END)
    # msg= cipher.encode()
    # hash=hashlib.sha256(enc_pass.encode()) 
    # p = hash.digest()
    # key = p
    # iv = p.ljust(16)[:16]
    # aes = AES.new(key, AES.MODE_CFB, iv)
    # raw = aes.decrypt(msg)
    # msv= raw.decode('unicode_escape')
    # print (msv)
    # # ciphertext = StringVar()
    # textgEn.delete("1.0", tk.END)
    textgEn.insert("1.0",get_encrypt_string) 




# GUI STUFF
top=tk.Tk()
top.geometry("600x550")
top.resizable(0,0)
top.title("File Encryption ")

title="Encryption Using AES"
msgtitle=Message(top,text=title)
msgtitle.config(font=('helvetica',17,'bold'),width=300)
msgtitle.pack()

sp="---------------------------------------------------------------------"
sp_title=Message(top,text=sp)
sp_title.config(font=('arial',12),width=650)
sp_title.pack()


passlabel = Label(top, text="nhập mã khóa AES :")
passlabel.pack()

passg = Entry(top, width=60)
passg.config(highlightthickness=1,highlightbackground="blue")
passg.pack()

textlableEn = Label(top, text="bản rõ")
textlableEn.pack()


textgEn = Text(top, width= 50,height=1)
textgEn.config(highlightthickness=1,)
textgEn.pack()

textlableDe = Label(top, text="bản mã hóa")
textlableDe.pack()


textgDe = Text(top, width= 50 ,height=1 )
textgDe.config(highlightthickness=1,)
textgDe.pack()


txt = Label(top, text="KHÓA ĐƯỢC SINH RA :")
txt.pack()
getkey = StringVar()
textlableKey = Label(top, text="Key",textvariable=getkey)
textlableKey.pack()



get_encrypt_string=Button(top,text="mã hóa chuỗi",width=28,height=3,command=get_encrypt_string)
get_encrypt_string.pack(side=BOTTOM)
get_decrypt_string=Button(top,text="giải mã hóa",width=28,height=3,command=get_decrypt_string)
get_decrypt_string.pack(side=BOTTOM)

encrypt=Button(top,text="Mã hóa file",width=28,height=3,command=encrypt)
encrypt.pack(side=LEFT)
decrypt=Button(top,text="Giải Mã file",width=28,height=3,command=decrypt)
decrypt.pack(side=RIGHT)

top.mainloop()