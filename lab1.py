import os
import re
import hashlib
import sqlite3
from Tkinter import *
import ttk
import tkMessageBox as mb
"""
ToDo list:
Scroll-bar
Check-button
EditingFunction
"""
db_filename = 'appdata'
db_is_new = not os.path.exists(db_filename)
conn = sqlite3.connect(db_filename)
conn.text_factory = str
c = conn.cursor()
if db_is_new:
    c.execute('''CREATE TABLE Users
        (Username TEXT UNIQUE, Password TEXT, PassCheck INTEGER DEFAULT 1, Blocked TEXT DEFAULT 0)''')
    c.execute('INSERT INTO USERS(Username) VALUES(?)', ('ADMIN',))
root = Tk()
c.execute('SELECT * FROM Users')
mas=c.fetchall()
print mas
def CloseProgram():
    conn.commit()
    conn.close()
    os._exit(0)
                                                
def MainScreen():
    def About():
        mb.showinfo("About", u"Password must contains numbers and signs of arithmetic operations!\n \u00a9 P.Vovchanovskyi")
    def AskPwd(username):
        askpwd=Toplevel()
        askpwd.grab_set()
        askpwd.geometry("200x80")
        askpwd.title('Autentification required')
        text_askpwd = Label(askpwd, text="Password:").pack()
        entry_askpwd = Entry(askpwd, show='*')
        entry_askpwd.pack()
        def ComparePwd():
            c.execute('SELECT Password FROM Users WHERE Username = ?', (username,))
            reply=c.fetchone()
            if reply[0][:32]==hashlib.pbkdf2_hmac('sha256', entry_askpwd.get(), reply[0][32:], 100000): 
                global acl
                acl=1
            else:
                acl=0
            askpwd.destroy()
            askpwd.quit()
        button_askpwd = Button(askpwd, text="Submit", command=ComparePwd).pack()
        askpwd.mainloop()
        return acl
    def ChangePwdForm(username):
        pwdch=Toplevel()
        pwdch.grab_set()
        pwdch.geometry("250x200")
        pwdch.title("Change password")
        text_username = Label(pwdch, text="Username:").pack()
        my_username = Entry(pwdch, justify='center')
        my_username.insert(0, username)
        my_username.config(state='readonly')
        my_username.pack()
        text_newpassword = Label(pwdch, text="Enter new password:").pack()
        new_password = Entry(pwdch, show='*')
        new_password.pack()
        text_newpassword = Label(pwdch, text="Repeat new password:",).pack()
        newrep_password = Entry(pwdch, show='*')
        newrep_password.pack()
        def CheckPwd():
            new_password.config(state='readonly')
            newrep_password.config(state='readonly')
            answer=0
            if new_password.get()==newrep_password.get():
                c.execute('SELECT PassCheck FROM Users WHERE Username = ?', (username,))
                reply=c.fetchone()
                def WritePwd():
                    salt = os.urandom(16)
                    hash = hashlib.pbkdf2_hmac('sha256', new_password.get(), salt, 100000)
                    c.execute('UPDATE Users SET Password=? WHERE Username = ?', (hash+salt,username))
                    conn.commit()
                    mb.showinfo("Completed","Password successfully changed")
                if int(reply[0])==1:
                    if bool(re.match(r'(?=.*[0-9])(?=.*[*\-\+\/\*\=]).', new_password.get())):
                        WritePwd()  
                    else:
                        answer=mb.askretrycancel("Error", "Password must contains numbers and signs of arithmetic operations!\nDo you want to try that again?")
                else:
                   WritePwd() 
            else:
                answer = mb.askretrycancel("Error", "New passwords don`t match!\nDo you want to try that again?")
            if answer:
                pwdch.focus_set()
                new_password.config(state='normal')
                newrep_password.config(state='normal')
                new_password.delete(0, END)
                newrep_password.delete(0, END)
                new_password.focus_set()
            else:
                pwdch.destroy()
                pwdch.quit()
        button_submit = Button(pwdch, text="Submit", command=CheckPwd).pack()
        pwdch.mainloop()
    def SendData():
        if SendData.counter == 3:
                root.destroy()
        else:
            if not reg_login.get():
                mb.showerror('Error','Username is empty!')
            else:
                c.execute('SELECT Blocked, Password FROM Users WHERE Username = ?', (reg_login.get(),))
                reply=c.fetchone()
                if reply:
                    if not int(reply[0]):
                        if not reply[1] and not reg_password.get():
                            status.config(text='Status: Changing Password')
                            ChangePwdForm(reg_login.get())
                            status.config(text='Status: Blocked')
                        elif reg_password.get() and reply[1]:
                            if reply[1][:32]==hashlib.pbkdf2_hmac('sha256', reg_password.get(), reply[1][32:], 100000):
                                global userinterface
                                userinterface=Toplevel()
                                userinterface.focus_force() 
                                userinterface.geometry("320x20")
                                userinterface.title("Very Protected Privacy")
                                root.withdraw()
                                def Logout():
                                    userinterface.destroy()
                                    userinterface.quit()
                                    root.deiconify()
                                def ChangePass():
                                    if AskPwd(reg_login.get())==1:
                                        ChangePwdForm(reg_login.get())
                                    else:
                                        Logout()
                                mainmenu2 = Menu(userinterface)
                                userinterface.config(menu=mainmenu2)
                                helpmenu2 = Menu(mainmenu2, tearoff=0)
                                helpmenu2.add_command(label="About...", command=About)
                                mainmenu2.add_cascade(label="Help", menu=helpmenu2)
                                if reg_login.get()=='ADMIN':
                                    usermenu = Menu(mainmenu2, tearoff=0)
                                    usermenu = Menu(mainmenu2, tearoff=0)
                                    def AddUser():
                                        addusr=Toplevel()
                                        addusr.grab_set()
                                        addusr.geometry("200x80")
                                        addusr.title('Add user')
                                        text_newusr = Label(addusr, text="Username:").pack()
                                        entry_newusr = Entry(addusr)
                                        entry_newusr.pack()
                                        def Record():
                                            try:
                                                c.execute('INSERT INTO USERS(Username) VALUES(?)', (entry_newusr.get(),))
                                                conn.commit()
                                                mb.showinfo("Add user","User "+entry_newusr.get()+" was added successfully!")
                                            except:
                                                mb.showerror('Error',"User "+entry_newusr.get()+" has already exists!")
                                            addusr.destroy()
                                        button_newusr = Button(addusr, text="Submit", command=Record).pack()
                                        addusr.mainloop()
                                    def ViewUser():
                                        userinterface.geometry("500x300")
                                        scrollbar = Scrollbar(userinterface)
                                        scrollbar.pack(side = RIGHT, fill = Y)
                                        c.execute('SELECT rowid, Username, PassCheck, Blocked FROM USERS LIMIT 10')
                                        data=c.fetchall()
                                        row_0 = Frame(userinterface)
                                        row_0_0 = Label(row_0, width=7, height=4, bd=2, text='ID')
                                        row_0_1 = Label(row_0, width=7, height=4, bd=2, text='Username')
                                        row_0_2 = Label(row_0, width=7, height=4, bd=2, text='Password')
                                        row_0_3 = Label(row_0, width=7, height=4, bd=2, text='PassCheck')
                                        row_0_4 = Label(row_0, width=7, height=4, bd=2, text='Blocked')
                                        row_0.pack(side=TOP)
                                        row_0_0.pack(side=LEFT)
                                        row_0_1.pack(side=LEFT)
                                        row_0_2.pack(side=LEFT)
                                        row_0_3.pack(side=LEFT)
                                        row_0_4.pack(side=LEFT)
                                        for i in range(len(data)):
                                            row_1 = Frame(userinterface)
                                            row_1_0 = Label(row_1, width=7, height=4, text=data[i][0])
                                            row_1_1 = Label(row_1, width=7, height=4, text=data[i][1])
                                            row_1_2 = Button(row_1,  width=7, height=4, text="Reset")
                                            PasschkValue = BooleanVar()
                                            PasschkValue.set(1)
                                            PasschkButton = Checkbutton(row_1, variable=PasschkValue)
                                            BlockedValue = IntVar()
                                            BlockedValue.set(int(data[i][3]))
                                            BlockedButton = Checkbutton(row_1, variable=BlockedValue)
                                            row_1.pack(side=TOP)
                                            row_1_0.pack(side=LEFT)
                                            row_1_1.pack(side=LEFT)
                                            row_1_2.pack(side=LEFT)
                                            PasschkButton.pack(side=LEFT)
                                            BlockedButton.pack(side=LEFT)
                                    usermenu.add_command(label='Add', command=AddUser)
                                    usermenu.add_command(label='View', command=ViewUser)
                                    mainmenu2.add_cascade(label="Users", menu=usermenu)
                                mainmenu2.add_command(label='Change password', command=ChangePass)
                                mainmenu2.add_command(label='Log out', command=Logout)
                                mainmenu2.add_command(label='Exit', command=root.destroy)
                                status2 = Label(userinterface, text='Status: Log in as '+reg_login.get(), bd=1, relief=SUNKEN, anchor=W)
                                status2.pack(side=BOTTOM, fill=X)
                                userinterface.mainloop()
                            else:
                                SendData.counter += 1
                                mb.showerror('Error','Incorrect username or password!')
                        else:
                            SendData.counter += 1
                            mb.showerror('Error','Incorrect username or password!')
                    else:
                        mb.showerror('Error','Account is blocked!')
                else:
                    SendData.counter += 1
                    mb.showerror('Error','Incorrect username or password!')
            try:
                reg_login.delete(0, END)
                reg_password.delete(0, END)
                reg_login.focus_set()
            except:
                pass
    SendData.counter = 1
    root.geometry("250x150")
    root.title("Account Login")
    mainmenu = Menu(root) 
    root.config(menu=mainmenu)
    helpmenu = Menu(mainmenu, tearoff=0)
    helpmenu.add_command(label="About...", command=About)
    mainmenu.add_cascade(label="Help", menu=helpmenu)
    mainmenu.add_command(label='Exit', command=root.destroy)
    text_log = Label(text="Username:").pack()
    reg_login = Entry()
    reg_login.pack()
    text_password = Label(text="Password:").pack()
    reg_password = Entry(show='*')
    reg_password.pack()
    button_login = Button(text="Login", command=SendData).pack()
    status = Label(text='Status: Blocked', bd=1, relief=SUNKEN, anchor=W)
    status.pack(side=BOTTOM, fill=X)
    root.mainloop()
MainScreen()
conn.commit()
conn.close()
    



