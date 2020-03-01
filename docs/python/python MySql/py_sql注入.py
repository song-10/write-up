import tkinter as tk
import tkinter.messagebox as mb
import mysql.connector


class admin:
    def MB1(self):
        mb.askokcancel('提示', '登录成功')

    def MB2(self):
        mb.askokcancel('提示', '用户名或密码错误！')

    def check(self, user_name, password):
        mydb = mysql.connector.connect(
            host="192.168.218.139",
            user="root",
            passwd="root10",
            buffered=True,
            database="test_admin"
            )
        mycursor = mydb.cursor()
        mycursor.execute("use test_admin")
        mycursor.execute("SELECT * FROM admin WHERE\
            user =%s and passwd = %s" % (user_name, password))
        result = mycursor.fetchall()
        if(result):
            self.MB1()
        else:
            self.MB2()

    def __init__(self):
        win = tk.Tk()
        win.title('登录')
        win.geometry('400x200')
        # 输入
        s = tk.Label(win, text='用户名:', font=('Arial', 8))
        s.place(relx=0.1, rely=0.4, anchor='w')
        s = tk.Label(win, text='密码:', font=('Arial', 8))
        s.place(relx=0.1, rely=0.5, anchor='w')
        # 输入框
        e1 = tk.Entry(win, width=35)
        e1.place(relx=0.22, rely=0.4, anchor='w')
        e2 = tk.Entry(win, width=35, show='*')
        e2.place(relx=0.22, rely=0.5, anchor='w')

        # 传参函数
        def data():
            username = str(e1.get())
            password = str(e2.get())
            self.check(username, password)
        # 按钮
        b1 = tk.Button(win, text='submit', width=5, command=data)
        b2 = tk.Button(win, text='exit', width=5, command=win.quit)
        b1.place(relx=0.52, rely=0.65, anchor='w')
        b2.place(relx=0.69, rely=0.65, anchor='w')
        # 显示窗口
        win.mainloop()


if __name__ == "__main__":
    admin()
