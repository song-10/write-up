#!usr/bin/python
# coding=utf-8


import mysql.connector
import hashlib

try:
    mydb = mysql.connector.connect(
      host="192.168.218.139",
      user="root",
      passwd="root10",
      buffered=True,
      database="test_admin"
    )
    mycursor = mydb.cursor()
    mycursor.execute("use test_admin")
except Exception as err:
    print(err)
    mydb = mysql.connector.connect(
      host="192.168.218.139",
      user="root",
      buffered=True,
      passwd="root10"
    )
    mycursor = mydb.cursor()
    mycursor.execute("CREATE DATABASE test_admin")
    mycursor.execute("use test_admin")
    # 创建测数据表
    mycursor.execute("CREATE TABLE admin(user VARCHAR(255), \
    passwd VARCHAR(255))")
    # 主键设置
    mycursor.execute(
      "ALTER TABLE admin ADD COLUMN id INT AUTO_INCREMENT PRIMARY KEY")
# 插入记录
sql = "INSERT INTO admin (user, passwd) VALUES (%s, %s)"
val = [
  ('Tom', hashlib.md5('123'.encode("utf-8")).hexdigest()),
  ('Tony', hashlib.md5('123'.encode("utf-8")).hexdigest()),
  ('Jenifer', hashlib.md5('123'.encode("utf-8")).hexdigest()),
  ('Jon', hashlib.md5('123'.encode("utf-8")).hexdigest())
]
# 实际情况下用户密码是以md5的形式存储在数据库中的
# 执行SQL语句
mycursor.executemany(sql, val)
# 提交修改
mydb.commit()
