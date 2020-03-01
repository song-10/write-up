import mysql.connector

try:
    mydb = mysql.connector.connect(
      host="192.168.218.139",
      user="root",
      passwd="root10",
      buffered=True,
      database="test_db"
    )
    print("数据库已存在")
    mycursor = mydb.cursor()
except Exception as err:
    print(err)
    mydb = mysql.connector.connect(
      host="192.168.218.139",
      user="root",
      buffered=True,
      passwd="root10"
    )
    mycursor = mydb.cursor()
    mycursor.execute("CREATE DATABASE test_db")
    print("数据库已创建")
    mycursor.execute("use test_db")
    print("已选择数据库test_db")
print("数据库有：")
mycursor.execute("SHOW DATABASES")
for x in mycursor:
    print(x, end=' ')

mycursor.execute("CREATE TABLE t_table(name VARCHAR(255), url VARCHAR(255))")

# 查看已有数据表

mycursor.execute("SHOW TABLES")
for x in mycursor:
    print(x)
mycursor.execute(
  "ALTER TABLE t_table ADD COLUMN id INT AUTO_INCREMENT PRIMARY KEY")
# 主键设置

# 单条记录插入
sql = "INSERT INTO t_table (name, url) VALUES (%s, %s)"
val = ("RUNOOB", "https://www.runoob.com")
mycursor.execute(sql, val)
mydb.commit()    # 数据表内容有更新，必须使用到该语句
print(mycursor.rowcount, "单条记录插入成功。")

# 批量插入记录的情况（val可以是列表）

sql = "INSERT INTO t_table (name, url) VALUES (%s, %s)"
val = [
  ('Google', 'https://www.google.com'),
  ('Github', 'https://www.github.com'),
  ('Taobao', 'https://www.taobao.com'),
  ('stackoverflow', 'https://www.stackoverflow.com/')
]
mycursor.executemany(sql, val)
mydb.commit()    # 数据表内容有更新，必须使用到该语句
print(mycursor.rowcount, "多条记录插入成功。")

# 插入数据并获取记录id

sql = "INSERT INTO t_table (name, url) VALUES (%s, %s)"
val = ("Zhihu", "https://www.zhihu.com")
mycursor.execute(sql, val)
mydb.commit()
print("1 条记录已插入, ID:", mycursor.lastrowid)

mycursor.execute("SELECT * FROM t_table")
# 获取指定字段的数据：
# mycursor.execute("SELECT name, url FROM sites")
myresult = mycursor.fetchall()     # fetchall() 获取所有记录
for x in myresult:
    print(x)

# 只读取一条数据的情况（fetchone（））
mycursor.execute("SELECT * FROM t_table")
myresult = mycursor.fetchone()
# 获取一条记录
print(myresult)

# 读取name字段的RUNOOB的记录：（防止数据库查询时发送sql注入攻击，可以使用占位符（%s）来转义查询的条件）

sql = "SELECT * FROM t_table WHERE name = %s"
na = ("RUNOOB", )

# %s占位符读取的是元组，所以na需定义为元组
mycursor.execute(sql, na)
myresult = mycursor.fetchall()
for x in myresult:
    print(x)

# 使用通配符匹配（%oo%）
sql = "SELECT * FROM t_table WHERE url LIKE '%oo%'"
mycursor.execute(sql)
myresult = mycursor.fetchall()
for x in myresult:
    print(x)

# 降序输出
sql = "SELECT * FROM t_table ORDER BY name DESC"
mycursor.execute(sql)
myresult = mycursor.fetchall()
for x in myresult:
    print(x)

# offset指定起始位置，默认为0
# 从第二条记录开始读取前3条记录
mycursor.execute("SELECT * FROM t_table LIMIT 3 OFFSET 1")
# 0 为 第一条，1 为第二条，以此类推
myresult = mycursor.fetchall()
for x in myresult:
    print(x)

# 删除记录

sql = "DELETE FROM t_table WHERE name = %s"
na = ("RUNOOB", )
mycursor.execute(sql, na)
mydb.commit()
print(mycursor.rowcount, " 条记录删除")

# 数据表更新
sql = "UPDATE t_table SET name = %s WHERE name = %s"
val = ("Zhihu", "ZH")
# 将name的内容ZH换为ZHihu
mycursor.execute(sql, val)
mydb.commit()
print(mycursor.rowcount, " 条记录被修改")

# 删除表
# sql = "DROP TABLE IF EXISTS t_table"  # 删除数据表
# mycursor.execute(sql)
