# MySql(Python)

## Python MySQL - mysql-connector 驱动

mysql-connector 是 MySQL 官方提供的驱动器。
安装mysql-connector：`python -m pip install mysql-connector`

## 创建连接数据库

### 连接数据库

```python
import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",       # 数据库主机地址
  user="username",    # 数据库用户名
  buffered=True,      #解决查询报错：“unread result found”的问题
  passwd="password"   # 数据库密码
)
print(mydb)
```

### 创建数据库

```python
import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  buffered=True,
  passwd="password"
)
mycursor = mydb.cursor()
mycursor.execute("CREATE DATABASE test_db_")
#创建数据库前可以使用“show databases”查看数据库是否存在：

import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  buffered=True,
  passwd="password"
)
mycursor = mydb.cursor()
mycursor.execute("SHOW DATABASES")
for x in mycursor:
  print(x)

#此方法会打印存在的所有数据库
#也可以直接连接数据库，如果不存在数据库就会输出错误信息

import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
#综合下来可以加入异常处理（数据库不存在时就新建数据库）

import mysql.connector
try:
  mydb = mysql.connector.connect(
    host="localhost",
    user="username",
    passwd="password",
    buffered=True,
    database="test_db"
  )
  print("数据库已存在")
  mycursor = mydb.cursor()
except:
  mydb = mysql.connector.connect(
  host="localhost",
  user="username",
  buffered=True,
  passwd="password"
)
  mycursor = mydb.cursor()
  mycursor.execute("CREATE DATABASE test_db")
  print("数据库已创建")
print("数据库有：")
mycursor.execute("SHOW DATABASES")
for x in mycursor:
  print(x,end=',')
```

## 创建数据表

创建数据表使用 "CREATE TABLE" 语句，创建数据表前，需要确保数据库已存在。

```python
#创建一个名为t_table的数据表
import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="username",
  passwd="password",
  buffered=True,
  database="test_db:
)
mycursor = mydb.corsor()
mycursor.execute("CREATE TABLE t_table(name VARCHAR(255),url VARCHAR(255))")
#查看已有数据表
mycursor.execute("SHOW TABLES")
for x in mycursor:
  print(x)
```

### 主键设置

创建表的时候我们一般都会设置一个主键（PRIMARY KEY），使用 "INT AUTO_INCREMENT PRIMARY KEY" 语句来创建一个主键，主键起始值为 1，逐步递增。
如果数据表已经创建，使用 ALTER TABLE 来给表添加主键：

```python
import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="username",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
mycursor.execute("ALTER TABLE t_table ADD COLUMN id INT AUTO_INCREMENT PRIMARY KEY")
```

如果数据表不存在，则：

```python
import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="username",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
mycursor.execute("CREATE TABLE t_table (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255), url VARCHAR(255))")
```

## 插入数据

插入数据使用“INSERT INTO”

```python
import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()

#单条记录插入
sql = "INSERT INTO t_table (name, url) VALUES (%s, %s)"
val = ("RUNOOB", "https://www.runoob.com")
mycursor.execute(sql, val)
mydb.commit()    # 数据表内容有更新，必须使用到该语句
print(mycursor.rowcount, "记录插入成功。")

#批量插入记录的情况（val可以是列表）
sql = "INSERT INTO t_table (name, url) VALUES (%s, %s)"
val = [
  ('Google', 'https://www.google.com'),
  ('Github', 'https://www.github.com'),
  ('Taobao', 'https://www.taobao.com'),
  ('stackoverflow', 'https://www.stackoverflow.com/')
]
mycursor.executemany(sql, val)
mydb.commit()    # 数据表内容有更新，必须使用到该语句
print(mycursor.rowcount, "记录插入成功。")
```

如果想在数据记录插入后，获取该记录的 ID ，可以使用以下代码：

```python
import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
sql = "INSERT INTO t_table (name, url) VALUES (%s, %s)"
val = ("Zhihu", "https://www.zhihu.com")
mycursor.execute(sql, val)
mydb.commit()
print("1 条记录已插入, ID:", mycursor.lastrowid)
#lastrowid方法用于获取id
```

## 查询数据

查询数据用select语句：

```python
#获取所有记录（fecthall（））

import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
mycursor.execute("SELECT * FROM t_table")
#获取指定字段的数据：
#mycursor.execute("SELECT name, url FROM sites")
myresult = mycursor.fetchall()     # fetchall() 获取所有记录
for x in myresult:
  print(x)

#只读取一条数据的情况（fetchone（））

import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
mycursor.execute("SELECT * FROM t_table")
myresult = mycursor.fetchone()
#获取一条记录
print(myresult)
```

### where条件语句

读取指定条件的数据，使用where语句

```python
#读取name字段的RUNOOB的记录：

import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
sql = "SELECT * FROM t_table WHERE name ='RUNOOB'"
mycursor.execute(sql)
myresult = mycursor.fetchall()
for x in myresult:
  print(x)

#使用通配符匹配（%oo%）

import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
sql = "SELECT * FROM t_table WHERE url LIKE '%oo%'"
mycursor.execute(sql)
myresult = mycursor.fetchall()
for x in myresult:
  print(x)

#防止数据库查询时发送sql注入攻击，可以使用占位符（%s）来转义查询的条件

import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
sql = "SELECT * FROM t_table WHERE name = %s"
na = ("RUNOOB", )#%s占位符读取的是元组，所以na需定义为元组
mycursor.execute(sql, na)
myresult = mycursor.fetchall()
for x in myresult:
  print(x)
```

### 排序order by

查询结果排序可以使用 ORDER BY 语句，默认的排序方式为升序，关键字为 ASC，如果要设置降序排序，可以设置关键字 DESC。

```python
#降序排序实例

import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
sql = "SELECT * FROM t_table ORDER BY name DESC"
mycursor.execute(sql)
myresult = mycursor.fetchall()
for x in myresult:
  print(x)
```

### Limt

limt可设置查询的数量

```python
#offset指定起始位置，默认为0
#从第二条记录开始读取前3条记录
import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
mycursor.execute("SELECT * FROM t_table LIMIT 3 OFFSET 1")  # 0 为 第一条，1 为第二条，以此类推
myresult = mycursor.fetchall()
for x in myresult:
  print(x)
```

## 删除记录

删除记录使用 "DELETE FROM" 语句：

```python

import mysql.connector

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
sql = "DELETE FROM t_table WHERE name = 'RUNOOB'"
mycursor.execute(sql)
mydb.commit()
print(mycursor.rowcount, " 条记录删除")
```

>注意：要慎重使用删除语句，删除语句要确保指定了 WHERE 条件语句，否则会导致整表数据被删除。为了防止数据库查询发生 SQL 注入的攻击，可以使用 %s 占位符来转义删除语句的条件：

```python

import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
sql = "DELETE FROM t_table WHERE name = %s"
na = ("RUNOOB", )
mycursor.execute(sql, na)
mydb.commit()
print(mycursor.rowcount, " 条记录删除")
```

## 更新数据表

数据表更新使用 "UPDATE" 语句：

```python
import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
sql = "UPDATE t_table SET name = 'ZH' WHERE name = 'Zhihu'"
mycursor.execute(sql)
mydb.commit()
print(mycursor.rowcount, " 条记录被修改")
```

>注意：UPDATE 语句要确保指定了 WHERE 条件语句，否则会导致整表数据被更新。为了防止数据库查询发生 SQL 注入的攻击，可以使用 %s 占位符来转义更新语句的条件：

```python

import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
sql = "UPDATE t_table SET name = %s WHERE name = %s"
val = ("Zh", "ZHihu")
mycursor.execute(sql, val)
mydb.commit()
print(mycursor.rowcount, " 条记录被修改")
```

## 删除表

删除表使用 "DROP TABLE" 语句， IF EXISTS 关键字是用于判断表是否存在，只有在存在的情况才删除：

```python
import mysql.connector
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="password",
  buffered=True,
  database="test_db"
)
mycursor = mydb.cursor()
sql = "DROP TABLE IF EXISTS t_table"  # 删除数据表
mycursor.execute(sql)
```
