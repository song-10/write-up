import pymysql

# 选择数据库/不存在时创建数据库
try:
    db = pymysql.connect(
        host="192.168.218.139",
        user="root",
        passwd="root10",
        database="TESTDB")
    cursor = db.cursor()
    cursor.execute("SELECT VERSION()")
    data = cursor.fetchone()
    print("Database version : %s " % data)
except Exception as err:
    print(err)
    db = pymysql.connect(
        host="192.168.218.139",
        user="root",
        passwd="root10")
    cursor = db.corsor()
    cursor.execute("create database TESTDB")
    print("数据库已创建")

# 使用预处理语句创建表
cursor.execute("DROP TABLE IF EXISTS EMPLOYEE")
sql = """CREATE TABLE EMPLOYEE (
         FIRST_NAME  CHAR(20) NOT NULL,
         LAST_NAME  CHAR(20),
         AGE INT,
         SEX CHAR(1),
         INCOME FLOAT )"""
cursor.execute(sql)
print("数据表创建完成")

# 擦插入数据
sql = "INSERT INTO EMPLOYEE(\
            FIRST_NAME, LAST_NAME, AGE, SEX, INCOME) \
            VALUES ('%s', '%s',  %s,  '%s',  %s)" % \
            ('Mac', 'Mohan', 20, 'M', 2000)
# 反斜杠\，仅表示指令换行，无其他作用
try:
    # 执行sql语句
    cursor.execute(sql)
# 执行sql语句
    db.commit()
    print("数据表插入完成")
except Exception as err:
    # 发生错误时回滚
    print(err)
    db.rollback()
# 数据库里做修改后 （ update ,insert , delete）未commit 之前 使用rollback 可以恢复数据到修改之前。

# SQL 查询语句

sql = "SELECT * FROM EMPLOYEE WHERE INCOME > %s" % (1000)
try:
    # 执行SQL语句
    cursor.execute(sql)
    # 获取所有记录列表
    results = cursor.fetchall()
    for row in results:
        fname = row[0]
        lname = row[1]
        age = row[2]
        sex = row[3]
        income = row[4]
        # 打印结果
    print("fname=%s,lname=%s,age=%s,sex=%s,\
        income=%s" % (fname, lname, age, sex, income))
except Exception as err:
    print(err)

# 更新操作用于更新数据表的的数据，以下实例将 TESTDB 表中 SEX 为 'M' 的 AGE 字段递增 1：
# SQL 更新语句
sql = "UPDATE EMPLOYEE SET AGE = AGE + 1 WHERE SEX = '%c'" % ('M')
try:
    # 执行SQL语句
    cursor.execute(sql)
    # 提交到数据库执行
    db.commit()
    print("数据表更新完成")
except Exception as err:
    # 发生错误时回滚
    print(err)
    db.rollback()

# SQL 删除语句
sql = "DELETE FROM EMPLOYEE WHERE AGE > %s" % (50)
try:
    # 执行SQL语句
    cursor.execute(sql)
    # 提交修改
    db.commit()
    print("删除记录完成")
except Exception as err:
    # 发生错误时回滚
    print(err)
    db.rollback()
# 关闭连接
db.close()
