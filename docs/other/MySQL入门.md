# MySql

## 安装（Linux）

Debain or Ubuntu: `sudo apt-get install mysql mysql-server`
CentOS:`sudo yum install mysql mysql-server`
安装完成后需设置密码：`mysqladmin -u root -p password '密码'`
按照成功教程：[MySQL第一次安装](https://www.cnblogs.com/hongchengcheng/p/8623219.html)

## MySQL配置

1. 配置文件路径：
    - win（默认）:`C:\Program Files\MySQL\MySQL Server 5.6\my-default`
    - Linux:`/etc/my.cnf`
2. 修改配置文件：
    >`[client]`
    >`default-character-set=utf8`
    >`[mysqld]`
    >`character-set-server=utf8`
    >`default-storage-engine=INNODB`
3. 重启Mysql
    >win:通过Windows服务重启
    >linux(centos):/etc/init.d/mysql restart

## MySQL基本

- 命令
  - 查看当前有哪些数据库（DB,databases):`show databases`;
  - 添加数据库：`create database 数据库名;`;
  - 删除数据库：`drop database 数据库名;`;
- 数据类型
    MySQL有三种主要的数据类型：
    1. 文本类
    2. 数字类
    3. 日期类
  - 文本类：
    数据类型    |描述
    --|---
    CHAR（size）|保存固定长度（size）的字符串，可包含字母、数字以及特殊字符。在括号中指定字符串的长度，最多255个字符。
    VARCHAR（size）|保存可变长度的字符串，可包含字母、数字以及特殊字符。在括号中指定字符串的最大长度。最多255个字符。如果值的长度大于255，则转换为TEXT类型
    TINYTEXT|存放最大长度为255个字符的字符串
    TEXT|存放最大长度为65，535个字符的字符串
    BLOB|用于BLOBs（Binary Large Objects）。存放最多65，535字节的数据
    MEDIUMTEXT|存放最大长度为16，77，215个字符的字符串。
    MEDIUMBLOB|用于BLOBs（Binary Large Objects）。存放最多16，777，215字节的数据。
    LONGTEXT|存放最大长度为4，294，967，295个字符的字符串。
    LONGBLOB|用于BLOBsBinary Large Objects）。最多存放4，294，967，295字节的数据。
    ENUM（x，y，z，etc.）|允许输入可能值得列表。可以在ENUM列表中列出最大65535个值。如果列表中不存在插入得值，则插入空值。注意：这些值是按照输入得顺序存储得。可以按照此格式输入可能的值：`ENUM('x','y','z')`,每次只能取单值，如x或y或z，三者不能同时取
    SET|与ENUM类似，set最多只能包含64个列表项，不过SET可存储一个以上的值，即可以取多个值
  - 数字类
    数据类型    |描述
    --|---
    TINYINT（size）|-128到127常规。0-255无符号。在括号中规定最大位数
    SMALLINT（size）|-32768到32767常规。0到65535无符号。在括号中规定最大位数
    MEDIUMINT（size）|-8388608-8388697普通。0到1677215无符号。在括号中规定最大位数
    INT（size）|-2147483648到2147483647常规。0到4294967295无符号。在括号中规定最大位数
    BIGINT（size）|-9223372036854775808到9223372036854775807常规。0到18446744073709551615无符号。在括号中规定最大位数
    FLOAT（size，d）|带有浮动小数点的小数字。在括号中规定最大位数。在d参数中规定小数点右侧的最大位数。
    DOUBLE（size，d）|带有浮动小数点的大数字。在括号中规定最大位数，在d参数中规定小数点右侧的最大位数。
    DECIMAL（size，d）|作为字符串存储的DOUBLE类型，允许固定的小数点
  -日期类
    数据类型    |描述
    --|---
     DATE（）|日期。格式：YYYY-MM-DD.注：支持的范围是从‘1000-01-01’到‘9999-12-31’
     DATETIME（）|日期和时间的组合。格式：YYYY-MM-DD HH：MM：SS.注：支持的范围是从：‘1000-01-01 00：00：00’到‘9999-12-31 23：59：59’
     TIMESTAMP（）|时间戳，格式：YYYY-MM-DD HH：MM：SS. 注：支持的范围是从'1970-01-01 00:00:01'UTC到'2038-01-09 03:14:07'UTC
     TIME（）|时间。格式：HH：MM：SS. 注：支持的范围是从'-838:59:59'到'838:59:59'
     YEAR()|2位或4位格式的年。注：4位格式所允许的值：1901到2155.2位格式所允许的值：70到69，表示从1970到2069

## MySQL-table操作

### 添加和删除数据表（table）

- 创建数据表table：

    ```mysql
    create table table_name(
        colum_name data_type,
        colum_name data_type,
        .
        .
        .
        colum_name data_type,
    )
    //按列添加，（colum_name为每列的名字）实例
    create table account(
        id bigint(20),
        createTime datetime,
        ip varchar(255),
        mobile varchar(255),
        nickname varchar(255),
        password varchar(255),
        username varchar(255),
        avatar varchar(255),
        brief text,
        job varchar(255),
        location varchar(255),
        qq varchar(255),
        gender int(11),
        city varchar(255),
        province varchar(255)
    );
    ```

- 删除数据表table
    `drop table table_name;`
- 操作过程：
  - `show databases;`显示当前有哪些数据库
  - `use database_name`选择要进行操作的数据库
  - `show tables;`显示当前数据库有哪些数据表
  - 使用create创建数据表
  - 再次查看当前数据库的数据表
  - `describe table_name`,查看数据表具体内容
  - 使用drop删除数据表

### 修改table-增加、删除列

-增加列：

```mysql
    alter table table_name add column_name data_type [not null] [default]
    //其中，[]部分的内容是可选项（可选项可有可无），not null默认不为null，default设置默认值，例：
    alter table account add c1 int(11) not null default 1;
    //增加一个名为c1的列，数据类型为11位的int，默认值为1，该列不为null
```

- 删除列

```mysql
       alter table table_name drop column_name
       //例，
       alter table account drop c1;
```

- 操作过程
  - 选择使用的数据库
  - `alter table account add c1 int(11) not null default 1;`，增加一列
  - 显示表的详细信息
  - `alter table account drop c1;`删除列
  - 显示表的详细信息

### 修改table-修改列信息和表名

- 修改表名

    `alter table table_name change old_column_name new_colum_name data_type`
    1. 只改列名：
        >data_type和原来一样，old_column_name！=new_column_name
        >`alter table account change city newcity varchar(255);`
    2. 只改数据类型：
        >old_column_name==new_column_name,data_type改变
        >`alter table account change newcity newcity text;`
    3. 列名和数据类型都改变
        >`alter table account change newcity city varchar(255);`

### 插入&&查看数据表

- 查看数据表
    1. `select * from table_name;`查看表的所有数据
    2. `select col_name1,col_name2,... from tabe_name;`查看表特定列的数据
- 插入数据
    1. `insert into table_name values(val1,val2,...);`值和表的列一一对应，值的数量必须等于列的数量，且值的顺序与列的顺序一致
    2. `insert into table_name(col1,col2,...) values(val1,val2,...);`值与列一一对应

```mysql
insert into book values(1,'t hah','content');
insert into book(title) values('title1');
```

- 操作过程
  - 选择数据库
  - 新建一个book表：
  
```mysql
    create table book(
        id bigint(20),
        title varchar(255),
        content text
    );
```

- 插入数据
  - 每列均插入数据：`insert into book values(1,'book_name1','content1');`
  - 查看表的内容：`select * from book;`
  - 选定列插入数据：`insert into book(title) values('eduncation');`
  - 查看选定表的内容：`select title,content from book;`
    >注意：插入数据是按行（记录）插入，且不会覆盖之前已经存在的行（记录），即使一行中并为对某列赋值，但该列还是会占据内存空间

### where条件

- 语法
    `select * from table_name where col_name 运算符 值`
    >例：`select * from book where title = 't';`
- 运算符
    运算符  |描述
    --|---
    =|等于
    ！=|不等于
    \>|大于
    \<|小于
    \>=|大于等于
    \<=|小于等于
    between|在两个值范围内
    like|按某个模式查找

- 组合条件：`and , or`
    >where后面可以通过and与or运算符组合多个条件筛选
    >语法：`select * from table_name where col1 = xxx and col2 = xx or col3 >xx`

    实例：

    ```mysql
    //查出book中id等于1的行（记录）
    select * from book where id = 1;
    //查出id=1或者content为c的行（记录）
    select * from book where id = 1 or contetn='c';
    //查出content为c，title为t
    select * from book where title = 't' and content = 'c';
    //查找id为1，且content为c或title为t,括号优先级高
    select * from book where id = 1 and (content = 'c' or title = 't');
    //当where后判断语句为真时，会查询到整个数据表
    select * from book where id = 0 or 1 = 1;
    ```

### where条件中null字段的判断

null的判断是比较特殊的一个情况，在使用where条件查找null字段时，直接判断会返回空值，即：
`select * from book where id = null;`
>Empty set (0.00 sec)(终端显示结果)
null的判断语法：（is /is not）
`select * from table_name where col_name is null;`查找字段为null的行（记录）
`select * from table_name where col_name is not null;`查找字段不为null的行（记录）

### select distinct，去掉重复查询结果

distinct(精确的)
`select distinct col_name from table_name;`
例,
`select distinct title from book;`去除book表中title中内容相同的记录
`select distinct title,content from book;`
去除book表中title和content
内容均一致的记录

### 使用order by 对查询结果排序

1. 按单一列名排序：
    `select * from table_name [where 子句] order by col_name [asc/desc]`
2. 按多列排序：
    `select * from table_name [where 子句] order by col1[asc/desc],col2[asc/desc]...`
    当col1中内容一致时，按照col2的内容排序，依次类推
    >注意：不加asc（升序）或者desc（降序）时，默认为asc
    >例，`select * from book where title = 't' id desc,content asc;`查找book表中title为t的记录，并且id按照降序排序，id一致时，按 content升序排序

### select结果按limit截取

`select *from table_name [where 子句] [oder by 子句] limit [offset,]rwoCount；`
offset:查询结果的起始位置（下标从0开始，即第一条记录其实就是0）
rowCount：从offset开始，获取的记录数
>注意：limit rowCount = limit 0,rowCount
`select * from book where title = 't' oder by id asc limit 0,2;`
选取book表中title为并且id按照升序排列后的前两条记录（行）

### insert into和select组合使用

`insert into [table_name1] select col1,col2 from [table_name2];`
`insert into [table_name1](col1,col2) select col3,col4 from [table_name2];`
例，
`insert into book2 select * from book1 where id != 1;`book1和book2列数一致时，将book1中id不等于1的记录添加到book2中
`insert into book2(title) select content from book1;`
将book1中的content内容作为title插入到book1中
`insert into book2 select name,price,id from bookbox;`
bookbox（大于3列）与book1（3列）列数不一致，将bookbox中选定的三列内容的记录添加到book1对应的三列中

### 更新数据表

update语法

1. 修改单列：
    `update table_name set column_name = xxx[where 子句];`
2. 修改多列：
    `update table_name set column_name1 = xxx,cloumn_name2 =xxx...[where 子句];`
    >例，
    >`update book set title = 'a';`将book表中title列所有内容更新为a
    >`update book set content = 'good' where id = 2;`将book表中id为2的记录content项内容修改为good
    >`update book set title = 't',content = 'bad',id = 0;`将book表中所有记录的title项内容更新为t，content项内容更新为bad，id项内容更新为0

### where的in操作符

in语法
`select * from table_name where column_name in (value1,value2,...);`
`select * from tabele_name where column_name in (select column_name from table_name)`
>注：column_name in (value1,value2...)等同 column = value1 or column_name = =value2...
>例，
>`select * from book where title in ('sun','color');`查找出book中title项内容为sun或color的记录（行）
>`select * from book where title in (select title from book2 where id <4);`查找出book表中title项内容为book2中id<4，title项的内容的记录（行）

### between操作符

`select * from table_name where column_name between value1 and value2;`
`select * from table_name where column_name not between value1 and value2;`
between 值1 and 值2，相当于大于等于值1且小于等于值2的范围
>例，
>`select * from book where id between 2 and 5;`查找book表中id项值在[2,5]上的记录
>`select * from book where id not between 2 and 5;`查找book表中id项值不在[2,5]上的记录

### where的like操作符

`select * from table_name where column_name [not] like pattern;`
like的作用是进行模糊匹配。
pattern：匹配模式,比如
'abc'，匹配字段为abc的记录；
'%abc'，匹配字段以abc结尾的记录（包括abc本身）；
'abc%'，匹配字段以abc开头的记录（包括abc本身）；
'%abc%'，匹配包含字段abc的记录（包括abc本身）。
“%”是一个通配符，理解上可以当成任意字符串，如'%abc'可以匹配到字符串'erttsabc'
>`select * from book where title like 't';`匹配book表中title内容为t的记录；
>`select * from book where title like '%t';`匹配book表中title内容以t结尾（包括t本身）的记录；
>`select * from book where title like '%t%';`匹配book表中title内容中包含t（包括t本身）的记录。
>注：like后的内容必须以单引号括起来
