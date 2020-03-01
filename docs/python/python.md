# python

## python中的文件操作

```python
#读文件
open("文件地址+文件名","操作形式")
```

open表示读文件，他有两个参数，第一个是文件的地址以及文件名，这里可以是相对路径也可以是绝对路径，但使用相对路径时，要读取的文件需和python文件在同一目录下。
第二个参数表示文件的权限，分为三种：
>r:表示读文件
>w:表示写文件
>a:表示追加文件，w，r都会覆盖之前的内容重新写入，而a会在原内容后添加
>b:表示二进制文件，即将文件以二进制的形式读入

打开的文件可以赋值给一个变量，即文件的句柄：

```python
f=open('D:\\Python\\test.txt','r')
#变量f即为句柄
#python中地址中为斜杠'/'或者两个反斜杠 '\\'
```

将文件内容显示出来，可以使用 ==read()== 函数或 ==readline()== 函数，两者的区别在于：

1. ==read()== 函数会将文件的全部内容读取出来；
2. ==readline()== 函数则只读取文件的一行内容。

使用时，两种方式：

```python
f=open('D:/python/test.txt','r')#这里可能会出现编码报错,解决如下
# f=open('D:python/test.txt','r',encoding='UTF-8')
#第一种方式
print(f.read())
print(f.raedline())
#第二种方式
data1=f.read()
print(data1)
data2=f.readline()
print(data2)
```

即可以将读的内容赋给一个变量，再对这个变量进行操作，也可以直接操作，不赋给变量。
文件操作结束后需关闭文件，即：

```python
f.colse()
```

写入文件

```python
#方式1
f=open('D:/python/test.txt','w')
data1="hello"
data2='world'
f.write(data1)
f.write(data2)
f.close()
#只有当调用close函数后，才会保存文件，所以上述代码执行完后，test.txt文件中
#方式2
f=open('D:/python/test.txt','w')
data1="hello"
f.write(data1)
f.close()
data2='world'
f.write(data2)
f.close()
#这种方式在执行完后，test.txt文档中只会有字符 ‘world’，先前写入的 ‘hello’ 会被覆盖
#方式3
f=open('D:/python/test.txt','w')
data1="hello"
f.write(data1)
f.close()
data2='world'
f.write(data2)
f.close()
#将操作形式改为 a+ 也能得到方式1的结果
```

## python中异常处理

格式：
>try:
> 程序块
>except Exception as 异常名：
> 异常处理程序块

在使用了异常处理的部分，如果发生异常，那么程序并不会终止执行，而是执行except后的语句，接着再执行后续的语句。

```python
try:
    for i in range(10):
        if(i==7):
            print(j)
        print(i,end=',')
except Exception as erro:
    print(erro)
print('hello,python!')
```

>本段代码的运行结果为：
0,1,2,3,4,5,6,name 'j' is not defined
hello,python!

可以看出，程序并不会终止执行，而是输出异常信息（异常处理部分）后继续执行。
另一种情况，异常处理在循环中时，就类似于continue语句，即终止当前循环，接着执行下一循环

```python
for i in range(10):
    try:
        if i==7:
            print(j)
    except Exception as erro:
        print(erro)
    print(i)
print('hello,python!')
```

>本段代码运行结果如下：
0,1,2,3,4,5,6,name 'j' is not defined
7,8,9,hello,python!

若不想做异常处理，则再except的作用域下使用pass占位符即可：

```python
for i in range(10):
    try:
        if i==7:
            print(j)
    except Exception as erro:
        pass
    print(i)
print('hello,python!')
```

>运行结果如下：
0,1,2,3,4,5,6,7,8,9,hello,python!

## python中面向对象编程

定义类

```python
class 类名：
    pass
```

类的实例化

```python
class test:
    pass
opp=test()
```

类的构造函数（实例化类时不用调用，构造函数会自动执行）
构造函数的实际意义：初始化，因此想要给类添加参数时，只需要对构造函数添加参数即可。

```python
class test:
    def __init__(self):
        pass
    #init前后都是双下划线
```

>tips:只要是在类中定义的方法，形参列表都为（self，参数），即
def func(self, 参数1，参数2，……)

属性：类的静态特征，即类的成员变量：self.变量名
方法：类的动态特征，即类的成员函数：def 函数名（self, 参数）

```python
class test():
    def __init__(self,n,m):
        self.name=n
        self.job=m
    def func(self,a,b):
        print(a,b)
        print(self.name,self.job)
```

类的继承与重载
==继承== 把某一个类或多个类（基类）的特征拿过来，单继承、多继承均可再添加自己新的方法（功能）；
==重载== 在子类（派生类）里面对继承过来的特征重新定义,对继承的方法有所优化（减弱）；
==父类== 基类
==子类== 派生类

```python
#基类
class father():
    def speak(self):
        print("I can speak!")
class mother():
    def write(self):
        print("I can write!")
#派生类（单继承）
class son1(father):
    pass
s=son1()
s.speak()
#派生类（多继承）
class daughter(father,mother):
    def listen(self):
        print("I can listen!")
d=daughter()
d.speak()
d.listen()
d.write()
#重载
class son2(father):
    def speak(self):
        print("I can't speak!")
s1=son2()
s1.speak()
