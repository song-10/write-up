# 正则表达式（Python3）

## Python3 正则表达式(re库)

### re.match函数

re.match 尝试从字符串的起始位置匹配一个模式，如果不是起始位置匹配成功的话，match()就返回none。
`re.match(pattern, string, flags=0)`
<p>函数参数说明：</p>
<table>
<tbody>
   <tr><th>参数</th><th>描述</th>   </tr>
   <tr><td>pattern</td><td>匹配的正则表达式</td></tr>
   <tr><td>string</td><td>要匹配的字符串。</td></tr>
   <tr><td>flags</td><td>标志位，用于控制正则表达式的匹配方式，如：是否区分大小写，多行匹配等等。</td></tr>
</tbody></table>
<p>`group(num)和gropus()`方法：</p>
<table>
<tbody>
   <tr><th>匹配对象方法</th><th>描述</th></tr>
   <tr><td>group(num=0)</td><td>匹配的整个表达式的字符串，group() 可以一次输入多个组号，在这种情况下它将返回一个包含那些组所对应值的元组。</td></tr>
   <tr><td>groups()</td><td>返回一个包含所有小组字符串的元组，从 1 到 所含的小组号。</td></tr>
</tbody></table>

```python
#!/usr/bin/python3
import re
line = "Cats are smarter than dogs";
searchObj = re.search( r'(.*) are (.*?) .*', line, re.M|re.I)
if searchObj:
   print ("searchObj.group() : ", searchObj.group())
   print ("searchObj.group(1) : ", searchObj.group(1))
   print ("searchObj.group(2) : ", searchObj.group(2))
else:
   print ("Nothing found!!")
"""
执行结果如下：
searchObj.group() :  Cats are smarter than dogs
searchObj.group(1) :  Cats
searchObj.group(2) :  smarter
"""
```

### re.search方法

re.search扫描整个字符串并返回第一个成功的匹配：`re,serach(pattern,strings,flags=0)`,否则就返回None
<table>
<tbody>
   <tr><th>参数</th><th>描述</th></tr>
   <tr><td>pattern</td><td>匹配的正则表达式</td></tr>
   <tr><td>string</td><td>要匹配的字符串。</td></tr>
   <tr><td>flags</td><td>标志位，用于控制正则表达式的匹配方式，如：是否区分大小写，多行匹配等等。</td></tr>
</tbody>
</table>
<p>`group(num)和gropus()`方法：</p>
<table>
<tbody>
   <tr><th>匹配对象方法</th><th>描述</th></tr>
   <tr><td>group(num=0)</td><td>匹配的整个表达式的字符串，group() 可以一次输入多个组号，在这种情况下它将返回一个包含那些组所对应值的元组。</td></tr>
   <tr><td>groups()</td><td>返回一个包含所有小组字符串的元组，从 1 到 所含的小组号。</td></tr>
</tbody></table>

```python
#!/usr/bin/python3
import re
print(re.search('www', 'www.runoob.com').span())  # 在起始位置匹配
print(re.search('com', 'www.runoob.com').span())         # 不在起始位置匹配
#运行结果为：
#(0,3)
#(11,14)
```

### re.match与re.search的区别

re.match只匹配字符串的开始，如果字符串开始不符合正则表达式，则匹配失败，函数返回None；而re.search匹配整个字符串，直到找到一个匹配。

```python

#!/usr/bin/python3
import re
line = "Cats are smarter than dogs";
matchObj = re.match( r'dogs', line, re.M|re.I)
if matchObj:
   print ("match --> matchObj.group() : ", matchObj.group())
else:
   print ("No match!!")

matchObj = re.search( r'dogs', line, re.M|re.I)
if matchObj:
   print ("search --> matchObj.group() : ", matchObj.group())
else:
   print ("No match!!")
#结果如下：
#No match!!
#search --> matchObj.group() :  dogs
```

### 检索和替换

re.sub用于替换字符串中的匹配项：`re.sub(pattern,rep1,string,count=0,flags=0)`
   参数  |描述
   --|---
   pattern | 正则中的模式字符串。
   repl | 替换的字符串，也可为一个函数。
   string | 要被查找替换的原始字符串。
   count | 模式匹配后替换的最大次数，默认 0 表示替换所有的匹配。
   flags | 编译时用的匹配模式，数字形式。
>注：前三个为必选参数，后两个为可选参数。

```python

#!/usr/bin/python3
import re
phone = "2004-959-559 # 这是一个电话号码"
# 删除注释
num = re.sub(r'#.*$', "", phone)
print ("电话号码 : ", num)
# 移除非数字的内容
num = re.sub(r'\D', "", phone)
print ("电话号码 : ", num)
#运行结果
#电话号码 :  2004-959-559
#电话号码 :  2004959559
```

#### repl参数是一个函数的情况

```python
#!/usr/bin/python
import re
# 将匹配的数字乘于 2
def double(matched):
    value = int(matched.group('value'))
    return str(value * 2)
s = 'A23G4HFD567'
print(re.sub('(?P<value>\d+)', double, s))
#将字符串中的匹配的数字乘2
#运行结果：
#A46G8HFD1134
```

### compile函数

compile 函数用于编译正则表达式，生成一个正则表达式（ Pattern ）对象，供 match() 和 search() 这两个函数使用。
`re.compile(pattern[, flags])`
   参数  |描述
   --|---
   pattern | 一个字符串形式的正则表达式
   flags |可选，表示匹配模式，比如忽略大小写，多行模式等，具体参数为：
   re.I |忽略大小写
   re.L |表示特殊字符集 \w, \W, \b, \B, \s, \S 依赖于当前环境
   re.M |多行模式
   re.S |即为' . '并且包括换行符在内的任意字符（' . '不包括换行符）
   re.U |表示特殊字符集 \w, \W, \b, \B, \d, \D, \s, \S 依赖于 Unicode 字符属性数据库
   re.X |为了增加可读性，忽略空格和' # '后面的注释

```python
import re
pattern = re.compile(r'\d+')                    # 用于匹配至少一个数字
m = pattern.match('one12twothree34four')        # 查找头部，没有匹配
print m
#结果：None
m = pattern.match('one12twothree34four', 2, 10) # 从'e'的位置开始匹配，没有匹配
print m
#结果：None
m = pattern.match('one12twothree34four', 3, 10) # 从'1'的位置开始匹配，正好匹配
print m                                         # 返回一个 Match 对象
#结果：<_sre.SRE_Match object at 0x10a42aac0>
m.group(0)   # 可省略 0
#结果：'12'
m.start(0)   # 可省略 0
#结果：3
m.end(0)     # 可省略 0
#结果：5
m.span(0)    # 可省略 0
#结果：(3, 5)
```

匹配成功时返回一个Macth对象，其中：

- group([group1, …]) 方法用于获得一个或多个分组匹配的字符串，当要获得整个匹配的子串时，可直接使用 group() 或 group(0)；
- start([group]) 方法用于获取分组匹配的子串在整个字符串中的起始位置（子串第一个字符的索引），参数默认值为 0；
- end([group]) 方法用于获取分组匹配的子串在整个字符串中的结束位置（子串最后一个字符的索引+1），参数默认值为 0；
- span([group]) 方法返回 (start(group), end(group))。

```python
import re
pattern = re.compile(r'([a-z]+) ([a-z]+)', re.I)   # re.I 表示忽略大小写
m = pattern.match('Hello World Wide Web')
print m                               # 匹配成功，返回一个 Match 对象
#结果：<_sre.SRE_Match object at 0x10bea83e8>
m.group(0)                            # 返回匹配成功的整个子串
#结果：'Hello World'
m.span(0)                             # 返回匹配成功的整个子串的索引
#结果：(0, 11)
m.group(1)                            # 返回第一个分组匹配成功的子串
#结果：'Hello'
m.span(1)                             # 返回第一个分组匹配成功的子串的索引
#结果：(0, 5)
m.group(2)                            # 返回第二个分组匹配成功的子串
#结果：'World'
m.span(2)                             # 返回第二个分组匹配成功的子串索引
#结果：(6, 11)
m.groups()                            # 等价于 (m.group(1), m.group(2), ...)
#结果：('Hello', 'World')
m.group(3)                            # 不存在第三个分组
#结果：Traceback (most recent call last):
#结果：  File "<stdin>", line 1, in <module>
#结果：IndexError: no such group
```

### findall

在字符串中找到正则表达式所匹配的所有子串，并返回一个列表，如果没有找到匹配的，则返回空列表。
>注意： match 和 search 是匹配一次 findall 匹配所有
`findall(string[,pos[,endpos]])`
参数：

- string 待匹配的字符串。
- pos 可选参数，指定字符串的起始位置，默认为 0。
- endpos 可选参数，指定字符串的结束位置，默认为字符串的长度。
查找字符串中所有数字：

```python
import re
pattern = re.compile(r'\d+')   # 查找数字
result1 = pattern.findall('runoob 123 google 456')
result2 = pattern.findall('run88oob123google456', 0, 10)
print(result1)
print(result2)
#结果：
#['123', '456']
#['88', '12']
```

### re.finditer

和 findall 类似，在字符串中找到正则表达式所匹配的所有子串，并把它们作为一个迭代器返回。
`re.finditer(pattern,string,flags=0)`

<p>函数参数说明：</p>
<table>
<tbody>
   <tr><th>参数</th><th>描述</th></tr>
   <tr><td>pattern</td><td>匹配的正则表达式</td></tr>
   <tr><td>string</td><td>要匹配的字符串。</td></tr>
   <tr><td>flags</td><td>标志位，用于控制正则表达式的匹配方式，如：是否区分大小写，多行匹配等等。</td></tr>
</tbody></table>

实例：

```python
import re
it = re.finditer(r"\d+","12a32bc43jf3")
for match in it:
    print (match.group(),end=',')
#结果：12,32,43,3
```

### re.split

split 方法按照能够匹配的子串将字符串分割后返回列表：`re.split(pattern,string[,maxsplit=0,flags=0])`

<p>函数参数说明：</p>
<table>
<tbody>
   <tr><th>参数</th><th>描述</th></tr>
   <tr><td>pattern</td><td>匹配的正则表达式</td></tr>
   <tr><td>string</td><td>要匹配的字符串。</td></tr>
   <tr><td>maxsplit</td><td>分隔次数，maxsplit=1 分隔一次，默认为 0，不限制次数。</td></tr>
   <tr><td>flags</td><td>标志位，用于控制正则表达式的匹配方式，如：是否区分大小写，多行匹配等等。</td></tr>
</tbody></table>

实例：

```python
import re
re.split('\W+', 'runoob, runoob, runoob.')
#结果：['runoob', 'runoob', 'runoob', '']
re.split('(\W+)', ' runoob, runoob, runoob.')
#结果：['', ' ', 'runoob', ', ', 'runoob', ', ', 'runoob', '.', '']
re.split('\W+', ' runoob, runoob, runoob.', 1)
#结果：['', 'runoob, runoob, runoob.']
re.split('a*', 'hello world')   # 对于一个找不到匹配的字符串而言，split 不会对其作出分割
#结果：['hello world']
```

## 正则表达式对象

### re.RegexObject

re.complime()返回RegexObject对象

### re.MacthObject

group()返回被RE匹配的字符串

- `start()`返回匹配开始的位置；
- `end()`返回匹配结束的位置；
- `span()`返回一个元组包含匹配（开始，结束）的位置。

### 正则表达式-可选标志

正则表达式可以包含一些可选标志修饰符来控制匹配的模式。修饰符被指定为一个可选的标志。多个标志可以通过按位 OR(|) 它们来指定。如 re.I | re.M 被设置成 I 和 M 标志：

<table>
<tbody>
   <tr><th>修饰符</th><th>描述</th></tr>
   <tr><td>re.I</td><td>使匹配对大小写不敏感</td></tr>
   <tr><td>re.L</td><td>做本地化识别（locale-aware）匹配</td></tr>
   <tr><td>re.M</td><td>多行匹配，影响 ^ 和 $</td></tr>
   <tr><td>re.S</td><td>使 . 匹配包括换行在内的所有字符</td></tr>
   <tr><td>re.U</td><td>根据Unicode字符集解析字符。这个标志影响 \w, \W, \b, \B.</td></tr>
   <tr><td>re.X</td><td>该标志通过给予你更灵活的格式以便你将正则表达式写得更易于理解。</td></tr>
</tbody></table>

### 正则表达式模式

模式字符串使用特殊的语法来表示一个正则表达式：
字母和数字表示他们自身。一个正则表达式模式中的字母和数字匹配同样的字符串。
多数字母和数字前加一个反斜杠时会拥有不同的含义。
标点符号只有被转义时才匹配自身，否则它们表示特殊的含义。
反斜杠本身需要使用反斜杠转义。

<table>
<tbody>
   <tr><th>模式</th><th>描述</th></tr>
   <tr><td>^</td><td>匹配字符串的开头</td></tr>
   <tr><td>$</td><td>匹配字符串的末尾。</td></tr>
   <tr><td>.</td><td>匹配任意字符，除了换行符，当re.DOTALL标记被指定时，则可以匹配包括换行符的任意字符。</td></tr>
   <tr><td>[...]</td><td>用来表示一组字符,单独列出：[amk] 匹配 'a'，'m'或'k'</td></tr>
   <tr><td>[^...]</td><td>不在[]中的字符：[^abc] 匹配除了a,b,c之外的字符。</td></tr>
   <tr><td>re*</td><td>匹配0个或多个的表达式。</td></tr>
   <tr><td>re+</td><td>匹配1个或多个的表达式。</td></tr>
   <tr><td>re?</td><td>   匹配0个或1个由前面的正则表达式定义的片段，非贪婪方式</td></tr>
   <tr><td>re{ n}</td><td>匹配n个前面表达式。例如，"o{2}"不能匹配"Bob"中的"o"，但是能匹配"food"中的两个o。</td></tr>
   <tr><td>re{ n,}</td><td>精确匹配n个前面表达式。例如，"o{2,}"不能匹配"Bob"中的"o"，但能匹配"foooood"中的所有o。"o{1,}"等价于"o+"。"o{0,}"则等价于"o*"。</td></tr>
   <tr><td>re{ n, m}</td><td>匹配 n 到 m 次由前面的正则表达式定义的片段，贪婪方式</td></tr>
   <tr><td>a| b</td><td>匹配a或b</td></tr>
   <tr><td>(re)</td><td>匹配括号内的表达式，也表示一个组</td></tr>
   <tr><td>(?imx)</td><td>正则表达式包含三种可选标志：i, m, 或 x 。只影响括号中的区域。</td></tr>
   <tr><td>(?-imx)</td><td>正则表达式关闭 i, m, 或 x 可选标志。只影响括号中的区域。</td></tr>
   <tr><td>(?: re)</td><td> 类似 (...), 但是不表示一个组</td></tr>
   <tr><td>(?imx: re)</td><td>在括号中使用i, m, 或 x 可选标志</td></tr>
   <tr><td>(?-imx: re)</td><td>在括号中不使用i, m, 或 x 可选标志</td></tr>
   <tr><td>(?#...)</td><td>注释.</td></tr>
   <tr><td>(?= re)</td><td>前向肯定界定符。如果所含正则表达式，以 ... 表示，在当前位置成功匹配时成功，否则失败。但一旦所含表达式已经尝试，匹配引擎根本没有提高；模式的剩余部分还要尝试界定符的右边。</td></tr>
   <tr><td>(?! re)</td><td>前向否定界定符。与肯定界定符相反；当所含表达式不能在字符串当前位置匹配时成功。</td></tr>
   <tr><td>(?&gt; re)</td><td>匹配的独立模式，省去回溯。</td></tr>
   <tr><td>\w</td><td> 匹配数字字母下划线</td></tr>
   <tr><td>\W</td><td>匹配非数字字母下划线</td></tr>
   <tr><td>\s</td><td> 匹配任意空白字符，等价于 [\t\n\r\f]。</td></tr>
   <tr><td>\S</td><td>匹配任意非空字符</td></tr>
   <tr><td>\d</td><td> 匹配任意数字，等价于 [0-9]。</td></tr>
   <tr><td>\D</td><td>匹配任意非数字</td></tr>
   <tr><td>\A</td><td>匹配字符串开始</td></tr>
   <tr><td>\Z</td><td>匹配字符串结束，如果是存在换行，只匹配到换行前的结束字符串。</td></tr>
   <tr><td>\z</td><td>匹配字符串结束</td></tr>
   <tr><td>\G</td><td>匹配最后匹配完成的位置。</td></tr>
   <tr><td>\b</td><td>匹配一个单词边界，也就是指单词和空格间的位置。例如， 'er\b' 可以匹配"never" 中的 'er'，但不能匹配 "verb" 中的 'er'。</td></tr>
   <tr><td>\B</td><td>匹配非单词边界。'er\B' 能匹配 "verb" 中的 'er'，但不能匹配 "never" 中的 'er'。</td></tr>
   <tr><td>\n, \t, 等。</td><td>匹配一个换行符。匹配一个制表符, 等</td></tr>
   <tr><td>\1...\9</td><td>匹配第n个分组的内容。</td></tr>
   <tr><td>\10</td><td>匹配第n个分组的内容，如果它经匹配。否则指的是八进制字符码的表达式。</td></tr>
</tbody></table>

### 正则表达式实例

<h4>字符匹配</h4>
<table>
<tbody>
   <tr><th>实例</th><th>描述</th></tr>
   <tr><td>python</td><td>匹配 "python". </td></tr>
</tbody></table>
<h4>字符类</h4>
<table>
<tbody>
   <tr><th>实例</th><th>描述</th></tr>
   <tr><td>[Pp]ython </td><td>匹配 "Python" 或 "python"</td></tr>
   <tr><td>rub[ye]</td><td>匹配 "ruby" 或 "rube"</td></tr>
   <tr><td>[aeiou]</td><td>匹配中括号内的任意一个字母</td></tr>
   <tr><td>[0-9]</td><td>匹配任何数字。类似于 [0123456789]</td></tr>
   <tr><td>[a-z]</td><td>匹配任何小写字母</td></tr>
   <tr><td>[A-Z]</td><td>匹配任何大写字母</td></tr>
   <tr><td>[a-zA-Z0-9]</td><td>匹配任何字母及数字</td></tr>
   <tr><td>[^aeiou]</td><td>除了aeiou字母以外的所有字符 </td></tr>
   <tr><td>[^0-9]</td><td>匹配除了数字外的字符
</td></tr>
</tbody></table>
<h4>特殊字符类</h4>
<table>
<tbody><tr><th>实例</th><th>描述</th></tr>
   <tr><td>.</td><td>匹配除 "\n" 之外的任何单个字符。要匹配包括 '\n' 在内的任何字符，请使用象 '[.\n]' 的模式。</td></tr>
   <tr><td>\d</td><td>匹配一个数字字符。等价于 [0-9]。</td></tr>
   <tr><td>\D </td><td>匹配一个非数字字符。等价于 [^0-9]。</td></tr>
   <tr><td>\s</td><td>匹配任何空白字符，包括空格、制表符、换页符等等。等价于 [ \f\n\r\t\v]。</td></tr>
   <tr><td>\S </td><td>匹配任何非空白字符。等价于 [^ \f\n\r\t\v]。</td></tr>
   <tr><td>\w</td><td>匹配包括下划线的任何单词字符。等价于'[A-Za-z0-9_]'。</td></tr>
   <tr><td>\W</td><td>匹配任何非单词字符。等价于 '[^A-Za-z0-9_]'。</td></tr>
</tbody></table>
