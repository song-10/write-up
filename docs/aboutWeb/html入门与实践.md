# HTML5

## WEB标准

1. 优点：
    - 让WEB的发展前景更广阔；
    - 内容能被更广泛的设备访问；
    - 更容易被搜索引擎搜索；
    - 降低网站流量费用；
    - 使网站更容易维护；
    - 提高页面浏览速度。
2. Web标准构成：web标准不是某一个标准，而是由W3C和其他标准化组织指定的一系列标准的集合。主要包括结构（Structure）、表现（Presentation）和行为（Behavior）
    - ==结构标准== ：用于对网页元素进行整理和分类，主要包括XML和XHTML两个部分（*.html)；使内容更清晰，更有逻辑性；
    - ==样式标准== ：表现用于设置网页元素的版式、颜色、大小等外观样式，主要指的是css(*.css)；用于修饰内容的样式；
    - ==行为标准== ： 行为是指网页模型的定义及交互的编写，主要包括DOM和ECAScript两个部分(*.js);内容的交互及操作效果。

## HTML入门

1. HTML初识：
HTML（Hyper Text Markup Language），超文本标签语言，主要使通过HTML标签对网页中的文本、图片、声音等内容进行描述。
2. HTML骨架：

    ```html
    <html>
        <head>
            <title><title/>
        </head>
        <body>
        </body>
    </html>
    ```

    - html标签： 作用所有html中标签的一个根节点；
    - head标签：用于存放：title、meta、base、style、script、link。注意在head标签中必须要设置的标签是title；
    - body标签：页面的主体部分，用于存放所有的html标签：p、h、a、b、u、i、s、em、del、ins、strong、img

3. HTML标签分类

    在HTML页面中，带有“<>”符号的元素被称为标签，如`<html>`、`<head>`、`<body>`等。在“<>”标签符中表示某个功能的编码命令，也称==HTML标签==或==HTML元素==

    - 双标签
    <标签名>内容</标签名>
    - 该语法中“<标签名>”表示该标签作用开始，一般称为“开始标签（start tag），“</标签名>”表示该标签作用结束，一般称为结束标签（end tag），和开始标签相比，结束标签只是在前面加了一个关闭符“/”

    ```html
    <body>内容</body>
    ```

    - 单标签
    <标签名 />
    单标签也称空标签，是指用一个标签符号即可完整地描述某个功能地标签

    ```html
    <br />
    ```

4. 标签嵌套和并列关系

    - 嵌套关系(作用不同级，head和title就是父子关系（嵌套）)

    ```html
    <head>
        <title></title>
    <head>
    ```

    - 并列关系(作用同级，head和body就是兄弟关系（并行)）

    ```html
    <head>
        <title></title>
    </head>
    <body>
    </body>
    ```

5. 在Sublime中生成html骨架：

    两种方式,输入结束后tab键(输入时需切换至英文输入法)

    ```html
    html:5
    !
    ```

6. 文档类型`<!DOCTYPE>`

    ```html
    <!DOCTYPE html>
    <!--表示使用的是html5的版本-->
    ```

    <!DOCTYPE>标签位于文档的最前面，用于向浏览器说明当前文档使用哪种HTML或XHTML标准规范，必须在开头处使用<!DOCTYPE>标签为所有的XHTML文档指定XHTML版本和类型，只有这样浏览器才能按指定的文档类型进行解析。

7. 字符集简介

    ```html
    <meta cahrset="UTF-8">
    ```

    - utf-8是目前最常用的字符集编码方式，常用的字符集编码方式还有gbk和gb2312；
    - gb2312：简体中文，包括6763个汉字；
    - BIG5：繁体中文港澳台等用；
    - GBK：包含全部中文字符，是GB2312的扩展，加入对繁体字的支持，兼容GB2312
    - UTF-8：包含全世界所有国家需要用到的字符。

8. HTML标签的语义化（所谓语义化就是指标签的含义）

    - 方便代码的阅读和维护；
    - 同时让浏览器或是网络爬虫可以很好地解析，从而更好分析其中的内容；
    - 使用语义化标签具有更好的搜索引擎优化；
    - 核心：合适的地方给一个最为合理的标签；
    - 语义是否良好：去掉css之后，网页结构依然组织有序，并且有良好的可读性；
    - 遵循的原则： 先确定语义的HTML，再选合适的css。

9. HTML标签

- 排版标签
  - 标题标签
     单词缩写： head 头部、标题
     HTML提供6个等级的标题，即
  
   ```html
     <h1>,<h2>,<h3>,<h4>,<h5>,<h6>
     <!DOCTYPE html>
     <html>
         <head>
            <meta charset="UTF-8">
            <title>标题标签</title>
        </head>
        <body>
            <h1>一级标题</h1>
            <h2>二级标题</h2>
            <h3>三级标题</h3>
            <h4>四级标题</h4>
            <h5>五级标题</h5>
            <h6>六级标题</h6>
        </body>
    </html>
    <!-->一级标题一般给logo使用</!-->
    <!--注释-->
  ```

  - 段落标签
    单词缩写：paragraph 段落
    在网页中把文字有条理的显示出来
  - 水平标签
    单词缩写：horizontal 横线
    在网页中常常看到一些`水平线`将段落与段落之间隔开，使得文档结构清晰，层次分明。这些水平线可以通过插入图片实现，也可以简单的通过标记来完成

    ```html
    <!DOCTYPE html>
    <html>
        <head>
            <meta charset="UTF-8">
            <title>段落标签&&水平标签</title>
        </head>
        <body>
            <h2>《面朝大海，春暖花开》</h2>
            <hr />
            <!--<hr />是单标记，可创建网页水平横线--->
            <p>从明天起，做一个幸福的人</p>
            <p>  喂马、劈柴，周游世界</p>
            <p>  从明天起，关心粮食和蔬菜</p>
            <p>  我有一所房子，面朝大海，春暖花开</p>
            <p>  从明天起，和每一个亲人通信</p>
            <p>  告诉他们我的幸福</p>
            <p>  那幸福的闪电告诉我的</p>
            <p>  我将告诉每一个人</p>
            <p>  给每一条河每一座山取一个温暖的名字</p>
            <p>  陌生人，我也为你祝福</p>
            <p>  愿你有一个灿烂的前程</p>
            <p>  愿你有情人终成眷属</p>
            <p>  愿你在尘世获得幸福</p>
            <p>  我只愿面朝大海，春暖花开</p>
            <!--文本在一个段落中会根据浏览器窗口大小自动换行-->
        </body>
    </html>
    ```

  - 换行标签
    单词缩写： break 打断，换行
    在HTML中，一个段落中的文字会从左到右依次排列，直到浏览器窗口的右端，然后自动换行。如果希望文本强制换行，就需要使用换行标签
  - div span标签
    - div span 是没有语义的，是网页布局主要的2个盒子；
    - div 就是divsion的缩写，分区的意思，其实有很多div来组合网页；
    - span 跨度，跨距，范围

    ```html
    <!DOCTYPE html>
    <html>
        <head>
            <meta charset="UTF-8">
            <title>换行标签&&div span标签</title>
        </head>
        <body>
            <p>世界上最好的语言：</p>
            1. PHP<br /><!--<br />表示换行-->
            2. Python<br />
            3. C/C++<br />
            4. Java<br />
            <div>人生苦短，我用python</div>
            <span>测试语句</span>
        </body>
    </html>
    ```

  - 文本格式化标签
    标签    |显示效果
    --|---
    |`<b></b><strong></strong>`|文字以==粗体==方式显示（XHTML推荐使用strong）
    |`<i></i><em></em>`|文字以==斜体==方式显示（XHTML推荐使用em）
    |`<s></s><del></del>`|文字以==加删除线==方式显示（XHTML推荐使用del）
    |`<u></u><ins></ins>`|文字以==加下划线==方式显示（XHTML不赞成使用u）
    b、i、s、u只有使用没有强调的意思，strong、em、del、ins语义更强烈
  - 标签属性：即标签的特性
    使用HTML制作网页时，如果让HTML标签提供更多信息，可以使用HTML标签的属性加以设置。其基本语法如下：

    ```html
    <标签名 属性1="属性值" 属性2="属性值"……>内容</标签名>
    <!--上述语法中：-->
    <!-->
    1. 标签可以拥有多个属性，必须写在开始标签中，位于标签名后面；
    2. 属性之间可以不区分先后顺序，标签与属性、属性之间均以空格分开；
    3. 任何标签的属性都有默认值，省略该标签属性则取默认值。
    注：标签的属性采用键值对的格式，key="value"
    </-->
    <!-示例代码-->
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>标签属性</title>
    </head>
    <body>
    要求：<br />
        1. 分割线显示为红色；<br />
        2. 分割线长度为500.<br />
        3. 第一段现实为红色，字号为50<br />
        <h1 color="yellow">语法要求</h1>
        <hr width="500" color="red"/>
        <p ><font color="red" size="50">1. 标签可以拥有多个属性，必须写在开始标签中，位于标签名后面；</font></p>
        <!--font标签可以单独对莫一部分的内容进行单独的设置-->
        <p ">2. 属性之间可以不区分先后顺序，标签与属性、属性之间均以空格分开；</p>
        <p >3. 任何标签的属性都有默认值，省略该标签属性则取默认值。</p>
        <p >注：标签的属性采用键值对的格式，key="value"</p>
        </body>
    </html>
    ```

  - 图像标签img
    单词缩写： image 图像
    HTML网页中任何元素的实现都要依靠HTML标签，要想在网页中显示图像就需要使用图像标签`<img />`以及其他相关的属性。其基本语法格式如下：

    ```html
    <img src="图像URL" />
    ```

    > 该语法中src属性用于指定图像文件的路径和文件名，它是img标签的必须属性。
    >图片的格式：
    >1. JPEG(JPG)
    >   -JPEG支持的颜色较多，图片可以压缩(体积小），但不支持透明（背景）
    >   -一般使用JPEG的图片来保存照片等颜色丰富的图片
    >2. GIF
    >   -GIF支持的颜色少，支支持简单的透明（水平线和竖直线方向上），支持动态图
    >   -图片颜色单一或者是动态图可以使用
    >3. PNG
    >   -PNG支持的颜色多，并且支持复杂的透明
    >   -可以用来显示颜色复杂的透明的图片
    >图片的使用原则：
    >   -效果不一致，使用效果好的
    >   -效果一致使用小的

    `<img />`标签属性

    属性    |属性值    |描述
    --|---|---
    |src|URL|图像的路径
    |alt|文本|图像不能显示时的替换文字,搜索引擎可以通过alt来识别不同的图片
    |title|文本|鼠标悬停时显示的内容
    |width|像素（XHTML不支持%页面百分比）|设置图像的宽度
    |height|像素（XHTML不支持%页面百分比）|设置图像的高度
    |==border==|==数字==|==设置图像边框的宽==度
    - 链接标签
    单词缩写： anchor
    在HTML中创建链接，只需要用标签环绕需要 被链接的对象即可，其基本语法如下：

    ```html
    <a href="跳转目标" target="目标窗口的弹出方式">文本或图像</a>
    <!-->
    href:用于指定链接目标的url地址，当标签应用href属性时，它就具有了超链接的功能。
    Hypertext Reference的缩写。意思时超文本引用；
    target：用于指定链接页面的打开方式，其取值有self和blank两种，其中self为默认值，blank为在新窗口中打开。
    blank前加下划线_，的作用是不断打开一个新的网页，如果不加下划线，系统就会认为输入的是blank字符串，即target="self"还是会在新窗口打开页面
    注意：
    1. 外部链接需添加http://传输协议
    2. 内部链接直接链接内部页面名称即可，比如<a href="index.html">首页</a>
    3. 如果当时没有确定链接目标时，通常将链接标签的href属性值定义为“#”（即href=“#”）此时点击链接时会自动跳转到页面的顶部，表示该链接暂时为一个空链接
    4. 不仅可以创建文本超链接，在网页中各种元素，如图像、表格、音频、视频等都可以添加超链接
    5. href属性值设置为mailto:地址 时，点击链接以后会自动打开计算机中默认的邮件客户端并且收件人会设置为mailto后的地址
    </-->
      <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>链接标签</title>
    </head>
    <body>
        <a href="http://www.baidu.com">baidu</a>
        <a href="mailto:tempersong@gmail.com">联系作者</a>
        <!--发送电子邮件的超链接-->
    </body>
    </html>
    ```

  - 锚点定位
    通过创建锚点链接，用户能够快速定位到目标内容；

    ```html
      <!-->
      创建锚点链接分为两步：
      1. 使用<a href="#id_name"></a>创建文本，id可以对任何标签设置，且id作为标签的唯一标识，所以id属性在同一页面中不能重复
      2. 使用相应的id_name标注跳转目标的位置
      </-->
       <!DOCTYPE html>
        <html>
            <head>
                <meta charset="UTF-8">
                <title>锚点定位</title>
                <meta http-equiv="refresh" content="5;url=#second" /t>
                <!--上述语句表示5秒之后跳转到second部分-->
            </head>
            <body>
                <h2 id="start">《面朝大海，春暖花开》</h2>
                <a href="#first">第一遍</a><br />
                <a href="#second">第二遍</a><br />
                <hr />
                <!--<hr />是单标记，可创建网页水平横线--->
                <p id ="first">从明天起，做一个幸福的人</p>
                <p>  喂马、劈柴，周游世界</p>
                <p>  从明天起，关心粮食和蔬菜</p>
                <p>  我有一所房子，面朝大海，春暖花开</p>
                <p>  从明天起，和每一个亲人通信</p>
                <p>  告诉他们我的幸福</p>
                <p>  那幸福的闪电告诉我的</p>
                <p>  我将告诉每一个人</p>
                <p>  给每一条河每一座山取一个温暖的名字</p>
                <p>  陌生人，我也为你祝福</p>
                <p>  愿你有一个灿烂的前程</p>
                <p>  愿你有情人终成眷属</p>
                <p>  愿你在尘世获得幸福</p>
                <p>  我只愿面朝大海，春暖花开</p>
                <!--文本在一个段落中会根据浏览器窗口大小自动换行-->
                <a href="#start">回到开始</a>
                <p id="second">从明天起，做一个幸福的人</p>
                <p>  喂马、劈柴，周游世界</p>
                <p>  从明天起，关心粮食和蔬菜</p>
                <p>  我有一所房子，面朝大海，春暖花开</p>
                <p>  从明天起，和每一个亲人通信</p>
                <p>  告诉他们我的幸福</p>
                <p>  那幸福的闪电告诉我的</p>
                <p>  我将告诉每一个人</p>
                <p>  给每一条河每一座山取一个温暖的名字</p>
                <p>  陌生人，我也为你祝福</p>
                <p>  愿你有一个灿烂的前程</p>
                <p>  愿你有情人终成眷属</p>
                <p>  愿你在尘世获得幸福</p>
                <p>  我只愿面朝大海，春暖花开</p>
            </body>
        </html>
        ```
  
  - base标签:可以设置整体链接的打开状态

    ```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>base标签</title>
        <base target="_blank" />
    </head>
    <body>
        <a href="http://www.baidu.com">百度</a><br />
        <a href="http://www.sina.com" target="_self">新浪</a><br />
        <!--base标签起作用后，body中的所有链接都会以新建页面的方式打开，如果想要某个链接不打开新页面，
        那么只需要对这个链接单独设置-->
        <!--target的值可以使用内联框架的name属性值，这样点击超链接后，会在内联框架中打开-->
        <a href="http://www.google.com">谷歌</a><br />
        <a href="http://www.163.com">网易</a><br />
    </body>
    </html>
    ```

  - 特殊字符
    HTML为这些特殊字符准备了专门的替代代码
        特殊字符    |描述   |字符的代码
        --|--|--
        | |空格符|`&nbsp;`
        |<|小于号|`&lt;`
        |>|大于号|`&gt;`
        |&|和号|`&amp;`
        |￥|人民币|`&yen;`
        |&copy;|版权|`&copy;`
        |&reg;|注册商标|`&reg;`
        |&deg;|摄氏度|`&deg;`
        |&plusmn;|正负号|`&plusmn;`
        |&times;|乘号|`&times;`
        |&divide;|除号|`&divide;`
        |&sup2;|平方2（上标2）|`&sup2;`
        |&sup3;|立方3（上标3）|`&sup3;`

    ```html
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>特殊字符</title>
        </head>
        <body>
            -----&nbsp;&nbsp;&nbsp;&nbsp;测试文本&nbsp;&nbsp;&nbsp;&nbsp;----
            <!--测试文前后各四个空格-->
        </body>
        </html>
    ```

  - 注释标签

    ```html
    1. <!--注释内容-->
    2. <!-->注释内容</-->
    ```

  - 相对路径
    - 图像文件和HTML文件位于同一文件夹，只需输入文件的名称即可，如`<img src="logo.gif" />`;
    - 图像文件位于HTML文件的下一级文件夹，输入文件夹和文件名，之间用“/”隔开，如`<img src="img/img01/logo.gif" />`；
    - 图像文件位于HTML文件的上一级文件夹，在文件名之前加上“../”，如果是上两级，则需使用“../../”,依次类推，如`<../../../logo.gif />`.
  - 绝对路径
    完整的地址，如"D:web\img\logo.gif"或`"https://upload-images.jianshu.io/upload_images/2551993-296a9795ceb494e9.png?imageMogr2/auto-orient/"`
  - 无序列表

    ```html
    <!-->
    无序列表的各个列表项之间没有顺序之分，是并列的，其基本语法格式如下
    </-->
    <ul>
        <li>列表项1</li>
        <li>列表项2</li>
        <li>列表项3</li>
        <li>列表项4</li>
        <li>列表项5</li>
        ......
    </ul>
    ```

    > 无序列表注意事项:
    >1. `<ul></ul>`中只嵌套`<li></li>`,直接在`<ul></ul>`标签中输入其他标签或者文字的做法是不允许的
    >2. `<li></li>`之间相当于一个容器，可以容纳任何元素
    >3. 无序列表会带有自己的样式属性，可通过css来处理

  - 有序列表

    ```html
    <!-->
    有序列表的各个列表项之间有先后顺序之分
    </-->
        <ol>
            <li>列表项1</li>
            <li>列表项2</li>
            <li>列表项3</li>
            <li>列表项4</li>
            <li>列表项5</li>
            ......
        </ol>
    ```

    >注：有序列表的注意事项与无序列表一致
  - 自定义列表

    ```html
    <!-->
    自定义列表常用于对术语或名词进行解释和描述，定义列表的列表项前没有任何项目符号，其基本语法如下：
    </-->
    <dl>
        <dd>名词1</dd>
        <dt>名词1解释1</dt>
        <dt>名词1解释2</dt>
        <dt>名词1解释3</dt>
        <dt>名词1解释4</dt>
        ......
        <dd>名词2</dd>
        <dt>名词2解释1</dt>
        <dt>名词2解释2</dt>
        <dt>名词2解释3</dt>
        <dt>名词2解释4</dt>
        ......
    </dl>
    ```

  - meta标签

    ```html
    <meta charset="UTF-8" />
    <!--指定字符集编码-->
    <!-->
    使用meta标签还可以来设置网页的关键字,关键字可以是多个，也可以是一个，关键字的内容由属性content决定
    </-->
    <meta name="keywords" content="HTML5,JavaScript,Java,Python" />
    <!--
        还可以用来指定网页的描述
    -->
    <meta name="description" content="人生苦短，我用Pyhton" />
    <!--
        描述和关键字浏览器并不会解析出来，而是由搜索引擎在检索页面时，同时检索页面中的关键词和描述，但时关键词和描述不会影响页面在搜索引擎中的排名
    -->
    <!--重定向，即跳转到其他地址
    <meta http-equiv="refresh" content="秒数;url=目标路径" />
    其中，refresh表示刷新网页
    -->
    <meta http-equiv="refresh" content="5;url=http://www.baidu.com">
    <!--上述语表示五秒后跳转到百度首页-->
    ```

  - xhtml语法规范

    ```html
    <!--
        1.HTML中不区分大小写，但一般使用小写
        2.HTML中的注释不能嵌套
        3.HTML标签结构必须完整，要么成对出现（双标签），要么自结束标签（单标签）
        注：浏览器会尽最大的努力正确解析页面，所有的不符合语法规范的内容，浏览器都会自动修正，但有些情况会出现修正错误
        4.HTML标签可以嵌套，但是hi不能交叉嵌套
        5.HTML标签中的属性必须有值，且值必须加引号（单引号双引号都可以）
    -->
    ```

  - 内联框架
    >使用内联框架可以引入一个外部页面，使用iframe创建一个内联框架
    >属性：
    >   1. src:指向一个外部页面的路径，可以使用相对路径
    >   2. width,height
    >   3. name可以为内联框架指定一个name属性
    >注意：在现实开发中不推荐使用内联框架，因为内联框架中的内容不会被搜索引擎所检索

    ```html
            <!DOCTYPE html>
            <html>
                <head>
                    <meta charset="UTF-8">
                    <title>内联框架</title>
                    <meta name="keywords" content="内联框架" /t>
                </head>
                <body>
                    <center>
                    <h2>《面朝大海，春暖花开》</h2>
                    <hr />
                    <!--<hr />是单标记，可创建网页水平横线--->
                    <p>从明天起，做一个幸福的人</p>
                    <p>  喂马、劈柴，周游世界</p>
                    <p>  从明天起，关心粮食和蔬菜</p>
                    <p>  我有一所房子，面朝大海，春暖花开</p>
                    <p>  从明天起，和每一个亲人通信</p>
                    <p>  告诉他们我的幸福</p>
                    <p>  那幸福的闪电告诉我的</p>
                    <p>  我将告诉每一个人</p>
                    <p>  给每一条河每一座山取一个温暖的名字</p>
                    <p>  陌生人，我也为你祝福</p>
                    <p>  愿你有一个灿烂的前程</p>
                    <p>  愿你有情人终成眷属</p>
                    <p>  愿你在尘世获得幸福</p>
                    <p>  我只愿面朝大海，春暖花开</p>
                    <a href="http://www.hao123.com" target="百度一下，你就知道">hao123</a><br />
                    <!--设置超链接的target属性值为内联框架的name属性值，可以让点击超链后在内联框架中打开-->
                    <iframe src="http://www.baidu.com" name="百度一下，你就知道" width="2000" height="1000"></iframe>
                    </center>
                    <!--center标签可以让内容居中，但不推荐使用-->
                </body>
            </html>
    ```

  - 一个简单的登录页面

    ```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>登录界面</title>
    </head>
    <body>
        <form action="http://wwww.baidu.com" method="post">
        <!--form标签构建表单，向服务器传送数据-->
            <table border="1" cellpadding="0" cellspacing="0">
            <!--table标签构建表格-->
                <tr>
                    <td>UserName</td>
                    <td><input type="UserName" name="txtName"></td>
                    <!--tr标签标识行，td标签表示列，先行后列-->
                </tr>
                <tr>
                    <td>PassWord</td>
                    <td><input type="PassWord" name="textPwd"></td>
                </tr>
                <tr>
                    <td>验证码</td>
                    <td><input type="text" name="txtJudge"></td>
                </tr>
                <tr>
                    <td colspan="2"><center><input type="checkbox" name="txtRem">记住密码</center></td>
                    <!--colspan合并列,rowspan合并行,center标签让内容居中-->
                </tr>
                <tr>
                    <td colspan="2"><center><input type="submit" value="submit"><input type="reset" value="reset"></center></td>
                </tr>
            </table>
        </form>
    </body>
    </html>
    ```
