# 前端开发css基础

## 写入CSS的三种方式

1. css（Cascading Style Sheet）层叠样式表，它可以让网页制作者有效的定制、改善网页的效果
2. 写入css的三种方式
    - 内联样式表（在标签内设置元素的样式）
    >内联样式表具有灵活的特点，但不适宜对标签的批量操作

    ```html
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>内联样式表</title>
        </head>
        <body>
            <p style="background:red;font-size:xx-large">内联样式表可以单独对某个标签进行样式设置，三种方式中优先级最高</p>
            <!--内联样式表使用style属性引入，内置的属性如background等之间用分号隔开-->
        </body>
    </html>
    ```

    - 嵌入样式表（需要在head标签中写入`<style type="text/css"></type>`)

    ```html
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>内联样式表</title>
            <style type="text/css">
            p{
                background-color:yellow;
                font-size:xx-small;
            }
            </style>
        </head>
        <body>
            <p style="background:red;font-size:xx-large">内联样式表可以单独对某个标签进行样式设置，三种方式中优先级最高</p>
            <!--内联样式表使用style属性引入，内置的属性如background等之间用分号隔开-->
            <p>嵌入样式表可以对某一类标签进行批量设置，三种方式中优先级居中</p>
        </body>
    </html>
    ```

    - 外部样式表（在文件外部编写css代码，然后再html文件内引用，引用时需在head标签中添加`<link href="css代码地址" rel="stylesheet" type="text/css" />`

    ```html
    <!--html部分-->
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>内联样式表</title>
            <link href="demo_css1.css" rel="stylesheet" type="text/css" />
            <style type="text/css">
            p{
                background-color:yellow;
                font-size:xx-small;
            }
            </style>
        </head>
        <body>
            <p style="background:red;font-size:xx-large">内联样式表可以单独对某个标签进行样式设置，三种方式中优先级最高</p>
            <!--内联样式表使用style属性引入，内置的属性如background等之间用分号隔开-->
            <p>嵌入样式表可以对某一类标签进行批量设置，三种方式中优先级居中</p>
            <tt>外部样式表可以在head标签内声明之后，引用外部css文件，此种方法优先级最低</tt>
        </body>
    </html>
    ```

    ```css
    /*css部分,css文件和html文件在同一文件夹下，这里使用的是相对路径*/
    tt{
        background-color:green;
    }
    p{
                background-color:green;
                font-size:xx-large;
            }
    ```

## CSS中的选择器

样式规则的选择器（通过怎样的途径来获得页面上要设置样式的元素）

1. HTML Selector：获取某一标签，对该类标签做整体样式设置

    ```html
    <!DOCTYPE html>
    <!--采用嵌入样式表的方式实现HTML Slector-->
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>HTML Selector</title>
            <style type="text/css">
            p{
                background-color:yellow;
                font-size:xx-small;
            }
            </style>
        </head>
        <body>
            <p>HTML Selector 可以对同类的所有标签进行样式设置</p>
            <p>测试文本</p>
            <p>测试文本</p>
            <p>测试文本</p>
            <p>测试文本</p>
            <p>测试文本</p>
        </body>
    </html>
    ```

2. class selector(需要给设置样式的标签的class属性赋值)

    class selector可以实现对多个同类标签的样式设置，只需将class的属性值设置为一样即可

    ```html
    <!DOCTYPE html>
    <!--采用嵌入样式表的方式实现Class Slector-->
    <!--Class Selector的用法有两种，一是"标签名.class名" ；另一种是 ".class名"-->
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Class Selector</title>
            <style type="text/css">
            p.class1{
                background-color:yellow;
                font-size:xx-small;
            }
            .class2{
                background-color:green;
                font-size:xx-large;
            }
            </style>
        </head>
        <body>
            <p>Class Selector 可以对同类的标签进行样式设置</p>
            <p class="class1">测试文本</p>
            <p class="class1">测试文本</p>
            <p>测试文本</p>
            <p class="class2">测试文本</p>
            <p class="class2">测试文本</p>
        </body>
    </html>
    ```

3. ID Selector(需要给设置样式的标签的ID属性赋值)

    ID属性应是唯一的，即每个标签的ID都互不相同，通过ID Selector可以对单个标签设置相应的样式，作用类似于内联样式表,此外，ID Selcetor优先级高于class

    ```html
    <!--采用嵌入样式表的方式实现 ID Selector-->
    <!--ID Selector 的用法为“ #ID名”-->
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>ID Selector</title>
            <style type="text/css">
            p.class1{
                background-color:yellow;
                font-size:xx-small;
            }
            .class2{
                background-color:green;
                font-size:xx-large;
            }
            #p1{
                background-color:red;
                font-size:xx-small;
            }
            #p2{
                background-color:pink;
                font-size:xx-large;
            }
            </style>
        </head>
        <body>
            <p id="p1">ID Selector 可以对单个标签进行样式设置</p>
            <p class="class1">测试文本</p>
            <p class="class1">测试文本</p>
            <p id="p2">测试文本</p>
            <p class="class2">测试文本</p>
            <p class="class2">测试文本</p>
        </body>
    </html>
    ```

4. 关联选择器
    `标签名1 标签名2`
    适用于嵌套使用的标签中的样式设置

    ```html
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Selector</title>
            <style type="text/css">
            p tt{
                background: red;
                font-size: small;
            }
            </style>
        </head>
        <body>
        <p><tt>关联选择器测试文本</tt></p>
        <p>测试文本</p>
        <p>测试文本</p>
        <tt>测试文本</tt>
        <tt>测试文本</tt>
        </body>
    </html>
    ```

5. 组合选择器
    对多个不同标签设置同一种样式
    ~标签1，标签2，标签3，……，标签n~

    ```html
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Selector</title>
            <style type="text/css">
            h1,h2,h3,h4,table,p,tt{
                background: red;
            }
            </style>
        </head>
        <body>
        <h1>测试标题</h1>
        <h2>测试标题</h2>
        <h3>测试标题</h3>
        <h4>测试标题</h4>
        <table>
            <tr>
                <td>测试表格</td>
                <td>测试表格</td>
                <td>测试表格</td>
                <td>测试表格</td>
            </tr>
            <tr>
                <td>测试表格</td>
                <td>测试表格</td>
                <td>测试表格</td>
                <td>测试表格</td>
            </tr>
            <tr>
                <td>测试表格</td>
                <td>测试表格</td>
                <td>测试表格</td>
                <td>测试表格</td>
            </tr>
        </table>
        <p>测试文本</p>
        <tt>测试文本</tt>
        </body>
    </html>
    ```

6. 伪元素选择器
    伪元素选择器是指对同一个HTML元素的各种状态和其所包括的部分内容的一种定义方式。如对超链接标签、段落标签的状态等都可以用伪元素选择器来定义
    `常用的伪元素选择器`
        使用方法    |使用效果
        --|---
        A:active|选中超链接时的状态
        A:hover|光标移动到超链接上的状态
        A:link|超链接的正常状态
        A:visited|访问过的超链接状态
        P:first-line|段落中的第一行文本
        P:first-letter|段落中的第一个字母

    ```html
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Selector</title>
            <style type="text/css">
                A:active{
                    text-decoration: none;
                }
                A:hover{
                    font-size: xx-large;
                }
                P:first-letter{
                    font-size: xx-small;
                }
                P:first-line{
                    font-size: xx-large;
                    background: red;
                }
            </style>
        </head>
        <body>
        <a href="#">超链接测试</a><br />
        <a href="#">超链接测试</a><br />
        <a href="#">超链接测试</a><br />
        <a href="#">超链接测试</a><br />
        <p>
            段落测试1<br />
            段落测试2<br />
            段落测试3<br />
            段落测试4<br />
        </p>
        </body>
    </html>
    ```

## CSS中的属性

CSS属性很多，大致分为以下几类：
`字体`、`背景`、`文本`、`位置`、`布局`、`边缘`、`列表`。

1. 字体

    >字体的属性主要包括文字的字体、大小、颜色、显示效果等基本样式

    字体属性    |属性作用   |属性值
    --|---|---
    font-family|设置字体系列
    font-size|定义文字的大小可以使用度量单位来设置，也可以使用一个相对的字体大小，还可以是使用绝对的大小标记符；|绝对大小的设置为：xx-small、x-small、small、medium、large、x-large、xx-large，其中xx-small最小，xx-large最大
    font-style|设置字体样式|Normal、Italic或Oblique（斜体）
    text-decoration|设置文本中条件下划线、上划线、中划线、闪烁效果
    font-weight|设置粗体字的磅值|normal、bold、bolder、lighter、100~900

2. 背景

    >背景包括背景颜色、背景图像以及背景图像的控制

    背景属性    |属性作用   |属性值
    --|---|---
    background-color|设置背景色|transparent表示透明的背景色
    background-image|设置元素的背景图像
    backgr-repeat|确定背景图像是否以及如何重复|no-repeat表示背景图像只在元素的显示区域中出现一遍，repeat表示在水平和垂直方向上重复，repeat-x和repeat-y分别表示水平或垂直方向上的重复
    background-attachment|确定背景图像是否跟随内容移动|fixed表示固定背景图像，scroll表示图像跟随内容的移动而移动
    background-position|指定背景图像的水平位置和垂直位置|水平位置可以是left、center、right也可以时数值；垂直位置可以是top、center、bottom也可以是数值

    ```html
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>backgroud</title>
            <style type="text/css">
                div{
                    height: 300px;
                    width: 300px;
                }
                .div1{
                    background-color: red;
                    top:100px;
                    left: 100px;
                }
                .div2{
                    background-color: green;
                    top:130px;
                    left: 130px;
                }
                .div3{
                    background-color: yellow;
                    top:160px;
                    left: 160px;
                }
                /*更改文件流，默认情况下，div标签会占据一整行*/
                .div4{
                    background-color: red;
                    top:100px;
                    left: 100px;
                    position: absolute;/*绝对定位，不会随内容的移动而移动*/
                    z-index: 3
                }
                .div5{
                    background-color: green;
                    top:130px;
                    left: 130px;
                    position: absolute;/*绝对定位*/
                    z-index: 2
                }
                .div6{
                    background-color: yellow;
                    top:160px;
                    left: 160px;
                    position: absolute;/*绝对定位*/
                    z-index: 1/*z-index值最高的会显示在最外面*/
                }
            </style>
        </head>
        <body>
        <div class="div1"></div>
        <div class="div2"></div>
        <div class="div3"></div>
        <div class="div4"></div>
        <div class="div5"></div>
        <div class="div6"></div>
        </p>
        </body>
    </html>
    ```

3. 文本
    >文本的属性包括：文字间距、对齐方式、上标、下标、排列方式、首行缩进

    文本属性  |属性作用   |属性值
    --|---|---
    word-spacing|设置英文单词之间的间距|值具体数值
    letter-spacing|设置字符之间的间距|值为具体数值
    text-align|设置文本的水平对齐方式|left、right、center、justfy
    text-indent|设置第一行文本的缩进值|值为具体数值
    line-height|设置文本所在行的行高|值为具体数值

4. 位置
    - 标准盒子模型
    ![Alt](https://timgsa.baidu.com/timg?image&quality=80&size=b9999_10000&sec=1563099763278&di=0760b3bda1ada2622c2177eca739ad48&imgtype=0&src=http%3A%2F%2Fimage.mamicode.com%2Finfo%2F201712%2F20171229222533760353.png)
    >1. 蓝色部分可看作一个盒子，一个盒子就是一个div
    >2. 盒子与盒子(div与div，同一层次），盒子与网页边缘之间的距离用margin表示
    >3. div与其中的内容间距用padding表示
    >4. boder即盒子的边框
    >5. 布局时一般都先将整体结构搭好，然后再逐步往里面放入内容
    - 盒子模型的内容包括：content、padding、border、margin，F分为标准盒（正常盒模型、怪异盒模型）和伸缩盒（新、旧）
        - 内边距：padding
        内边距在content外，边框内
            属性    |描述
            --|---
            padding|设置所有边距
            padding-bottom|设置底边距
            padding-left|设置左边距
            padding-right|设置右边距
            padding-top|设置上边距
        - 边框：border
            属性    |描述
            --|---
            border-width|边框宽度
            border-style|边框样式
            border-color|边框颜色
            border-radius|设置圆角边框
            border-shadow|设置对象阴影
            border-image|边框背景图片
        - 外边距：margin
            - 围绕在内容边框（上一级标签，最外层为body标签）的区域就是外边距，外边距默认为透明区域；
            - 外边距接收任何长度单位、百分数值。
                属性    |描述
                --|---
                margin|设置所有边距
                margin-bottom|设置底边距
                margin-left|设置左边距
                margin-right|设置右边距
                margin-top|设置上边距
                >在设置内边距时，会自动撑开外盒子

                ```html
                <!DOCTYPE html>
                <html>
                <head>
                   <title>padding-margin</title>
                   <meta charset="utf-8" />
                   <style type="text/css">
                   .shoebox{
                    width:200px;
                    height:200px;
                    padding:20px;
                /*此处外盒子和内盒子大小一致，但外盒子设置内边距为20px后，会自动将外盒子撑大，不需要再手动对外盒子大小进行设置 */
                    background-color:aquamarine;
                   }
                   .shoe{
                    width:200px;
                    height:200px;
                    background-color:brown;
                   }
                   </style>
                </head>
                <body>
                   <div class="shoebox">
                       <div class="shoe"></div>
                   </div>
                </body>
                </html>
                ```

        - 外边距合并的问题：如果同级盒子一个都设置了外边距，则取数值大的外边距，并不会将两者设置的外边距进行叠加。

            ```html
            <!DOCTYPE html>
            <html>
            <head>
                <title>padding-margin</title>
                <meta charset="utf-8" />
                <style type="text/css">
                .div1{
                width:200px;
                height:200px;
                margin-bottom:20px;
                /*此处将下边距设置为20px*/
                background-color:aquamarine;
                }
                .div2{
                width:200px;
                height:200px;
                margin-top:30px;
                /*此处将上边距设置为30px，30大于20，所以div2和div1之间的边距为30*/
                background-color:brown;
                }
                </style>
            </head>
            <body>
                <div class="div1"></div>
                <div class="shoe"></div>
            </body>
            </html>
            ```

    - 怪异盒子
        `box-sizing:border-box`设置该属性及属性值之后，盒子的大小会固定在widt和height设置的值上，不会改变，无论添加内边距还是边框，整个盒子的大小都不会变，即里面的内容不会超出盒子的大小，且div是从左上角开始渲染的。

        ```html
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>简单布局</title>
                <style type="text/css">
                /* *号表示获得所有文档，对所有内容设置样式*/
                *{
                    margin: 0px;
                    /*margin共四个参数，依次控制的间距是上、右、下、左（顺时针）
                    三个参数的情况，第一个和第三个参数表示上下边距，中间第二个参数表示左右边距
                    两个参数的情况，第一个表示上下边距，第二个表示左右边距
                    一个参数表示上下左右的边距
                padding属性的参数情况与margin一致
                    */
                }
                .div_index{
                    width: 1600px;
                    height: 950px;
                    background-color: white;
                    margin: 0px auto;
                    /*margin控制盒子与页面之间的边距，两个参数，作用为上下边距设置为0px，左右边距自动调整，即居中*/
                }
                .div_logo{
                    width: 1600px;
                    height: 100px;
                    background-color: blue;
                }
                .div_logo img{
                    width: 160px;
                    height: 100px;
                }
                .div_input{
                    background-color: white;
                    width:1440px;
                    height: 100px;
                    float: right;
                }
                .div_input p{
                    float: right;
                }
                #header1,#header2{
                    font-family: fantasy;
                    text-decoration: line-through;
                    font-weight: lighter,border;
                    text-align: center;
                }
                .div_content{
                    width: 1600px;
                    height: 700px;
                    background-color: green;
                }
                .div_link{
                    width: 300px;
                    height: 700px;
                    float: left;
                    background-color: white;
                }
                .div_window{
                    background-color: white;
                    width:1300px;
                    height: 700px;
                    float: left;
                }
                .p{
                text-align:center;  
                }
                </style>
            </head>
            <body>
                <div class="div_index">
                    <div class="div_logo">
                        <img src="https://timgsa.baidu.com/timg?image&quality=80&size=b9999_10000&sec=1563104937035&di=f64160f2368911806f6a63745819f67e&imgtype=0&src=http%3A%2F%2Fimages.cpooo.com%2Ffiles%2F201111%2Fproduct%2F387%2F344428_1321489660.jpg" />
                        <div class="div_input">
                            <p>
                                这里想放个<br />
                                <strong>天气预报</strong><br/>
                                但不会！！！
                            </p>
                            <h2 id="header1">感觉这儿应该有文字，但不知道写什么<br />就连左边的谷歌logo</h2>
                            <h3 id="header2" style="font-style: oblique;color: red;">都是生拉硬凑的</h3>
                        </div>
                    </div>
                    <div class="div_content">
                    <div class="div_link">
                        <table border="0px" cellspacing="7px" cellpadding="0px">
                            <tr>
                                <td><a href="http://www.sohu.com/" target="window">搜狐</a></td>
                                <td><a href="https://www.qq.com/" target="window">腾讯</a></td>
                                <td><a href="https://www.163.com/" target="window">网易</a></td>
                                <td><a href="http://www.people.com.cn/" target="window">人民网</a></td>
                                <td><a href="http://www.xinhuanet.com/" target="window">新华网</a></td>
                                <td><a href="http://www.cctv.com/" target="window">央视网</a></td>
                            </tr>
                        </table>
                        <img src="https://timgsa.baidu.com/timg?image&quality=80&size=b9999_10000&sec=1563106204360&di=7097e1c3b38e3d720ddf3be6bbf2a035&imgtype=0&src=http%3A%2F%2Fi5.hexunimg.cn%2F2011-11-04%2F134872814.jpg" style="width:300px;height: 200px; " title="不知道这张图片是干嘛用的" />
                        <p >
                            <br />
                            这里还是放几个文字吧，<br />
                            不然感觉怪怪的！！！<br />
                            <font color="red">蓝蓝的天空白云飘，白云下面小肥羊跑<br /></font>
                            <br />
                            <h2>《面朝大海，春暖花开》</h2>
                            <hr /><br />
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
                        </p>
                    </div>
                    <div class="div_window">
                        <iframe src="http://www.baidu.com" name="window" width="1300" height="700"></iframe>
                    </div>
                </div>
                <br/><hr/><br/>
                <div class="informaton">
                    <p class="p">
                        <a href="mailto:tempersong@gmail.com">联系作者</a>&nbsp;
                        <a href="http://www.baidu.com" target="_blank">百度</a>&nbsp;
                        <a href="#">关于我</a>
                    </p>
                    <p class="p">
                        &copy;2019&nbsp;
                        html_test&nbsp;
                        Created by Nop&reg;
                    </p>
                </div>
            </body>
        </html>
        ```

    - 导航栏

        ```html
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>导航栏实例</title>
                <style type="text/css">
                    *{
                        margin: 0px;
                    }
                    div{
                        background-color: blue;
                        height: 30px;
                        width: 800px;
                        margin: 0px auto;
                    }
                    ul li{
                        float: left;
                        list-style:none;/*去掉列表前的小原点*/
                        width: 100px;
                        line-height: 30px;
                    }
                    A:hover{
                        font-size: x-large;
                        background-color: #2262ce;
                    }
                </style>
            </head>
            <body>
                <div>
                    <ul>
                        <li><a href="#">公司简介</a></li>
                        <li><a href="#">企业文化</a></li>
                        <li><a href="#">产品介绍</a></li>
                        <li><a href="#">交易大厅</a></li>
                        <li><a href="#">联系我们</a></li>
                    </ul>
                </div>
            </body>
        </html>
        ```

    - 一个实例

        ```html
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>页面实例</title>
            <style type="text/css">
            *{
                margin: 0px;
                font-size: 12px;
            }
            div.divIndex{
                height: 380px;
                width: 290px;
                background-color:#F8F8F8 ;
                float: right;
            }
            div.div1{
                width:290px;
                height: 35px;
                background-color: blue;
                color: white;
                text-align: center;
            }
            div.div1 p{
                padding: 5px;
                font-size: 18px;
            }
            #table1{
                width:290px;
                border:1px;
            }
            .td1{
                font-weight: border;
            }
            .td2{
                color: #246db2;
                padding: 6px;
                border-bottom: 1px dashed #cccccc;
            }
            .td3
            {
                font-weight: border;
                color: red;
                border-bottom:1px dashed #cccccc;
                text-align:right;
            }
            .td4{
                font-weight: border;
                color: blue;
                border-bottom:1px dashed #cccccc;
                text-align:right;
            }
            </style>
        </head>
        <body>
            <div class="divIndex">
                <table id="table1" >
                    <tr>
                        <td><div class="div1"><p>.Net培训开班信息</p></div></td>
                    </tr>
                    <tr>
                        <td>
                            <table width="280px">
                                <tr>
                                    <td class="td1">.Net基础班</td>
                                    <td></td>
                                </tr>
                                <tr>
                                    <td class="td2">北京--2014年5月5号</td>
                                    <td class="td3">预约报名中</td>
                                </tr>
                                <tr>
                                    <td class="td2">北京--3月26号</td>
                                    <td class="td4">爆满已开班</td>
                                </tr>
                                <tr>
                                    <td class="td2">广州--2014年5月29号</td>
                                    <td class="td3">预约报名中</td>
                                </tr>
                                <tr>
                                    <td class="td2">广州--2014年4月12号</td>
                                    <td class="td4">爆满已开班</td>
                                </tr>
                                <tr>
                                    <td class="td1">.Net就业班</td>
                                    <td></td>
                                </tr>
                                <tr>
                                    <td class="td2">北京--2014年4月26号</td>
                                    <td class="td3">预约报名中</td>
                                </tr>
                                <tr>
                                    <td class="td2">北京--2014年3月24号</td>
                                    <td class="td4">爆满已开班</td>
                                </tr>
                                <tr>
                                    <td class="td2">广州--2014年5月13号</td>
                                    <td class="td3">预约报名中</td>
                                </tr>
                                <tr>
                                    <td class="td2">广州--2014年3月26号</td>
                                    <td class="td4">爆满已开班</td>
                                </tr>
                                <tr>
                                    <td class="td1">.Net远程班</td>
                                    <td></td>
                                </tr>
                                <tr>
                                    <td class="td2">北京--2014年5月6号</td>
                                    <td class="td3">基础班预约报名中</td>
                                </tr>
                                <tr>
                                    <td class="td2">北京--2014年4月26号</td>
                                    <td class="td3">就业班预约报名中</td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </div>
        </body>
        </html>
        ```

## 其他内容

1. 注释
    与c/c++中跨行注释一致。即`/*注释内容*/`,快捷键`ctrl+?`,html中注释也是该快捷键。
2. 导入样式表

    ```html
    <!-- html部分 -->
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>导入样式表</title>
        <style>
        @import "demo_css1.css";
        /*导入样式表*/
        </style>
    </head>
    <body>
        <div class="div1">
            <!-- None -->
        </div>
    </body>
    </html>
    ```

    ```css
    /* css部分 */
    .div1{
        width:100px;
        height: 100px;
        background-color: blue;
    }
    ```

3. 四种样式的优先级
    内联样式表>嵌入样式表>外部样式表>导入样式表

4. 元素分类
    - 块级元素
    (1) 常用的块级元素有：`<div>`,`<p>`,`<h1>...<h6>`,`<ol>`,`<ul>`,`<li>`,`<dl>`,`<dd>`,`<dt>`,`<table>`,`<tr>`,`<td>`,`<address>`,`<blockquote>`,`<form>`
    (2) 块级元素特点：
       - 每个块级元素都是从新的一行开始的，并且其后的元素也另起一行。
       - 元素的高度、宽度、行高以及顶和底边距都可设置
       - 元素宽度在不设置的情况下，是他本身容器的100%（和父元素的宽度一致），除非设置一个宽度
    (3) 设置`display:block`可以将元素显示为块级元素。如下代码就是将内联元素a转换为块状元素，从而使a元素具有块状元素的特点：(设置之后就会丢失原标签的特点，即独占一行)

    ```css
               a{display:block;}
    ```

    - 内联元素
    (1)常用的内联元素有：`<a>`,`<b>`,`<span>`,`<br>`,`<i>`,`<em>`,`<strong>`,`<label>`,`<q>`,`<cite>`,`<code>`
    (2)内联元素的特点：
          - 和其他元素都在一行上。
          - 元素的高度、宽度以及顶部和底部边距不可设置。
          - 元素的宽度就是它包含的文字或图片的宽度，不可改变。
    (3)内联元素也可以通过代码`display:inline`将元素设置为内联元素，如下代码就是将块状元素div转换为内联元素，从而使div元素具有内联元素的特点。（设置之后就会丢失原标签的特点，即不可更改宽高边距）

    ```css
               div{display:inline;}
    ```

    - 内联块级元素
    (1)常用的内联块级元素有：`<img>`,`<inout>`
    (2)内联元素的特点：
           - 和其他元素都在一行上。
           - 元素的高度、宽度、行高以及顶和底边距都可设置。
    (3)代码`display:inline-block`就是将元素设置为内联块级元素。

5. 定位

    - css定位：改变元素在页面上的位置；
    - css定位机制：普通流（元素按照其在HTML中的位置顺序决定排布的过程）、浮动、绝对布局；
    - css定位属性：
        属性    |描述
        --|---
        position|把元素放在一个静态的、相对的、绝对的或固定的位置中
        top|元素向上的偏移量
        left|元素向左的偏移量
        right|元素向右的偏移量
        bottom|元素向下的偏移量
        z-index|设置元素的堆叠顺序（默认值为0，数值小的在下方，数值可以为负数）
        - position属性：
            - static：对象遵循常规流，此时4个定位偏移量不会被应用；
            - relative：对象遵循常规流，并且参照自身在常规流中的位置通过top，right，bottom，left这4个定位偏移属性时不会影响常规流中的任何元素；
            - absolute：对象脱离常规流，此时偏移量参照的是里自身最近的定位祖先元素，如果没用定位的祖先元素，则一致回溯到body元素。盒子的偏移位置不影响常规流中的任何元素，其margin不与其他任何margin折叠；
            - fixed：与absolute一致，但偏移定位是以窗口为参考。当出现滚动条时，对象不会随着滚动。

        ```html
        <!-- position属性的absolute值与relative的配合使用 -->
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>positon</title>
            <style type="text/css">
                *{
                    padding:0;
                    margin:0;
                }
                .contanier{
                    width: 500px;
                    height: 500px;
                    background-color: red;
                    margin-top: 300px;
                    position: relative;
                    /*relative和absolute的配合使用，外层标签设置为relative时，内层标签设置边距时参考对象为外层标签*/
                }
                .in{
                    width: 100px;
                    height: 100px;
                    background-color: yellow;
                    position: absolute;
                    /*此处position的值应该为absolute*/
                    top:100px;
                }
            </style>
        </head>
        <body>
            <div class="contanier">
                <div class="in">内标签</div>
            </div>
        </body>
        </html>
        ```

6. 浮动

    - 浮动：（float）
        float属性的可用值：
        值  |描述
        --|---
        left|元素向左浮动
        right|元素向右浮动
        none|元素不浮动
        inherit|从父级继承浮动属性
    - clear属性：（去掉浮动属性（包括继承来的属性））
        clear属性值|    描述
        --|---
        left、right|去掉元素向左、右浮动
        both|左右两侧均去掉浮动
        inherit|从父级继承来的clear值

7. visibility&&overflow
    - visibility
        - 设置是否显示对象。与`display：none`不同，此属性为隐藏的对象保留其占据的物理空间
        - 如果希望对象为可视，其父对象也必须是可视的。
        - 属性值：
            - visible：设置对象可视
            - hidden：设置对象隐藏
    - overflow
        - 复合属性。设置对象处理溢出内容（内容大小超出容器大小）的方式。效果等同于overflow-x+overflow-y。
        - 如果希望对象为可视，其父对象也必须是可视的。
        - 属性值：
            - visible：对溢出内容不做处理，内容可能会超出容器（默认值）
            - hidden：隐藏溢出容器的内容，且不出现滚动条。
            - scroll：隐藏溢出容器的内容，溢出的内容将以卷动滚动条的方式呈现。
            - auto：当内容没有溢出容器时不出现滚动条，当内容溢出容器时出现滚动条，按需出现滚动条。此条为body对象和textarea的默认值。

8. css动画效果

    - 2D、3D转换
        - 通过2D、3D转换，可以对元素进行移动、缩放、转动、拉长或拉伸。转换时使元素改变形状、尺寸和位置的一种效果。
        - 2D（transform）转换方法：
            - translate（）：移动
            - rotate（）：旋转
            - scale（）：缩放
            - skew（）：倾斜
        - 3D转换方法：
            - rotateX（）
            - rotateY（）
    - 浏览器内核
        内核类型    |写法
        --|---
        webkit(Chrome/Safari)|-webkit-transform
        gecko(Firefox)|-moz-transform
        presto(Opera)|-o-transform
        trident(IE)|-ms-transform
    为了使不同浏览器都能正常渲染效果，需要在方法中添加浏览器内核

    ```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>动画效果</title>
        <style type="text/css">
        div{
            width: 100px;
            height: 100px;
            background-color: deepskyblue;
        }
        .change{
            transform: translate(100px);
            -webkit-transform:translate(100px,100px);
            -moz-transform:translate(100px,100px);
            -o-transform:translate(100px,100px);
            -ms-transform:translate(100px,100px);
            /*添加移动属性，两个参数，水平移动和垂直移动,只写入一个参数时，垂直方向上默认为0*/
            transform: rotate(30deg);
            -webkit-transform:rotate(30deg);
            -moz-transform:rotate(30deg);
            -o-transform:rotate(30deg);
            -ms-transform:rotate(30deg);
            /*添加旋转属性，参数为旋度数*/
            transform: scale(2,3);
            -webkit-transform:scale(2,3);
            -moz-transform:scale(2,3);
            -o-transform:scale(2,3);
            -ms-transform:scale(2,3);
            /*添加缩放属性，两个参数分别为水平和垂直方向上缩放的倍数*/
            transform: skew(20deg);
            -webkit-transform:skew(20deg);
            -moz-transform:skew(20deg);
            -o-transform:skew(20deg);
            -ms-transform:skew(20deg);
            /*添加倾斜属性，两个参数分别为水平和垂直方向上的倾斜度，参数为读数，一个参数时垂直方向上为0*/
        }
        </style>
    </head>
    <body>
        <div>初始效果（对比）</div>
        <br />
        <div class="change">变化后的效果</div>
    </body>
    </html>
    ```

    - 过渡
    - 通过css3，可以在不使用flash动画或js的情况下，当元素从一种样式变化为另一种样式时为元素设置过渡效果
        - css3过渡是元素从一种样式逐渐改变为另一种的效果。
            属性    |描述
            --|---
            transition|简写属性，用于在一个属性中设置四个过渡属性。
            transition-property|规定应用过渡的css属性名称
            transition-duration|定义过渡效果花费的时间，莫默认为0
            transition-timing-function|规定过渡效果的时间曲线，默认值是0
            transition-delay|规定过渡时间何时开始，默认是0（延迟）
        - transition-timing-function的取值：
        - linear：线性过渡，等同于贝塞尔曲线（0.0，0.0，1.0，1.0）
        - ease：平滑过渡，等同于贝塞尔曲线（0.25，0.1，0.25，1.0）
        - ease-in：由慢到快，等同于贝塞尔曲线（0.42，0，1.0，1.0）
        - ease-out：由快到慢，等同于贝塞尔曲线（0，0，0.58，1.0）
        - ease-in-out：由慢到快再到慢，等同于贝塞尔曲线（0.42，0，0.58，1.0）

        ```html
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>过渡</title>
            <style type="text/css">
            .first{
                width: 100px;
                height:100px;
                background-color: deepskyblue;
                transition: background-color，width 5s,5s linear;
                /* 多个属性同时变化时，transition 的值之间用英文逗号隔开 ；
                transition: width 5s linear;
                /* background-color为过渡属性的名称，不可缺少，5s为过渡时间，不可缺少，之后的参数可以缺省 */
            }
            .first:hover{
                background-color: blueviolet;
                width: 200px;
            }
            </style>
        </head>
        <body>
            <div class="first">效果</div>
        </body>
        </html>
        ```

    - 动画
    - 通过css3，可以创建动画，再许多网页中取代动画图片、falsh动画以及js。
            属性    |描述
            --|---
            animation|复合属性，检索或设置对象所应用的动画效果
            animation-name|检索或设置对象所应用的名称
            animation-duration|检索或设置动画的持续时间
            animation-timing-function|检索或设置动画的过渡类型
            animation-delay|检索或设置动画的延迟时间
            animation-interation-count|检索或设置对象动画的循环次数，infinite：无限次循环
            animation-direction|检索或设置对象动画再循环中是否反向运动，normal：正常方向，altternate：正常与反向交错

        ```html
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>动画</title>
            <style type="text/css">
            .first{
                width: 100px;
                height: 100px;
                background-color: blueviolet;
            /*animation-name:cartoon;
                animation-duration: 2s;
                animation-timing-function: ease-in-out;
                animation-delay: 1s;
                animation-direction: alternate;
                animation-iteration-count: infinite;*/
                animation:cartoon 2s ease-in-out 1s infinite alternate;
            }
            @keyframes cartoon{
        /*        from{
                    transform: rotate(0deg);
                    background-color: blueviolet;
                }
                to{
                    transform: rotate(180deg);
                    background-color: pink;
                }*/
                0%{
                    transform: rotate(0deg);
                    background-color: blueviolet;
                    opacity: 1;
                }
                25%{
                    transform: rotate(90deg);
                    background-color: green;
                    opacity: 0.8;
                }
                50%{
                    transform: rotate(180deg);
                    background-color: blue;
                    opacity:0.5;
                }
                75%{
                    transform: rotate(270deg);
                    background-color: pink;
                    opacity: 0.8;
                }
                100%{
                    transform: rotate(360deg);
                    background-color: blueviolet;
                }
            }
            </style>
        </head>
        <body>
            <div class="first">动画效果</div>
        </body>
        </html>
        ```

    - 多列
        属性    |描述
        --|---
        columns|设置或检索对象的列数和每列的宽度，复合属性
        column-width|每列的宽度
        column-conut|列数
        column-gap|列与列之间的间距
        column-rule|列于列之间的边框，复合属性
        column-rule-width|列于列之间边框的厚度
        column-rule-style|列于列之间边框的样式
        column-rule-color|列于列之间的边框颜色

        ```html
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>多列</title>
            <style type="text/css">
                .container
                {
                /*  -moz-column-count:3;
                    -moz-column-width:500px;*/
                    -moz-columns:3 500px;
                    -moz-column-gap:50px;
                /*   -moz-column-width:5px;
                    -moz-column-rule-style:solid;
                    -moz-column-rule-color:red;*/
                    -moz-column-rule:5px solid red;
                }
            </style>
        </head>
        <body>
        <div class="container">
            <div class="one">
                <img src="test.png" width="300px" />
                测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字
            </div>
                <div class="tow">
                <img src="test.png" width="300px" />
                测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字
            </div>
                <div class="three">
                <img src="test.png" width="300px" />
                测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字  测试文字
            </div>
        </div>
        </body>
        </html>
        ```

9. 媒体查询（根据浏览器窗口大小的变化来做出相应的改变）

    - 概念：指定样式表规则用于指定的媒体类型和查询条件
    - 语法：    `@media screen and （width/min-width/max-width）{}`

    ```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>媒体查询</title>
        <style type="text/css">
        *{
            margin:0px;
            padding: 0px;
        }
        @media screen and (max-width: 640px;) {
            .d1{
                width: 100%;
                height: 800px;
                background-color: pink;
            }
        }
        /*屏幕宽度最大值为640px，即屏幕宽度小于640px的情况*/
        @media screen and (min-width: 640px) and (max-width: 800px) {
            .d1{
                width: 100%;
                height: 800px;
                background-color: red;
            }
        }
        /*屏幕宽度在640px-800px之间*/
        @media screen and (min-width: 800px){
            .d1{
                width: 100%;
                height: 800px;
                background-color: blue;
            }
        }
        /*屏幕宽度大于800px*/
        </style>
    </head>
    <body>
        <div class="d1"></div>
    </body>
    </html>
    ```
