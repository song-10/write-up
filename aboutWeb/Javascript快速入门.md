# JavaScript

## 如何写一段JS代码并运行（一行语句结束可以直接回车不加分号）

1. 在标签中作为属性值写入

    ```html
    <input type="button" value="按钮" onclick="js
    代码">
    ```

2. 在 `body` 或`head`标签中插入js代码

    ```html
    <body>
        <script>
        js代码
        </script>
    </body>
    ```

3. 外部js文件引入

    ```html
    <body>
        <script src="*.js"></script>
    </body>
    ```

    >注意：外部引入js文件的优先级大于在 `body` 标签中写入js代码，即当引入外部js文件时， `body`标签内的js代码不会被执行

    ```html
    <!-- html部分 -->
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>第一行代码</title>
    </head>
    <body>
        <input type="botton" value="按钮" onclick="alert('hello,world!')">
        <script type="text/javascript" src="demo_js1.js">
            <!-- 外部导入js文件时，script标签内的代码不会被执行 -->
            alert('hello,javascript')
        </script>
    </body>
    </html>
    ```

    ```javascript
    // 外部js文件
    alert("I'm javascript")
    ```

## js语法基础(`console.log()在浏览器的控制台打印`)

1. 变量

    ```js
    var a;
    a=1
    // 声明一个变量a，然后给a赋值为1
    var b=1;
    // 声明变量b的同时给b赋值
    var c=1,d=1,e=1;
    // 同时声明多个变量并赋值
    ```

2. 变量命名
    >1. 变量名必须是数字、字母、下划线和`$`组成且不能以数字开头；
    >2. 变量名不能时关键字；
    >3. js中变量是区分大小写的；
    >4. 重复声明的变量，后者会覆盖前者
3. 数据类型（js中转义字符为`\`
    - 数值Number（数字）
    - 字符串String
    >双引号或单引号括起来;
    >字符串可以通过`+`号拼接字串
    > 变量从左往右进行运算：

    ```js
    var v1 = 1,v2 = 2, v3 = '3',v4 = '4', v5 = '5';
    //v1+v2+v3='33'
    //v1+v2+v3+v4+v5+v1+v2='334512'
    //即做加法运算时，只要遇到字符类型的变量，之后不管时什么类型，都会变成字符串的拼接
    ```

    - 布尔型（Boolean）
        1. Boolean字面量:true和false，区分大小写；
        2. true为1，false为0。
    - Undefined和Null
        1.undefined表示声明了一个没有被赋值的变量，变量只声明的时候默认类型为undefined；
        2. null表示一个空，变量的值如果为null，必须手动赋值`var t=null`
    - 复杂数据类型（object）
    - `typeof var`打印变量类型。`var.length`查看变量（字符串）长度
4. 代码注释
    - 单行注释：`//注释内容`
    - 多行注释：`/*注释内容*/`
5. 数据类型转换
    - 数值到字符串：`var n=5; var s = n.toString();`或`String(n)`或`var = ''+n;`
    - 其他类型到数值：
        `var a = '1';var b = Nmber(a);`
        `var a = 'c';b = Number(a);//字字母字符串不能转换为数字`
        `var a = Number(null);//值为0`
        `var a = Number(undefined);//不能转换`
        `var a = parseInt('2');`
        `var a = parseInt('a123');//不能转换`
        `var a = parseInt(undefined);//不能转换`
        `var a = parsefloat('1.23df');//结果为：1.23`
        `var a = parsefloat('1.2.3');//结果为：1.2`
        `var a = parsefloat(null);//不能转换`
        `var a = parsefloat(undefined);//不能转换`
        `var a = parsefloat('h34');//不能转换`
    - 布尔型转换
        `var a = Boolean('0');//true`
        `var a = Boolean(0);//false`
        `var a = Boolean('2');//true`
        `var a = Boolean(null);//false`
        `var a = Boolean(undefined);//false`
        `var a = Boolean('');//false,字符串只要由内容（包括空格）不为空，就为真'
6. 操作符
    - 算术运算符: `+ - * / %`
    - 一元运算符：自增自减（`-- ++`)
    - 逻辑运算符：`&& || !`(与或非)
    - 比较运算符：`> < <= >= == === != !==`

    ``` js
    var a='2',b=2;
    a==b;//true，不全等会自动做类型转换
    a===b;//false，全等要求值和数据类型都一致
    //！=（不等）也是不比较数据类型，！==(不全等)，即比较值，也比较类型
    ```

    - 赋值运算符：`+= -+ /= *=`
    - 运算符优先级
    ![Alt](https://images2017.cnblogs.com/blog/531939/201709/531939-20170917155621344-941370588.png)
7. 流程控制
    - 条件语句
        `if(条件){语句块}else{语句块}`
    - 开关语句
        `switch(判断条件){case 值：语句；break；default：语句；}
    - while循环
        `while(条件){语句块}`
    - do while循环
        `do{语句块}while(条件)`
    - for循环
        `for(初始表达式；判断表达式；自增或自减运算)`
    - break与continue
8. 数组
   `var array = [var1,var2,...];`
   `var a1 = new Array(var1, var2, var3, ...);`
   >注意：数组元素可以是不同类型的,数组里面也能由数组，类似于python
9. 函数
    `function 函数名（形参1，形参2，形参3，形参4，……）{函数体}`
    >形参不需要关键字var，返回值时使用return
    >立即执行函数（自调用的匿名函数）`(founction(形参列表){函数体})()`，可以防止全局变量的污染，封装某一个局部作用，函数体内。
    >函数名与变量名相同时会替换先前的声明。
10. 对象
    >字面声明对象（类似于python中的字典）
    >`var obj1={key1:value1,key2:value2,...}`以简直对的形式存在，值可以是任意类型的数据，包括函数

    ```js
    var per1={
        name:"kkx",
        age:20,
        sex:"man",
        ear:function(){
            console.log("eat");
        },
        readBook:function(){
            console.log("qrt");
        }
    };
    //该方法的的对象属于Object（），以该种方法创建的对象都是属于object（），即不可确定创建的对象属于哪个类型的
    ```

    >实例化方式声明对象
    >`var obj2 = new Object();'

    ```js
    var per2=new Object();
    per2.name="dsw";
    per2.age=30;
    per.sex="man",
    per2.eat=function(){
        console.log("liulian");
    };
    per2.play=function(){
        console.log("funny");
    };
    //该方法的的对象属于Object（），以该种方法创建的对象都是属于object（），即不可确定创建的对象属于哪个类型的
    ```

    >自定义构造函数方式
    >`function fun(){}

    ```js
    //person即是构造函数
    function Person(name,sex,age){
        this.name=name;
        this.sex=sex;
        this.age=age;
        this.play=function(){
            console.log("play day");
        };
    }
    var per=new Person("zt",18,"women");
    console.log(per instanceof Person);//结果为TRUE
    //自定义方式可以确定对象是属于哪种类型的
    ```

    >实例化定义构造函数方式声明对象
    >`var f = new Fun();`
    >调用对象的属性或者方法： 对象.属性名
    >`obj1.key1`,属性值为函数时：`obj1.key2()`
11. this对象

    ```js
    var obj1 = {
        name:'Tom',
        age:18,
        fun:function(){
            var s = this.age;
            console.log(s);
        }
    }
    obj1.fun();
    ```

12. this的指向

    ```js
    k='678';
    function fun(){
        var k = '89';
        console.log(this.k);
    }
    var o1 = {
        k:'123',
        f:fun
    }
    var o2 = {
        k:'345',
        f:fun
    }
    o1.f();//打印出123
    o2.f();//打印出345
    //this运行在哪个对象下，就指向哪个对象
    //另一种情况
    var o1 = {
        age:18,
        fun:function(){
            console.log(this.age);
        }
    }
    var o2 = {
        age:16,
        fun:o1.fun,//这里fun是o1.fun这个值，即o1.fun（）这个函数，实际上是将函数功能赋给对象o2的属性fun而并不是执行o1.fun（）这个函数
    }
    o2.fun();//此时输出结果为16
    ```

13. 对象的遍历及删除

    ```js
    var o1 = {
        name:'tom',
        age:'18',
        sex:'man'
    }
    //for(键 in 对象){}
    for(var i in o1){
        console.log(o1[i]);
    }
    //for遍历数组
    var array = [];
    for(var i in array){
        console.log(array[i]);
    }
    //删除对象的属性
    delete o1.age;//删除o1的age属性
    ```

14. 包装对象
    >原始类型（数值、字符串、布尔值）的数据在一定条件下自动转为对象就是包装对象;
    >如:`var v1 = new Number(123);`v1就是一个对象;
    >原始值可以自动当做对象来调用各种属性及方法，如`var a = '456'; a.length;`,当包装的对象使用完成后，就会立即自动销毁。

## js进阶

1. 工厂模式和自定义构造函数的区别：

    ```js
    //自定义构造函数
    function Person(name,page){
        this.name=name;
        this.age=age;
        this.sayHi=function(){
            console.log("hello");
        };
    }
    //创建对象---->实例化一个对象的同时对属性进行初始化
    var per=new Person("小红",20);
    /*
    new操作做的事情
    1. 开辟空间存储对象；
    2. 把this设置为当前的对象；
    3.设置属性和方法的值；
    4. 把this对象返回
    */
    //工厂方式
    function createObject(name,age){
        var obj=new Object();
        obj.name=name;
        obj.age=age;
        obj.sayHi=function(){
            console.log("hello");
        };
        return obj;
    }
    var per1=createObject("小明",20);
    /*
    共同点：都是函数，都可以创建对象，都可以传入参数

    工厂模式：
        函数名是小写；
        有new；
        有返回值；
        new之后的对象是当前的对象；
        直接调用函数就可以创建对象
    自定义构造函数：
        函数名是大写（首字母）；
        没有new；
        没有返回值；
        this是当前的对象；
        通过new的方式来创建对象
    */
    ```

2. 构造函数和实例对象之间的关系
    - 实例对象是通过构造函数来创建的---创建过程叫实例化
    - 如何判断对象是不是这个数据类型：
        - 通过构造器的方式： 实例对象.constructor==构造函数的名字；
        - 对象 instanceof 构造函数名字
3. 不对同对象指向同一个函数的方法：

    ```js
    function myEat(){
        console.log("eat something");
    }
    function Person(name,age){
        this.name=name;
        this.age=age;
        this.eat=myEat;
    }
    var per1=new Person("小白",20);
    var per2=new Person("小黑",30);
    console.log(per1.eat==per2.eat);//结果为TURE
    //这种方法容易造成命名冲突
    ```

    >通过原型可以解决此问题：数据共享，节省内存空间
4. 原型

    ```js
    function Person(name,age){
        this.name=name;
        this.age=age;
    }
    // 通过原型来添加方法，解决数据共享，节省内存空间
    Person.prototype.eat=function(){
        console.log("eat something");
    ;}

    var p1=new Person("小红",20);
    var p2=new Person("小明",30);
    console.log(p1.eat=p2.eat);//结果为TRUE，eat函数为p1和p2共享
    ```

    1. 构造函数可以实例化对象；
    2. 构造函数中有一个属性叫protoype，是构造函数的原型对象；
    3. 构造函数的原型对象（protoype）中有一个constructor构造器，这个构造器指向的是自己所在的原型对象所在的构造函数；
    4. 实例对象的原型对象（__proto__)指向的是该构造函数的原型对象；
    5. 构造函数的原型对象（prototype）中的方法是可以被实例对象直接访问的。
    ![Alt](img\1.jpg)

    ```js
    // 利用原型共享数据
    /*
    属性需要共享，方法也需要共享；
    不需要共享的数据卸载构造函数中，需要共享的数据写在原型中；
    */
    //构造函数
    function Student(name,age,sex){
        this.name=name;
        this.age=age;
        this.sex=sex;
    }
    /*
    所哟学生的身高都是188，所有人的体重都是55；
    所有学生每天都要写500行代码；
    所有学生每天都要吃十斤西瓜。
    */

    //原型对象
    // Student.prototype.height="188";
    // Student.prototype.weight="55";
    // Student.prototype.study=function(){
    //     console.log("学习，写500行代码");
    // };
    // Student.prototype.eat=function(){
    //     console.log("吃西瓜");
    // };
    Student.prototype={
        // 手动修改构造器指向
        constructor:Student,
        height:"188",
        weight:"55",
        study:function(){
        console.log("学习，写500行代码");
    },
        eat:function(){
        console.log("吃西瓜");
    }
    };
    //实例化对象并初始化
    var stu=new Student("程光",24);
    stu.eat();
    stu.study();
    ```

5. 原型中的方法可以相互调用

    ```js
    function Animal(name,age){
        this.name=name,
        this.age=age
    }
    // 原型中添加方法
    Animal.prototype.eat=function(){
        console.log("eat somethng");
        this.play();
    }
    Animal.prototype.play=function(){
        consloe.log("play ball");
        this.sleep();
    }
    Animal.prototype.sleep=function(){
        console.log("sleep");
    }
    var dog=new Animal("alen",5);
    dog.eat();
    ```

6. 实例对象使用的方法和属性层层搜索

    ```js
    function Person(age,sex){
        this.age=age;
        this.sex=sex;
        this.eat=function(){
            console.log("构造函数中的吃");
        };
    }
    Person.prototype.sex="女";
    Person.prototype.eat=function(){
        console.log("原型对象中的吃")；
    };
    var per=new Person("小明","男");\
    per.sex;//男
    per.eat();//构造函数中的吃
    //实例对象使用的属性或者方法，现在实例对象中查找，找到了则直接使用，找不到则去实例对象的__proto__指向的原型对象prototype中查找，找到了则使用，找不到则报错
    ```

7. 为内置对象的原型对象添加方法

    ```js
    String.prototype.myReverse=function(){
        for(var i=this.length-1;i>=0;i--){
            console.log(this[i]);
        }
    };// 其中，String为内置对象，myRevese()是手动添加的对象
    var str="abcdefg";
    str.myReverse();
    //array内置对象中的原型对象添加排序方法
    Array.prototype.mySort=function(){
        for(var i=0;i<this.length-1;i++){
            for(var j=0;j<this.length-1-i;j++){
                if(this[j]<this[j+1]){
                    var temp=this[j];
                    this[j]=this[j+1];
                    this[j+1]=temp;
                }//end for
            }//end for
        }//end for
    };
    var arr=[100,3,32,43,435,67];
    arr.mySort();
    ```

8. 局部变量变成全局变量

    ```js
    /*
    页面加载后，自调用函数就执行完成
    (function(形参){
        var num=10;//局部变量
    })(实参)；
    */
    (function(win){
        var num=10;//局部变量
        win.num=num;
    })(window);
    console.log(window.num);
    ```

9. 产生随机数对象

    ```js
    (function(window){
        //产生随机数的函数
        function Random(){
            //
        }
        //在原型对象中添加方法
        Random.prototype.getRandom=function(min,max){
            return Math.floor(Math.random()*(max-min)+min);
        };
        // 把Ranmdom对象暴露给顶级对象window--->外部可以直接使用这个对象
        window.Random=Random;
        //window.Random=new Random()
    })(window);
    var rm=new Random();
    // var rm=Random;
    console.log(rm.getRandom(0,5));
    ```

10. 案例-随机小方块

    ```js
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>随机方块</title>
        <style>
            .map{
                width:800px;
                height:600px;
                background-color: #ccc;
                position: relative;
            }
        </style>
    </head>
    <body>
        <div class="map"></div>
        <script>
            //产生随机数变量
            (function(window){
                function Random(){
                }
                Random.prototype.getRandom=function(min,max){
                    return Math.floor(Math.random()*(max-min)+min);
                };
                //把局部对象暴露给window顶级对象，就成了全局对象
                window.Random=new Random();
            })(window);//自调用构造函数的方式，分号一定要加上
            //产生小方块对象
            (function(window){
                //选择器的方式获取元素对象
                var map=document.querySelector(".map");

                // 食物的构造函数
                function Food(width,height,color){
                    this.width=width||20;//默认的小方块的宽
                    this.height=height||20;// 默认的小方块的高
                    //横坐标，纵坐标
                    this.x=0;//横坐标随机产生
                    this.y=0;//纵坐标随机产生
                    this.color=color;//小方块的背景颜色
                    this.element=document.createElement("div");//小方块的元素
                }
                //初始化小方块显示的效果及位置
                Food.prototype.init=function(map){
                    //设置小方块的样式
                    var div=this.element;
                    div.style.position="absolute";//脱离文档流
                    div.style.width=this.width+"px";
                    div.style.height=this.height+"px";
                    div.style.backgroundColor=this.color;
                    //把小方块加到map地图中
                    map.appendChild(div)
                    this.redener();
                };
                //产生随机位置
                Food.prototype.redener=function(){
                    //产生随机横纵坐标
                    var x=Random.getRandom(0,map.offsetWidth/this.width)*this.width;
                    var y=Random.getRandom(0,map.offsetHeight/this.height)*this.height;
                    this.x=x;
                    this.y=y;
                    var div=this.element;
                    div.style.left=this.x+"px";
                    div.style.top=this.y+"px";
                }
                var fd=new Food(20,20,"green");
                fd.init(map);
            })(window);
        </script>
    </body>
    </html>
    ```

11. 案例--贪吃蛇小游戏

    ```html
    <!-- UI.html -->
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>title</title>
    <style>
        .map {
        width: 800px;
        height: 600px;
        background-color: #CCC;
        position: relative;
        }
    </style>
    </head>
    <body>
    <!--画出地图,设置样式-->
    <div class="map"></div>
    <script src="food.js"></script>
    <script src="Snake.js"></script>
    <script src="Game.js"></script>
    <script>
    //初始化游戏对象
    var gm = new Game(document.querySelector(".map"));
    //初始化游戏---开始游戏
    gm.init();

    //外部测试代码
    //  var fd = new Food();
    //  fd.init(document.querySelector(".map"));
    //  //创建小蛇
    //  var snake = new Snake();
    //  snake.init(document.querySelector(".map"));//先在地图上看到小蛇
    //
    //
    //
    //  setInterval(function () {
    //    snake.move(fd, document.querySelector(".map"));
    //    snake.init(document.querySelector(".map"));
    //  }, 150);


    //  snake.move(fd, document.querySelector(".map"));//走一步
    //  snake.init(document.querySelector(".map"));//初始化---重新画一条小蛇(先删除之前的小蛇,把现在的小蛇显示出来)

    //  snake.move(fd, document.querySelector(".map"));
    //  snake.init(document.querySelector(".map"));
    //  snake.move(fd, document.querySelector(".map"));
    //  snake.init(document.querySelector(".map"));
    //  snake.move(fd, document.querySelector(".map"));
    //  snake.init(document.querySelector(".map"));
    //  snake.move(fd, document.querySelector(".map"));
    //  snake.init(document.querySelector(".map"));
    //  snake.move(fd, document.querySelector(".map"));
    //  snake.init(document.querySelector(".map"));
    //
    //  snake.move(fd, document.querySelector(".map"));
    //  snake.init(document.querySelector(".map"));

    //  fd.init(document.querySelector(".map"));
    //  fd.init(document.querySelector(".map"));
    //  fd.init(document.querySelector(".map"));
    //  fd.init(document.querySelector(".map"));
    //console.log(fd.x+"====>"+fd.y);

    //console.log(fd.width);
    </script>
    </body>
    </html>
    ```

    ```js
    // food.js
        //自调用函数----食物的
        (function () {
            var elements = [];//用来保存每个小方块食物的
            //食物就是一个对象,有宽,有高,有颜色,有横纵坐标,先定义构造函数,然后创建对象
            function Food(x, y, width, height, color) {
                //横纵坐标
                this.x = x || 0;
                this.y = y || 0;
                //宽和高
                this.width = width || 20;
                this.height = height || 20;
                //背景颜色
                this.color = color || "green";
            }

            //为原型添加初始化的方法(作用：在页面上显示这个食物)
            //因为食物要在地图上显示,所以,需要地图的这个参数(map---就是页面上的.class=map的这个div)
            Food.prototype.init = function (map) {
                //先删除这个小食物
                //外部无法访问的函数
                remove();

                //创建div
                var div = document.createElement("div");
                //把div加到map中
                map.appendChild(div);
                //设置div的样式
                div.style.width = this.width + "px";
                div.style.height = this.height + "px";
                div.style.backgroundColor = this.color;
                //先脱离文档流
                div.style.position = "absolute";
                //随机横纵坐标
                this.x = parseInt(Math.random() * (map.offsetWidth / this.width)) * this.width;
                this.y = parseInt(Math.random() * (map.offsetHeight / this.height)) * this.height;
                div.style.left = this.x + "px";
                div.style.top = this.y + "px";

                //把div加入到数组elements中
                elements.push(div);
            };

            //私有的函数---删除食物的
            function remove() {
                //elements数组中有这个食物
                for (var i = 0; i < elements.length; i++) {
                    var ele = elements[i];
                    //找到这个子元素的父级元素,然后删除这个子元素
                    ele.parentNode.removeChild(ele);
                    //再次把elements中的这个子元素也要删除
                    elements.splice(i, 1);
                }
            }

            //把Food暴露给Window,外部可以使用
            window.Food = Food;
        }());

    //game.js
    //自调用函数---游戏对象================================================
    (function () {

        var that = null;//该变量的目的就是为了保存游戏Game的实例对象-------

        //游戏的构造函数
        function Game(map) {
            this.food = new Food();//食物对象
            this.snake = new Snake();//小蛇对象
            this.map = map;//地图
            that = this;//保存当前的实例对象到that变量中-----------------此时that就是this
        }

        //初始化游戏-----可以设置小蛇和食物显示出来
        Game.prototype.init = function () {
            //初始化游戏
            //食物初始化
            this.food.init(this.map);
            //小蛇初始化
            this.snake.init(this.map);
            //调用自动移动小蛇的方法========================||调用了小蛇自动移动的方法
            this.runSnake(this.food, this.map);
            //调用按键的方法
            this.bindKey();//========================================
        };

        //添加原型方法---设置小蛇可以自动的跑起来
        Game.prototype.runSnake = function (food, map) {

            //自动的去移动
            var timeId = setInterval(function () {
                //此时的this是window
                //移动小蛇
                this.snake.move(food, map);
                //初始化小蛇
                this.snake.init(map);
                //横坐标的最大值
                var maxX = map.offsetWidth / this.snake.width;
                //纵坐标的最大值
                var maxY = map.offsetHeight / this.snake.height;
                //小蛇的头的坐标
                var headX = this.snake.body[0].x;
                var headY = this.snake.body[0].y;
                //横坐标
                if (headX < 0 || headX >= maxX) {
                    //撞墙了,停止定时器
                    clearInterval(timeId);
                    alert("游戏结束");
                }
                //纵坐标
                if (headY < 0 || headY >= maxY) {
                    //撞墙了,停止定时器
                    clearInterval(timeId);
                    alert("游戏结束");
                }
            }.bind(that), 300);
        };

        //添加原型方法---设置用户按键,改变小蛇移动的方向
        Game.prototype.bindKey=function () {

            //获取用户的按键,改变小蛇的方向
            document.addEventListener("keydown",function (e) {
                //这里的this应该是触发keydown的事件的对象---document,
                //所以,这里的this就是document
                //获取按键的值
                switch (e.keyCode){
                    case 37:this.snake.direction="left";break;
                    case 38:this.snake.direction="top";break;
                    case 39:this.snake.direction="right";break;
                    case 40:this.snake.direction="bottom";break;
                }
            }.bind(that),false);
        };

        //把Game暴露给window,外部就可以访问Game对象了
        window.Game = Game;
    }());

    // snake.js
    //自调用函数---小蛇
    (function () {
        var elements = [];//存放小蛇的每个身体部分
        //小蛇的构造函数
        function Snake(width, height, direction) {
            //小蛇的每个部分的宽
            this.width = width || 20;
            this.height = height || 20;
            //小蛇的身体
            this.body = [
                {x: 3, y: 2, color: "red"},//头
                {x: 2, y: 2, color: "orange"},//身体
                {x: 1, y: 2, color: "orange"}//身体
            ];
            //方向
            this.direction = direction || "right";
        }

        //为原型添加方法--小蛇初始化的方法
        Snake.prototype.init = function (map) {
            //先删除之前的小蛇
            remove();//===========================================

            //循环遍历创建div
            for (var i = 0; i < this.body.length; i++) {
                //数组中的每个数组元素都是一个对象
                var obj = this.body[i];
                //创建div
                var div = document.createElement("div");
                //把div加入到map地图中
                map.appendChild(div);
                //设置div的样式
                div.style.position = "absolute";
                div.style.width = this.width + "px";
                div.style.height = this.height + "px";
                //横纵坐标
                div.style.left = obj.x * this.width + "px";
                div.style.top = obj.y * this.height + "px";
                //背景颜色
                div.style.backgroundColor = obj.color;
                //方向暂时不定
                //把div加入到elements数组中----目的是为了删除
                elements.push(div);
            }
        };

        //为原型添加方法---小蛇动起来
        Snake.prototype.move = function (food, map) {
            //改变小蛇的身体的坐标位置
            var i = this.body.length - 1;//2
            for (; i > 0; i--) {
                this.body[i].x = this.body[i - 1].x;
                this.body[i].y = this.body[i - 1].y;
            }
            //判断方向---改变小蛇的头的坐标位置
            switch (this.direction) {
                case "right":
                    this.body[0].x += 1;
                    break;
                case "left":
                    this.body[0].x -= 1;
                    break;
                case "top":
                    this.body[0].y -= 1;
                    break;
                case "bottom":
                    this.body[0].y += 1;
                    break;
            }

            //判断有没有吃到食物
            //小蛇的头的坐标和食物的坐标一致
            var headX=this.body[0].x*this.width;
            var headY=this.body[0].y*this.height;
            //判断小蛇的头的坐标和食物的坐标是否相同
            if(headX==food.x&&headY==food.y){
                //获取小蛇的最后的尾巴
                var last=this.body[this.body.length-1];
                //把最后的蛇尾复制一个,重新的加入到小蛇的body中
                this.body.push({
                    x:last.x,
                    y:last.y,
                    color:last.color
                });
                //把食物删除,重新初始化食物
                food.init(map);
            }
        }
        ;//删除小蛇的私有的函数=============================================================================
        function remove() {
            //删除map中的小蛇的每个div,同时删除elements数组中的每个元素,从蛇尾向蛇头方向删除div
            var i = elements.length - 1;
            for (; i >= 0; i--) {
                //先从当前的子元素中找到该子元素的父级元素,然后再弄死这个子元素
                var ele = elements[i];
                //从map地图上删除这个子元素div
                ele.parentNode.removeChild(ele);
                elements.splice(i, 1);
            }
        }

        //把Snake暴露给window,外部可以访问
        window.Snake = Snake;
    }());
    ```
