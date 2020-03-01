# 环境配置

## 服务器上部署pwn题环境

来源:[如何安全快速地部署多道ctf pwn比赛题目](https://www.giantbranch.cn/2018/09/24/%E5%A6%82%E4%BD%95%E5%AE%89%E5%85%A8%E5%BF%AB%E9%80%9F%E5%9C%B0%E9%83%A8%E7%BD%B2%E5%A4%9A%E9%81%93ctf%20pwn%E6%AF%94%E8%B5%9B%E9%A2%98%E7%9B%AE/)

### pwn_deploy_chroot介绍

#### 特点

- 一次可以部署多个题目到一个docker容器中
- 自动生成flag,并备份到当前目录
- 也是基于xinted + docker + chroot
- 利用python脚本根据pwn的文件名自动化地生成3个文件：pwn.xinetd，Dockerfile和docker-compose.yml
- 在/bin目录，利用自己编写的静态编译的catflag程序作为/bin/sh,这样的话，system(“/bin/sh”)实际执行的只是读取flag文件的内容，完全不给搅屎棍任何操作的余地
- 默认从10000端口监听，多一个程序就+1，起始的监听端口可以在config.py配置，或者生成pwn.xinetd和docker-compose.yml后自己修改这两个文件

#### 服务器环境配置

```bash
  # 安装docker
  curl -s https://get.docker.com/ | sh
  # 安装 docker compose 和git
  apt install docker-compose git
  # 下载
  git clone https://github.com/giantbranch/pwn_deploy_chroot.git
```

#### 使用

1. 将要部署的pwn题目放到`~/pwn_deploy_chroot/bin`目录下,注意文件名不要含有特殊字符，文件名建议使用字母，下划线，短横线和数字；
2. 运行`initialize.py`,运行脚本后会输出每个pwn的监听端口，文件与端口信息，还有随机生成的flag默认备份到`flags.txt`;
3. 启动环境，root用户执行命令:`docker-compose up --build -d`,执行前确认docker已开启服务。
4. 键入命令查看是否已经成功启动：`netstat -antp | grep docker`.

## Docker

### Ubuntu安装Docker(菜鸟教程)

Docker要求Ubuntu系统的内核版本高于3.10，可以通过命令`uname -r`查系统的内核版本

- Docker安装
    Docker安装使用脚本安装，输入命令：`wget -qO- https://get.docker.com/ | sh`,中途可能会安装失败，可尝试命令`sudo apt-get update`后再进行安装。
    安装完成后，如果要以为root用户可以直接运行dockers，需要执行命令`sudo usermod -aG docker username`,然后重新登录，否则会报错。
- 启动Docker后台服务
    键入命令`sudo service docker start`
- 测试运行hello-world
    键入命令`docker run hello-world`,（`docker run`,创建一个新的容器并运行一个命令）
    ![Alt](img/docker-run.png)
    ![Alt](img/docker-run1.png)
- 镜像加速
    可以配置加速器来解决拉取Docker镜像十分缓慢的问题，网易的镜像地址`http://hub-mirror.c.163.com`
    键入命令`gedit  /etc/docker/daemon.json`,添加内容：

    ```json
        {
            "registry-mirrors": ["http://hub-mirror.c.163.com"]
        }
    ```

- Ubuntu16.04
    ![Alt](img/Ubuntu16-docker.png)
- Docker命令(容器生命周期管理)
  - docker run（参见3.测试运行hello-world）
  - docker start/stop/restart 命令
    ![Alt](img/docker-start.png)
  - docker kill
    ![Alt](img/docker-kill.png)
  - docker rm
    ![Alt](img/docker-rm.png)
  - docker pause/unpause
    ![Alt](img/docker-pause.png)
  - docker create
    ![Alt](img/docker-create.png)
  - docker exec
    ![Alt](img/docker-exec.png)
- Docker命令(容器操作)
  - docker ps
    ![Alt](img/docker-ps.png)
  - docker inspect
    ![Alt](img/docker-inspect.png)
  - docker top
    ![Alt](img/docker-top.png)
  - docker attach
    ![Alt](img/docker-attach.png)
  - docekr events
    ![Alt](img/docker-events.png)
  -docker logs
    ![Alt](img/docker-logs.png)
  - docker wait
    ![Alt](img/docker-wait.png)
  - docker export
    ![Alt](img/docker-export.png)
  - docker port
    ![Alt](img/docker-port.png)
- Docker命令(容器rootfs命令)
  - docker commit
    ![Alt](img/docker-commit.png)
  - docker cp
    ![Alt](img/docker-cp.png)
  - docker diff
    ![Alt](img/docker-diif.png)
- Docker命令(镜像仓库)
  - docker longin/logout
    ![Alt](img/docker-login.png)
  - docker pull
    ![Alt](img/docker-pull.png)
  - docker push
    ![Alt](img/docker-push.png)
  - docker search
    ![Alt](img/docker-search.png)
- Docker命令(本地镜像管理)
  - docker images
    ![Alt](img/docker-images.png)
  - docker rmi
    ![Alt](img/docker-rmi.png)
  - docker tag
    ![Alt](img/docker-tag.png)
  - docker build
    ![Alt](img/docker-build1.png)
    ![Alt](img/docker-build2.png)
  - docker history
    ![Alt](img/docker-history.png)
  - docker save
    ![Alt](img/docker-save.png)
  - docker load
    ![Alt](img/docker-load.png)
  - docker import
    ![Alt](img/docker-import.png)
- Docker命令(info|version)
  - docker info
    ![Alt](img/docker-info.png)
  - docker version
    ![Alt](img/docker-version.png)
- Docker删除镜像
  ![Alt](img/docker-delete.png)

### Docker 容器的使用与简单操作

- 导入打包好的`ubuntu.17.04.amd64.tar`
    将tar压缩文件拷贝到机器（Ubuntu）中后，键入命令`cat ubuntu.17.04.amd64.tar | docker import - ubuntu/17.04.amd64`
    回显sha1值后表示导入成功：（使用命令`docker images`会看到镜像仓库中出现了一个新的镜像）
    ![Alt](img/docker-ubuntu.png)
- 以导入的镜像创建容器
    使用命令`docker run -it -p 23946:23946 ubuntu/17.04.amd64 /bin/bash`创建一个容器并开启一个shell，并且将IDA调试服务器监听的`23946`端口转发到本地的`23946`端口:
    ![Alt](img/创建容器.png)
    ![Alt](img/创建容器1.png)
- 更改容器名
    打开新的bash窗口，键入命令`docker container ls -a`可以发现多了一个刚刚创建的容器（被赋予了一个随机名： `hungry_neumann`）
    ![Alt](img/新建容器.png)
    可以通过命令`docker container rename hungry_neumann ubuntu.17.04.amd64`把容器名更改为`ubuntu.17.04.amd64`或者其他名字
    ![Alt](img/容器更名.png)
- 打开目标容器(进入容器)
    键入命令`docker exec -it ubuntu.17.04.amd64 /bin/bash`,打开目标容器的一个新的`bash shell`,可以在容器中启动IDA调试服务器并用socat部署Pwn题目（socat部署pwn题目，命令：`socat tcp-listen:100001,reuseaddr,fork EXEC:./hello,pty,raw`即将名为hello的elf文件的IO转发到10001端口上）
    ![Alt](img/打开目标容器.png)
    >运行容器使用命令`docker start ubuntu.17.04.amd64`
    >![Alt](img/启动容器.png)
    >注意：`docker run ...`是用于新建一个容器并运行，而运行已存在的容器使用命名`docker start ...`
- 其他
    可以使用`docker container cp`命令在`docker`容器内外双向传输文件等等。需要注意的是，对容器的各种操作需要在容器运行时进行，若容器尚未运行(运行`docker container ls`未显示对应容器)，需使用命令`docker start`运行对应容器。此外，若同时运行多个容器，为了避免端口冲突，在启动容器时，可以将命令`docker run -it -p 23946:23946 ubuntu/17.04.amd64 /bin/bash` 中的第一个端口号`23946`改为其他数字。

## IDA的简单使用及远程调试配置

成功搭建Docker环境后，搭建IDA远程调试环境，在IDA安装目录下的`dbgsrv`目录下找到需要的调试服务器`Linux_server(32位)`和`Linux_serverx64(64位)`并复制到虚拟机中。
键入命令(64位容器与此一致)`docker container cp linux_server ubuntu.17.04.i386:/root/linux_server`将`linux_server`复制到32位容器（需要重新创建，过程和64位完全一致，即导入镜像、创建容器、映射端口等，此处我的32位容器映射端口号为`23945`）

![Alt](img/IDA1.png)

接着在IDA（32位）中载入调试测试程序`heapTest_x86`,定位到main函数后F2下断。然后启用Linux Debuuger通过`Debugger->Process options...`打开选项窗口设置远程调试选项

![Alt](img/IDA5.png)

在弹出的选项窗口中配置Hostname为kali的ip地址，Port为容器映射到kali中的端口:

![Alt](img/IDA2.png)

IDA会将被调试的文件复制到服务器所在目录下，然后汇编代码所在窗口背景会变成浅蓝色并且窗口布局发生变化。之后开始调试，F9运行程序，调试器常用快捷键：下断点/取消断点F2，运行程序F9，单步跨过函数F8，单步进入函数F7，运行到选中位置F4等。在调试模式下主要使用到的窗口有汇编窗口`IDA View-EIP`，寄存器窗口`General registers`，栈窗口`Stack view`，内存窗口`Hex View`，系统日志窗口`Output window`等。
>Tips:当IDA中的程序执行完call    ___isoc99_scanf或者类似的等待输入的指令后会陷入阻塞状态，F4，F7，F8，F9等和运行相关的快捷键都不生效。此时可以在shell中输入内容，IDA中的程序即可恢复执行。

## 使用pwntools和IDA调试程序

在这之前，确保linux_server开启

![Alt](img/linux_server.png)

在调试过程中遇到一些特殊需求，如自动化完成一些操作或向程序传递一些包含不可见字符的地址(\x50\x83\x04\x08(0x08048350))。就需要使用脚本来完成这些工作。可以利用python的pwntools配合IDA调试程序。
首先，进入python，导入pwntools库

![Alt](img/import-pwn.png)

新开一个32位容器的bash shell，打开调试程序所在目录(heapTest)，键入`socat tcp-listen:10001,reuseaddr,fork EXEC:./heapTest,pty,raw,echo=0`将heapTest的IO端口转发到10001端口上

![Alt](img/socat.png)

此时回到python中，和`172.17.0.2`(docker地址)建立连接

![Alt](img/link.png)

需要注意的是，此时heapTest已经运行，需要在IDA中附加到程序调试，`Debugger->Attach to process...`,附加到程序调试(断点下在`call __isoc99_scanf`处)

![Alt](img/attach.png)

开始调试后，EIP指向vdso中的pop ebp指令上

![Alt](img/attach1.png)

这几行指令实际是执行完`sys_read`后的指令，不用理会，直接F9，选中的标志会消失

![Alt](img/attach2.png),此时IDA被挂起，等待输入。

回到python中，通过send(或sendline)函数向程序传递输入

![Alt](img/py-dbg.png)

此时IDA窗口停在程序领空

![Alt](img/py-dbg1.png)

其中，`io.recv()`是读取输出，与程序交互，send和sendline的区别在于send不会在字符串末尾追加换行符
