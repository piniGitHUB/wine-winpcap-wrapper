#List of Winpcap Based Network Authentication Clients


---

# Only depends on winpcap: #

Some kinds of winpcap based network authentication clients only depends on winpcap, those clients ship with an npf.sys, when we have wpcap.dll.so on Wine, npf.sys is unnecessary at all.


## Mentohust ##

Mentohust is open source and cross-platform, no need to run on Wine, but we have a proof of concept regarding running Mentohust on Wine:

http://code.google.com/p/wine-winpcap-wrapper/wiki/MentohustOnWine


## Dr.com (城市热点) ##

More then **300** universities and **60** ISPs are using Dr.com's servers and clients... So amazing `[1]`:

```
城市热点积累了300多家高校用户和60多家运营商的用户经验
```

Dr.com has lots of versions and variants, some of them are cross-platform but most of them are Win32 only.

Most of them needs npptools.dll as well `[2]`

  * Here is an example of cross-platform Dr.com:

http://www.cquc.edu.cn/main/soft.html

  * Here is a Win32 only Dr.com for Guangdong University of Foreign Studies:

http://ishare.iask.sina.com.cn/f/16876555.html

There is an open source client for it:
https://github.com/huntxu/projects/tree/master/drcom4GDUFS

  * There are still many other variants which have no Linux/Mac alternative, I'll collect them here later.
    * (陕西科技大学) `[3]`, someone reported it works out of box on Wine `[4]`, I haven't confirmed by myself. Maybe it does not use winpcap (but it does ship with winpcap).
    * Dr.com for Tianjin University of Science and Technology. We've confirmed it works out of box on Wine. Unfortunately, we've also confirmed it doesn't depend on winpcap. But yes, it ship with winpcap... LOL... Also, there is no public download version for this variant.
    * [Dr.COM Client 标准版-Ver3.73|封装| FOR XP vista win7|802.1x|.exe](http://wlzx.cdutetc.cn/down.do?action=downLoad&did=2c9082c82761706a01276b04b2ca0002)

## Xuzhou Telecom Client (徐州电信客户端) ##

There are some variants: http://fb.86516.com/adsl/adslrj.html

See also:

[Bug 30378 - Xuzhou network client crashes at start](http://bugs.winehq.org/show_bug.cgi?id=30378)

[Bug 30379 - Xuzhou network client error while trying to connect: "Failed to create VPN dynamic, code = 1060"](http://bugs.winehq.org/show_bug.cgi?id=30379)



---

# Depends on more than winpcap: #


Some other winpcap based clients not only depends on winpcap, but also depends on other win32 kernel module, those clients ship with an npf.sys and a XXX.sys, usually XXX.sys is depends on ndis.sys. I have no idea if they have chance to run on Wine...


## Shan-Xun Client (闪讯客户端) ##

http://www.114school.cn/xytypt/typt/download/download.html

## Yi-Xun Client (翼讯客户端) ##

Also have lots variants, there are at least **19** different colleges use Yi-Xun client.

http://www.yixun.sn.cn/clientdownloadall.html



---









`[1]` http://www.doctorcom.com/article.php?articleid=148

`[2]` http://bugs.winehq.org/show_bug.cgi?id=30041

`[3]` http://wgzx.sust.edu.cn/yangshi2.jsp?pagetype=TPP_CONTENT&wbnewsid=109388&tree=2

`[4]` http://forum.ubuntu.org.cn/viewtopic.php?f=156&t=356291