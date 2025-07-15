# 使用说明
- 在运行目录创建admin:password形式的users.conf来自定义密码
- 在运行目录创建初始iptables命名为iptables.init，如下作为参考
``` bash
*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 62371 -j ACCEPT
-A INPUT -s 100.100.0.0/16 -j ACCEPT
-A INPUT -s 127.0.0.0/8 -j ACCEPT
-A INPUT -s 10.0.0.0/8 -j ACCEPT
-A INPUT -s 172.16.0.0/12 -j ACCEPT
-A INPUT -s 192.168.0.0/16 -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -s 【【在这里写你当前的IP以避免失联】】/32 -j ACCEPT
COMMIT
```

- 将文件加入crontab -e 以@reboot形式启动
```
@reboot cd /opt/ips && /usr/bin/python wl.py >> wl.log 2>&1
```
