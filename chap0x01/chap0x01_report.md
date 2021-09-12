# 基于VirtualBox的网络攻防基础环境搭建


## 实验目的

- 掌握VirtualBox虚拟机的安装与使用;
- 掌握VirtualBox的虚拟网络类型和按需配置;
- 掌握VirtualBox的虚拟硬盘多重加载;


## 实验环境

以下是本次实验需要使用的网络节点说明和主要软件举例：

- VirtualBox 虚拟机
- 攻击者主机（Attacker）：Kali Rolling 2021.2
- 网关（Gateway, GW）：Debian Buster
- 靶机（Victim）：From Sqli to shell / xp-sp3 / Kali


## 实验要求

- 虚拟硬盘配置成多重加载，效果如下图所示;

  ![requirement](./img/vb-multi-attach.png)


- 搭建满足如下拓扑图所示的虚拟机网络拓扑;

  ![requirement2](./img/vb-exp-layout.png)


> 根据实验宿主机的性能条件，可以适度精简靶机数量

- 完成以下网络连通性测试；
  - [x] 靶机可以直接访问攻击者主机
  - [x] 攻击者主机无法直接访问靶机
  - [x] 网关可以直接访问攻击者主机和靶机
  - [x] 靶机的所有对外上下行流量必须经过网关
  - [x] 所有节点均可以访问互联网

## 实验步骤


### 虚拟机多重加载及网络配置

1. 导入虚拟机后在虚拟介质管理中释放盘片，再选择类型为"多重加载"；  
   ![多重加载](./img/多重加载.png)
  
2. 根据网络拓扑图配置各虚拟机网络；
   - 网关主机网卡：  
   ![网关配置](./img/Gateway.png) 

   - 网关ip地址：  
   ![网关设置](./img/网关设置.png)

3. 配置dnsmasq实现自动获取IP地址；
  - 在网关主机安装dnsmasq;  
  ```
  apt install snsmasq
  ```
  - 添加配置文件;
  ```
  # /etc/dnsmasq.d/gw-enp09.conf
  interface=enp0s9
  dhcp-range=172.16.111.100,172.16.111.150,240h
  ```
  ```
  # /etc/dnsmasq.d/gw-enp010.conf
  interface=enp0s10
  dhcp-range=172.16.222.100,172.16.222.150,240h
  ```

4. 靶机网络设置；
- xp1设置为内部网络intnet1  
  - ![xp1](./img/xp1.png)  
  ![xp1网络](./img/xp1-ip.png)

- xp2设置为内部网络intnet2  
  - ![xp2](./img/xp2.png)  
  ![xp2网络](./img/xp2-ip.png)  

- kali-victim设置为内部网络intnet1  
  - ![kali-victim](./img/kali1.png)  
  ![kali-victim网络](./img/kali1-ip.png)  

- debian2设置为内部网络intnet2    
  - ![debian2网络](./img/debian2-attacker.png)

- kali-attacker设置为NAT 网络;
  - ![attacker网络](./img/attacker.png)
  - ![attacker网络](./img/attacker-ip.png)  



### 网络连通性测试


| 虚拟机 | 网络 | ip地址 |
| :-----:| :----: | :----: |
| xp-victim-1 | intnet1 | 172.16.111.121 |
| kali-victim-1 | intnet1 | 172.16.111.111 |
| xp-victim-2 | intnet2 | 172.16.222.149 |
| victim-debian2 | intnet2 | 172.16.222.140 |  

1. 靶机可以直接访问攻击者主机；  
   - ![debian直接访问attacker](./img/debian2-attacker.png)  
   - ![xp1直接访问attacker](./img/xp1-attacker.png)
   - ![xp2直接访问attacker](./img/xp2-attacker.png) 

2. 攻击者主机无法直接访问靶机;  
   - ![无法直接访问靶机](./img/attacker-all.png) 

3. 网关可以直接访问攻击者主机和靶机；
   - ![网关直接访问](./img/网关直接访问.png) 

4. 靶机的所有对外上下行流量必须经过网关；  
   - 在网关主机安装tmux和tcpdump
   ```
   apt install tcpdump
   apt install tmux
   ```
   - 抓包并保存数据  
   ```
   tcpdump -i enp0s10 -n -w 20210911.xp.1.pcap 
   ```
   - ![靶机流量](./img/靶机流量.png) 

5. 所有节点均可以访问互联网；  
   - ![网关访问互联网](./img/网关访问互联网.png)     
   - ![靶机访问互联网](./img/访问互联网1.png)  
   - ![攻击者访问互联网](./img/访问互联网2.png)  


## 实验问题


1. ssh远程登录时报错`permission denied please try again` 
   - 打开文件`sudo vi /etc/ssh/sshd_config`
   - 找到位置并修改为`PermitRootLogin yes`  
   ![sshd修改](./img/ssh.png)  
   - 重启sshd服务器`service sshd restart`  


## 参考资料


1. [virtualbox多重加载](https://blog.csdn.net/Jeanphorn/article/details/45056251)
2. [ssh登录问题修改](https://blog.csdn.net/donaldsy/article/details/102679413)