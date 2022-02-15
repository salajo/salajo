#!/bin/bash
# Centos7服务器系统及服务信息查询
# Author: admin@ym68.cc
# Date: 2021-12-10
# Version: 0.0.2
# Description: 该脚本用于查询服务器硬件及系统服务信息

# 设置脚本语言
Old_LANG=$LANG
LANG="en_US.utf8"

# 查看系统版本
System_Release_D=`sed -n 's/.*release[[:space:]]\([0-9]\)\.[0-9].*/\1/p'  /etc/redhat-release`

Info_Header(){
    echo -e "#==================== \033[33m ${1} !\033[0m ====================#"
}

Info_Echo(){
    echo -e "#\t${1}\t: \033[33m${2}\033[0m"
}

Info_Echo_2(){
    echo -e "#\t\t${1}\t: \033[33m${2}\033[0m"
}

# 检查If判断是否为空
Check_If_Not_Code_Null(){
    if [ ! -z "${2}" ];then
        Info_Echo_2 "${1}" "${2}"
    fi
}

# 检查服务状态
Check_Service_Status(){
    if [[ ${System_Release_D} -eq 7 ]];then
        # 服务检查
        systemctl is-active ${1}
    else
        if [ -e "/etc/init.d/$1" ];then
            if [ `/etc/init.d/${1} status 2>/dev/null | grep -E "is running|正在运行" | wc -l` -ge 1 ];then
                echo "active"
            else
                echo "inactive"
            fi
        else
            echo "unknown"
        fi
    fi
}

# 安装必要的依赖
Init_Install_Packages_Name_List=(pciutils nmap-ncat)
for Install_Packages_Name in ${Init_Install_Packages_Name_List[@]};do
    Check_Install_Info=`rpm -q "${Install_Packages_Name}"`
    if [[ "${Check_Install_Info}" =~ "is not installed" ]];then
        yum -y install "${Install_Packages_Name}" &> /dev/null
    fi
done

# 服务器硬件信息
Hardware_Information(){
    Info_Header "服务器设备信息"
    # 服务器序列号
    System_Serial_Number=`dmidecode -s system-serial-number`
    if [ -z "${System_Serial_Number}" ];then
        System_Serial_Number=`cat /proc/device-tree/serial-number`
    fi
    # 服务器型号
    System_Product_Name=`dmidecode -s system-product-name|egrep -v '^#|^$'|head -1`
    if [ -z "${System_Product_Name}" ];then
        System_Product_Name=`cat /proc/device-tree/model`
    fi
    # 服务器制造商
    System_Manufacturer=`dmidecode -s system-Manufacturer`
    # 服务器硬件类型
    System_Server_Hardware_Type=`dmesg |awk '/virtualized kernel on/ {if($8 == ""){print $7}else{print $7,$8}}'`
    if [ -z "${System_Server_Hardware_Type}" ];then
        System_Server_Hardware_Type=`lscpu|awk -F'[: ]+' '/Virtualization/{print $2}'`
    fi
    Info_Echo "服务器序列号" "${System_Serial_Number}"
    Info_Echo "服务器制造商" "${System_Manufacturer}"
    Info_Echo "服务器型号" "${System_Product_Name}"
    Info_Echo "服务器硬件类型" "${System_Server_Hardware_Type}"

    Info_Header "BIOS信息"
    # Bios信息
    System_Bios_Info=`dmidecode -t bios`
    # Bios厂商
    System_Bios_Vendor_Info=`echo "${System_Bios_Info}" |awk -F':[[:space:]]' '/Vendor/ {print $2}'|sort|uniq`
    # Bios版本
    System_Bios_Version_Info=`echo "${System_Bios_Info}" |awk -F':[[:space:]]' '/Version/ {print $2}'|sort|uniq`
    # Bios发布时间
    System_Bios_Release_Date_Info=`echo "${System_Bios_Info}" |awk -F':[[:space:]]' '/Release Date/ {print $2}'|sort|uniq`
    Info_Echo "Bios厂商" "${System_Bios_Vendor_Info}"
    Info_Echo "Bios版本" "${System_Bios_Version_Info}"
    Info_Echo "Bios发布时间" "${System_Bios_Release_Date_Info}"

    Info_Header "CPU硬件信息"
    CPU_Info=`cat /proc/cpuinfo`
    # CPU架构
    CPU_Arch_Info=`uname -m`
    # 物理CPU数量
    CPU_Physical_Sum_Info=`echo "${CPU_Info}"|grep "^physical id"| sort | uniq | wc -l`
    # CPU物理线程数
    CPU_Cores_Sum_Info=`echo "${CPU_Info}"|grep "^cpu cores"|uniq| awk -F':[[:space:]]' '{print $2}'`
    # CPU逻辑线程数
    CPU_Processor_Info=`echo "${CPU_Info}"|awk '/^processor/ {processor[$2]++} END { for (sum in processor) {print processor[sum]}}'`
    if [ "${CPU_Physical_Sum_Info}" = 0 -a "${CPU_Processor_Info}" -gt 0 -a -z "${CPU_Cores_Sum_Info}" ];then
        # CPU物理线程数
        CPU_Physical_Sum_Info=1
        CPU_Cores_Sum_Info=$CPU_Processor_Info
    fi
    Info_Echo "CPU架构类型" "${CPU_Arch_Info}"
    Info_Echo "物理CPU数量" "${CPU_Physical_Sum_Info}"
    Info_Echo "CPU总物理核心数" "${CPU_Physical_Sum_Info} * ${CPU_Cores_Sum_Info}"
    Info_Echo "CPU总逻辑线程数" "${CPU_Processor_Info}"
    # CPU物理ID列表
    CPU_Device_Physical_Id_List=`echo "${CPU_Info}"|awk -F':[[:space:]]' '/^physical id/ {print $2}'|sort |uniq`
    if [ -z "${CPU_Device_Physical_Id_List}" ];then
        Info_Echo "CPU硬件型号" "`echo "${CPU_Info}"|awk -F':[[:space:]]' '/^Hardware/ {print $2}'`"
    fi
    for CPU_Device_Physical_Id in ${CPU_Device_Physical_Id_List};do
        # CPU硬件信息
        CPU_Device_All_Info=`echo "${CPU_Info}"|grep -A 15 -B 9 "^physical id.*${CPU_Device_Physical_Id}"`
        # CPU设备型号
        CPU_Device_Model_Name_Info=`echo "${CPU_Device_All_Info}" |awk -F':[[:space:]]' '/^model name/ {print $2}'|sort|uniq`
        # CPU缓存大小
        CPU_Device_Cache_Size_Info=`echo "${CPU_Device_All_Info}" |awk -F':[[:space:]]' '/^cache size/ {print $2}'|sort|uniq`
        # CPU逻辑线程数
        CPU_Device_Siblings_Info=`echo "${CPU_Device_All_Info}" |awk -F':[[:space:]]' '/^siblings/ {print $2}'|sort|uniq`
        # CPU物理核心数
        CPU_Device_Cpu_Cores_Info=`echo "${CPU_Device_All_Info}" |awk -F':[[:space:]]' '/^cpu cores/ {print $2}'|sort|uniq`
        # CPU硬件查询
        CPU_Device_Processor_Info=`dmidecode -t processor|grep -v '[[:space:]][[:space:]]' |grep -A 22 -B2 "CPU.$((${CPU_Device_Physical_Id}+1))"|grep -B 30 "^$"`
        if [ -z "${CPU_Device_Processor_Info}" ];then
            # CPU硬件查询
            CPU_Device_Processor_Info=`dmidecode -t processor|grep -v '[[:space:]][[:space:]]' |grep -A 22 -B2 "CPU.$((${CPU_Device_Physical_Id}+1))"`
            if [ -z "${CPU_Device_Processor_Info}" ];then
                # CPU硬件查询
                CPU_Device_Processor_Info=`dmidecode -t processor|grep -v '[[:space:]][[:space:]]' |grep -A 22 -B2 "Socket.$((${CPU_Device_Physical_Id}+1))"`
                if [ -z "${CPU_Device_Processor_Info}" ];then
                    # CPU硬件查询
                    CPU_Device_Processor_Info=`dmidecode -t processor|grep -v '[[:space:]][[:space:]]' |grep -A 22 -B2 "CPU.${CPU_Device_Physical_Id}"`
                fi
            fi
        fi
        # CPU最大速率
        CPU_Device_Processor_Max_Speed=`echo "${CPU_Device_Processor_Info}" |awk -F':[[:space:]]' '/Max Speed:/ {print $2}'`
        # CPU当前速率
        CPU_Device_Processor_Current_Speed=`echo "${CPU_Device_Processor_Info}" |awk -F':[[:space:]]' '/Current Speed:/ {print $2}'`
        # CPU序列号
        CPU_Device_Processor_ID=`echo "${CPU_Device_Processor_Info}" |awk -F':[[:space:]]' '/[[:space:]]ID:/ {print $2}'`

        Info_Echo "CPU硬件型号" "${CPU_Device_Model_Name_Info}"
        Info_Echo_2 "CPU物理ID" "${CPU_Device_Physical_Id}"
        Check_If_Not_Code_Null "CPU序列号" "${CPU_Device_Processor_ID}"
        Info_Echo_2 "CPU缓存大小" "${CPU_Device_Cache_Size_Info}"
        Info_Echo_2 "CPU物理核心数" "${CPU_Device_Cpu_Cores_Info}"
        Info_Echo_2 "CPU逻辑线程数" "${CPU_Device_Siblings_Info}"
        Check_If_Not_Code_Null "CPU最大速率" "${CPU_Device_Processor_Max_Speed}"
        Check_If_Not_Code_Null "CPU当前速率" "${CPU_Device_Processor_Current_Speed}"
    done

    Info_Header "内存硬件信息"
    # 总内存数
    System_Memory_Total_Number=`awk -F":[[:space:]]" '/^MemTotal:/ {print $2}' /proc/meminfo|awk '{print $1/1024/1024}'`
    Info_Echo "当前内存" "${System_Memory_Total_Number} G"
    # 最大支持内存
    System_Memory_Maximum_Capacity=`dmidecode -t memory |awk -F':[[:space:]]' '/Maximum Capacity:/ {print $2}'|uniq`
    Info_Echo "最大支持内存" "${System_Memory_Maximum_Capacity}"
    # 内存条总插槽数
    System_Memory_Number_Of_Devices=`dmidecode -t memory |awk -F':[[:space:]]' '/Number Of Devices:/ {print $2}'|uniq`
    Info_Echo "内存条总插槽数" "${System_Memory_Number_Of_Devices}"
    # 内存条序列号列表
    Memory_Device_Serial_Number_List=`dmidecode -t memory |awk -F':[[:space:]]' '/Serial Number/{print $2}'|egrep -v 'NO[[:space:]]|_SerNum|Not'`
    # 内存条数量
    Memory_Device_Number=`echo "${Memory_Device_Serial_Number_List}"|wc -l`
    Info_Echo "已插内存条条数" "${Memory_Device_Number}"
    Old_IFS=$IFS
    IFS=$'\n'
    for Memory_Device_Serial_Number in ${Memory_Device_Serial_Number_List};do
        # 内存条硬件信息
        Memory_Device_Info=`dmidecode -t memory |grep -A '7' -B '15' "${Memory_Device_Serial_Number}"`
        # 存储大小
        Memory_Device_Size_Info=`echo "${Memory_Device_Info}"|awk -F':[[:space:]]' '/Size:/ {print $2}'`
        # 设备制造商
        Memory_Device_Manufacturer_Info=`echo "${Memory_Device_Info}"|awk -F':[[:space:]]' '/Manufacturer:/ {print $2}'`
        # 设备部件序号
        Memory_Device_Part_Number_Info=`echo "${Memory_Device_Info}"|awk -F':[[:space:]]' '/Part Number:/ {print $2}'`
        # 设备部件序号
        Memory_Device_Speed_Info=`echo "${Memory_Device_Info}"|awk -F':[[:space:]]' '/^[[:space:]]Speed:/ {print $2}'`
        Info_Echo "内存条序列号" "${Memory_Device_Serial_Number}"
        Info_Echo_2 "内存条频率" "${Memory_Device_Speed_Info}"
        Info_Echo_2 "内存条大小" "${Memory_Device_Size_Info}"
        Info_Echo_2 "内存条制造商" "${Memory_Device_Manufacturer_Info}"
        Info_Echo_2 "设备部件序号" "${Memory_Device_Part_Number_Info}"
    done
    IFS=$Old_IFS
    Info_Header "网卡硬件信息"
    # 网卡名称列表
    Network_Device_Name_List=`ls /sys/class/net/`
    for Network_Device_Name in ${Network_Device_Name_List};do
        Info_Echo "网卡设备名称" "${Network_Device_Name}"
        # 网卡设备信息
        Network_Device_Info=`ethtool ${Network_Device_Name} 2>&1`
        # 网卡开启状态
        Network_Device_Link_Detected_Info=`echo "${Network_Device_Info}"|awk -F':[[:space:]]' '/Link detected:/{print $2}'`
        # 网卡接口类型
        Network_Device_Port_Info=`echo "${Network_Device_Info}"|awk -F':[[:space:]]' '/Port:/{print $2}'`
        # 网卡工作速率
        Network_Device_Speed_Info=`echo "${Network_Device_Info}"|awk -F':[[:space:]]' '/Speed:/{print $2}'`
        # 网卡工作模式
        Network_Device_Duplex_Info=`echo "${Network_Device_Info}"|awk -F':[[:space:]]' '/Duplex:/{print $2}'`
        # 网卡设备驱动信息
        Network_Device_Driver_Info=`ethtool -i ${Network_Device_Name} 2>&1`
        # 网卡设备驱动类型
        Network_Device_Driver_Type_Info=`echo "${Network_Device_Driver_Info}"|awk -F':[[:space:]]' '/^driver:/{print $2}'`
        # 网卡设备驱动版本
        Network_Device_Driver_Version_Info=`echo "${Network_Device_Driver_Info}"|awk -F':[[:space:]]' '/^version:/{print $2}'`
        # 网卡设备总线信息
        Network_Device_Driver_Bus_Info_Info=`echo "${Network_Device_Driver_Info}"|awk -F':[[:space:]]' '/^bus-info:/{print $2}'|grep -Ev 'N/A|^tap'`
        Check_If_Not_Code_Null "网卡接口类型" "${Network_Device_Port_Info}"
        Check_If_Not_Code_Null "网卡工作模式" "${Network_Device_Duplex_Info}"
        Info_Echo_2 "网卡开启状态" "${Network_Device_Link_Detected_Info}"
        Check_If_Not_Code_Null "网卡工作速率" "${Network_Device_Speed_Info}"
        Check_If_Not_Code_Null "网卡驱动类型" "${Network_Device_Driver_Type_Info}"
        Check_If_Not_Code_Null "网卡驱动版本" "${Network_Device_Driver_Version_Info}"
        Check_If_Not_Code_Null "网卡总线信息" "${Network_Device_Driver_Bus_Info_Info}"

        if [ ! -z "${Network_Device_Driver_Bus_Info_Info}" ];then
            Network_Device_All_Info=`lspci -s "${Network_Device_Driver_Bus_Info_Info}" -vv 2>&1`
            # 网卡设备名称
            Network_Device_Name_Info=`echo "${Network_Device_All_Info}" |awk -F':[[:space:]]' '/Ethernet controller:/ {print $2}'`
            # 网卡设备序列号
            Network_Device_Device_Serial_Number_Info=`echo "${Network_Device_All_Info}" |awk -F'Device Serial Number[[:space:]]' '/Device Serial Number/ {print $2}'`
            Info_Echo_2 "网卡硬件型号" "${Network_Device_Name_Info}"
            Check_If_Not_Code_Null "网卡设备序列号" "${Network_Device_Device_Serial_Number_Info}"
        fi
    done
}


# 基础系统信息
System_Info(){
    Info_Header "系统信息"
    # 获取当前主机名
    Host_Name=`uname -n`
    # 操作系统
    Operating_System=`uname -o`
    # 系统内核
    System_Kernel=`uname -r`
    # 操作系统发行版本
    System_Release=`cat /etc/redhat-release`
    # SElinux状态
    SELinux_Status=`/usr/sbin/sestatus | awk '/^SELinux status:/ {print $3}'`
    # 系统启动时间
    System_Start=`who -b|awk '{print $3,$4}'`
    Info_Echo "主机名称" "${Host_Name}"
    Info_Echo "操作系统" "${Operating_System}"
    Info_Echo "系统内核" "${System_Kernel}"
    Info_Echo "发行版本" "${System_Release}"
    Info_Echo "SElinux状态" "${SELinux_Status}"
    Info_Echo "语言/编码" "${Old_LANG}"
    Info_Echo "启动时间" "${System_Start}"
}

# 网络信息
Network_Info(){
    Info_Header "网络信息"
    # 默认网卡名称
    Network_Device_Default_Name=`route -n |awk '/^0.0.0.0/ {print $8}'`
    # 获取外网IP
    External_Network_Address=`curl -s --connect-timeout 2 http://ip.42.pl/raw`
    Info_Echo "默认出口网卡" "${Network_Device_Default_Name}"
    Info_Echo "外网地址" "${External_Network_Address}"
    # DNS服务器地址
    Network_Resolv=`awk '/^nameserver/ {print $2}' /etc/resolv.conf| tr '\n' ',' | sed 's/,$//'`
    # 网关IP
    Network_Getway_Address=`route -n|awk '/^0/ {print $2}'`
    Info_Echo "DNS地址" "${Network_Resolv}"
    Info_Echo "网关地址" "${Network_Getway_Address}"
    # 网卡名称列表
    Network_Device_Name_List=`ls /sys/class/net/`
    for Network_Device_Name in ${Network_Device_Name_List};do
        Info_Echo "网卡名称" "${Network_Device_Name}"
        # 获取默认网卡IPv4&IPv6地址
        Domanin_Server_Ip_List=`ip addr show ${Network_Device_Name}|awk -F'[ ]+' '/inet/{print $3}' `
        for Domanin_Server_Ip in ${Domanin_Server_Ip_List};do
            Info_Echo_2 "本地地址" "${Domanin_Server_Ip}"
        done
    done
}

# SSH检查信息
SSH_Check_Info(){
    Info_Header "OpenSSH检查"
    # SSH服务版本
    Sshd_Service_Version=`ssh -V 2>&1|awk -F'[ ,]+' '{print $1}'`
    # SSH监听端口
    Sshd_Port=`sshd -T 2>&1|awk '/^port/ {print $2}'`
    # SSH允许远程ROOT登录
    Sshd_Permit_Root_Login=`sshd -T 2>&1|awk '/^permitrootlogin/ {print $2}'`
    # SSH运行状态
    Server_Sshd_Running_Status=`Check_Service_Status "sshd"`
    # SSH协议版本
    Sshd_Protocol_Version=`nc -v -i 0.01 127.0.0.1 ${Sshd_Port} 2>&1|awk -F'-' '/^SSH/{print $2}'`
    # SSH密码登陆
    Sshd_Password_Authentication=`sshd -T 2>&1|awk '/^passwordauthentication/ {print $2}'`
    # 信任主机配置
    Sshd_Authorized_Keys_File=`sshd -T 2>&1|awk '/^authorizedkeysfile/ {print $2}'`
    # 空密码登陆
    Sshd_Permit_Empty_Passwords=`sshd -T 2>&1|awk '/^permitemptypasswords/ {print $2}'`
    Info_Echo "SSHD服务版本" "${Sshd_Service_Version}"
    Info_Echo "SSHD运行状态" "${Server_Sshd_Running_Status}"
    Info_Echo "SSHD协议版本" "${Sshd_Protocol_Version}"
    Info_Echo "监听端口" "${Sshd_Port}"
    Info_Echo "ROOT远程登录" "${Sshd_Permit_Root_Login}"
    Info_Echo "SSH密码登陆" "${Sshd_Password_Authentication}"
    Info_Echo "空密码登陆" "${Sshd_Permit_Empty_Passwords}"
    Info_Echo "信任主机配置" "${Sshd_Authorized_Keys_File}"
    # 主机登陆用户列表
    Passwd_List_Info=`cat /etc/passwd`
     # 信任主机列表
     Sshd_Login_Bash_User_List=`echo "${Passwd_List_Info}"|awk -F':' '/\/bin\/bash/ {print $1}'`
     for Sshd_Login_Bash_User in ${Sshd_Login_Bash_User_List};do
         # 信任主机配置文件绝对路径
         Sshd_Authorize_File=`echo "${Passwd_List_Info}"|awk -F':' "/^${Sshd_Login_Bash_User}/ {print \\$6\"/${Sshd_Authorized_Keys_File}\"}"`
         if [ -f "${Sshd_Authorize_File}" ];then
             # 信任主机名称
            Sshd_Authorized_Host=`awk '{print $3}' $Sshd_Authorize_File 2>/dev/null | tr '\n' ',' | sed 's/,$//'`
            Check_If_Not_Code_Null "${Sshd_Login_Bash_User}免密授权" "${Sshd_Authorized_Host}"
        fi
    done
}


# 防火墙检查
Firewall_Check(){
    Info_Header "防火墙检查"
    # Firewalld版本
    Firewalld_Version=`firewall-cmd --version 2>&1`
    # Firewalld防火墙运行状态
    Server_Firewalld_Running_Status=`Check_Service_Status "firewalld"`
    # Firewalld默认节点
    Firewalld_Default_Zone=`firewall-cmd --get-default-zone 2>&1`
    # Firewalld地址伪装功能
    Firewalld_Masquerade=`firewall-cmd --zone=${Firewalld_Default_Zone} --list-all 2>&1|awk -F':[[:space:]]' '/masquerade:/ {print $2}'`
    Info_Echo "Firewalld防火墙运行状态" "${Server_Firewalld_Running_Status}"
    if [ "${Server_Firewalld_Running_Status}" = 'active' ];then
        Info_Echo "Firewalld版本" "${Firewalld_Version}"
        Check_If_Not_Code_Null "Firewalld地址伪装功能" "${Firewalld_Masquerade}"
        Info_Echo "Firewalld默认节点" "${Firewalld_Default_Zone}"
        # Firewalld服务端口
        Firewalld_Ports_List=`firewall-cmd --zone=${Firewalld_Default_Zone} --list-ports 2>&1`
        Check_If_Not_Code_Null "Firewalld开放端口" "${Firewalld_Ports_List}"
        # Firewalld高级规则
        Firewalld_Rich_Rules_List=`firewall-cmd --zone=${Firewalld_Default_Zone} --list-rich-rules 2>&1`
        Old_IFS=$IFS
        IFS=$'\n'
        for Firewalld_Rich_Rules in ${Firewalld_Rich_Rules_List};do
            Info_Echo_2 "Firewalld高级规则" "${Firewalld_Rich_Rules}"
        done
        # 还原分隔符
        IFS=$Old_IFS
    fi
    # IPtables_版本
    IPtables_Version=`iptables --version 2>&1|awk '{print $2}'`
    # iptables防火墙运行状态
    Server_IPtables_Running_Status=`Check_Service_Status "iptables"`
    # Input列表
    IPtables_Input_List=`iptables -n -L INPUT 2>&1`
    # Input开放列表
    IPtables_Input_ACCEPT_List=`echo "${IPtables_Input_List}" |awk -F'[ :.]+' '/^ACCEPT/ {if ($4 == "0"){print}}'`
    # IPtables开放端口
    IPtables_Input_ACCEPT_Port=`echo "${IPtables_Input_ACCEPT_List}"|awk -F'[[:space:]]dpt:' '{print $2}'|sort |uniq|grep -v '^$'| tr '\n' ',' | sed 's/,$//'`
    # IPtables开放端口范围
    IPtables_Input_ACCEPT_Ports=`echo "${IPtables_Input_ACCEPT_List}"|awk -F'[[:space:]]dpts:' '{print $2}'|sort |uniq|grep -v '^$'| tr '\n' ',' | sed 's/,$//'`
    Info_Echo "IPtables版本" "${IPtables_Version}"
    Info_Echo "IPtables防火墙运行状态" "${Server_IPtables_Running_Status}"
    Check_If_Not_Code_Null "IPtables开放端口" "${IPtables_Input_ACCEPT_Port}"
    Check_If_Not_Code_Null "IPtables开放端口范围" "${IPtables_Input_ACCEPT_Ports}"
}

# JAVA检查
Java_Check(){
    Info_Header "JAVA检查"
    # 检查java是否部署
    Check_Java_Install_Info=`which java 2>&1`
    if [[ "${Check_Java_Install_Info}" =~ "which: no" || -z "${Check_Java_Install_Info}" ]];then
        Check_Java_Install_Info_D='未部署'
    else
        Check_Java_Install_Info_D='已部署'
    fi
    # JAVA版本
    Java_Version=`java -version 2>&1|awk -F'[ "]+' '/version/ {print $3}'`
    Info_Echo "JAVA状态" "${Check_Java_Install_Info_D}"
    Check_If_Not_Code_Null "JAVA版本" "${Java_Version}"
    Check_If_Not_Code_Null "JAVA家目录" "${JAVA_HOME}"
}

# Sudoers检查
Sudoers_Check(){
    Info_Header "Sudoers检查"
    # Sudoers配置文件
    Sudoers_Conf_Info=`egrep -v "^#|Defaults|^$" /etc/sudoers`
    Old_IFS=$IFS
    IFS=$'\n'
    for Sudoers_Conf in ${Sudoers_Conf_Info};do
        # 授权用户
        Sudoers_User=`echo "${Sudoers_Conf}"|awk '{print $1}'`
        # 授权主机
        Sudoers_Host=`echo "${Sudoers_Conf}"|awk '{print $2}'`
        # 授权命令
        Sudoers_Order=`echo "${Sudoers_Conf}"|awk '{print $3}'`
        # 授权类型
        Sudoers_Order_T=`echo "${Sudoers_Order}"|awk -F':' '{print $1}'`
        # 授权命令列表
        Sudoers_Order_D_List=`echo "${Sudoers_Order}"|awk -F':' '{print $2}'|sed -n 's/,/\n/gp'`
        if [ -z "${Sudoers_Order_T}" ];then
            Sudoers_Order_T=$Sudoers_Order
        fi
        Info_Echo "授权用户" "${Sudoers_User}"
        Info_Echo_2 "授权主机" "${Sudoers_Host}"
        Info_Echo_2 "授权类型" "${Sudoers_Order_T}"
        for Sudoers_Order_D in ${Sudoers_Order_D_List};do
            Info_Echo_2 "授权命令" "${Sudoers_Order_D}"
        done
    done
    # 还原分隔符
    IFS=$Old_IFS
}

# 端口监听检查
Port_Answer_Check(){
    Info_Header "端口监听检查"
    # 端口接听列表
    Network_Answer_Port_Info_List=`ss -ntxulp | column -t|awk 'NR>1'`
    Old_IFS=$IFS
    IFS=$'\n'
    for Network_Answer_Port_Info in ${Network_Answer_Port_Info_List};do
        # 网络监听类型
        Network_Answer_Type=`echo "${Network_Answer_Port_Info}"|awk '{print $1}'`
        # 网络监听状态
        Network_Answer_Status=`echo "${Network_Answer_Port_Info}"|awk '{print $2}'`
        # 本地地址及端口
        Network_Answer_Local_Port=`echo "${Network_Answer_Port_Info}"|awk '{print $5}'`
        # 对端地址及端口
        Network_Answer_Peer_Address_Port=`echo "${Network_Answer_Port_Info}"|awk '{print $6}'`
        if [ "${Network_Answer_Type}" = 'tcp' -o "${Network_Answer_Type}" = 'udp' ];then
            # 显示监听端口的进程
            Network_Answer_Peer_Process_Info=`echo "${Network_Answer_Port_Info}"|awk '{print $7}'`
        else
            # 显示监听端口的进程
            Network_Answer_Peer_Process_Info=`echo "${Network_Answer_Port_Info}"|awk '{print $9}'`
        fi
        # 监听端口服务
        Network_Answer_Peer_Process_Command=`echo "${Network_Answer_Peer_Process_Info}"|awk -F'[ ",=)]+' '{print $2}'`
        # 监听进程Pid
        Network_Answer_Peer_Process_Pid=`echo "${Network_Answer_Peer_Process_Info}"|awk -F'[ ",=)]+' '{print $4}'`
        Network_Answer_Peer_Process_Fd=`echo "${Network_Answer_Peer_Process_Info}"|awk -F'[ ",=)]+' '{print $6}'`
        Info_Echo "本地地址及端口" "${Network_Answer_Local_Port}"
        Info_Echo_2 "网络监听类型" "${Network_Answer_Type}"
        Info_Echo_2 "监听端口服务" "${Network_Answer_Peer_Process_Command}"
        Info_Echo_2 "监听进程Pid" "${Network_Answer_Peer_Process_Pid}"
        Info_Echo_2 "网络监听状态" "${Network_Answer_Status}"
        Info_Echo_2 "对端地址及端口" "${Network_Answer_Peer_Address_Port}"
    done
    # 还原分隔符
    IFS=$Old_IFS
}

# 自启动检查
Auto_Start_Check(){
    Info_Header "自启动检查"
    rc_File_List=`find /etc/rc.d/ -type f`
    IFS=$'\n'
    Old_IFS=$IFS
    for Up_File in $rc_File_List;do
        if [ -f "${Up_File}" ];then
            # 本地自启动信息
            Local_Start_List=`egrep -v '^#|^$' "${Up_File}"`
            Info_Echo "自启动文件" "${Up_File}"
            for Local_Start in ${Local_Start_List};do
                Info_Echo_2 "启动命令" "${Local_Start}"
            done
        fi
    done
    # 还原分隔符
    IFS=$Old_IFS
}

# 用户登陆检查
User_Login_Check(){
    Info_Header "用户登陆检查"
    # 历史登陆用户信息
    History_Login_User_Info_List=`who /var/log/wtmp|tail`
    Old_IFS=$IFS
    IFS=$'\n'
    for History_Login_User_Info in ${History_Login_User_Info_List};do
        #echo "${History_Login_User_Info}"
        # 历史登陆用户名称
        History_Login_User_Name=`echo "${History_Login_User_Info}"|awk '{print $1}'`
        # 历史登陆窗口
        History_Login_Window=`echo "${History_Login_User_Info}"|awk '{print $2}'`
        # 历史登陆时间
        History_Login_Date=`echo "${History_Login_User_Info}"|awk '{print $3,$4}'`
        # 历史登陆IP
        History_Login_Address=`echo "${History_Login_User_Info}"|awk -F'[()]+' '{print $2}'`
        Info_Echo "登陆用户" "${History_Login_User_Name}"
        Info_Echo_2 "历史登陆窗口" "${History_Login_Window}"
        Info_Echo_2 "历史登陆时间" "${History_Login_Date}"
        Info_Echo_2 "历史登陆地址" "${History_Login_Address}"
    done
    # 还原分隔符
    IFS=$Old_IFS
}

# 软件包安装检查
Packages_Install_Check(){
    Info_Header "软件包安装检查"
    Packages_Install_Info_List=`rpm -qa --last | head | column -t|awk '{print $1}'`
    Old_IFS=$IFS
    IFS=$'\n'
    for Packages_Install_Info in ${Packages_Install_Info_List};do
        # 软件安装时间
        Packages_Install_Date=`rpm -qi "${Packages_Install_Info}"|awk -F':[[:space:]]' '/^Install Date/ {print $2}'|sed -r 's/[[:space:]]Build.*//g'|xargs -i date -d "{}" "+%Y-%m-%d %H:%M:%S"`
        # 软件打包时间
        Packages_Build_Date=`rpm -qi "${Packages_Install_Info}"|awk -F':[[:space:]]' '/^Build Date/ {print $2}'`
        Info_Echo "安装包" "${Packages_Install_Info}"
        Info_Echo_2 "软件安装时间" "${Packages_Install_Date}"
        Info_Echo_2 "软件打包时间" "${Packages_Build_Date}"
    done
    # 还原分隔符
    IFS=$Old_IFS
}

# 计划任务检查
Scheduled_Task_Check(){
    Info_Header "计划任务检查"
    # 系统登陆SHELL列表
     System_Login_Shell_List=`grep -Ev "/sbin/nologin|^#|^$" /etc/shells|sed -n 's#/#\\\/#gp'`
     for System_Login_Shell in ${System_Login_Shell_List};do
         System_Login_User_List=`awk -F':' "/${System_Login_Shell}/ {print \\$1}" /etc/passwd`
         for System_Login_User in ${System_Login_User_List};do
             System_User_Crontab_List=`crontab -l -u "${System_Login_User}" 2>/dev/null|grep -v '^#'`
             if [ ! -z "${System_User_Crontab_List}" ];then
                Info_Echo "用户" "${System_Login_User}"
                Old_IFS=$IFS
                IFS=$'\n'
                for System_User_Crontab in ${System_User_Crontab_List};do
                    Info_Echo_2 "生效任务" "${System_User_Crontab}"
                done
                # 还原分隔符
                IFS=$Old_IFS
             fi
         done
     done
     # 检索计划任务配置文件
     # find /etc/cron* -type f | xargs -i ls -l {} | column -t
}

# 服务检查
System_Service_Check(){
    Info_Header "自启服务检查"
    if [[ "${System_Release_D}" -eq 7 ]];then
        # 开机启动的服务列表
        System_Enable_Service_Info_List=`systemctl list-unit-files --type=service --state=enabled --no-pager | awk '/.service/ {print $1}'`
        # 运行的服务列表
        System_Running_Service_Info_List=`systemctl list-units --type=service --state=running --no-pager | awk '/.service/ {print $1}'`
    else
        # 开机启动的服务列表
        System_Enable_Service_Info_List=$(/sbin/chkconfig | grep -E ":on|:启用"|awk '{print $1}')
        # 运行的服务列表
        System_Running_Service_Info_List=`/sbin/service --status-all 2>/dev/null | grep -E "is running|正在运行"|awk '{print $1}'`
    fi
        for System_Enable_Service_Info in ${System_Enable_Service_Info_List};do
            Info_Echo "服务 ${System_Enable_Service_Info/.service} 状态" "Enabled"
        done
        Info_Header "运行服务检查"
        for System_Running_Service_Info in ${System_Running_Service_Info_List};do
            Info_Echo "服务 ${System_Running_Service_Info/.service} 状态" "Running"
        done
}

# 服务进程检查
Service_Process_Check(){
    Info_Header "服务进程检查"
    # 僵尸进程
    Zombie_Process_Check_Sum=`ps -ef | grep defunct | grep -v grep | wc -l`
    Info_Echo "僵尸进程数量" "${Zombie_Process_Check_Sum}"

    Info_Header "内存占用前10"
    # 内存占用前10
    Process_Memory_Info_List=`ps ax -o ruser=userForLongName -e -o pid,%mem,rss,start,time,command| sort -k3rn | head -n 10`
    Old_IFS=$IFS
    IFS=$'\n'
    for Process_Memory_Info in ${Process_Memory_Info_List};do
        # 进程PID
        Process_Memory_Pid=`echo "${Process_Memory_Info}"|awk '{print $2}'`
        # 程序运行路径
        Process_Running_Path=`lsof -p ${Process_Memory_Pid} -a -d txt +c 15|awk 'NR>1 {print $9}'`
        # 进程名称
        Process_Memory_Command=`lsof -p ${Process_Memory_Pid} -a -d txt +c 15|awk 'NR>1 {print $1}'`
        # 运行用户
        Process_Memory_Running_User=`echo "${Process_Memory_Info}"|awk '{print $1}'`
        # 内存使用率
        Process_Memory_Use_Rate=`echo "${Process_Memory_Info}"|awk '{print $3}'`
        # 物理内存使用
        Process_Memory_RSS=`echo "${Process_Memory_Info}"|awk '{print $4}'`
        # 运行时间
        Process_Memory_Time=`echo "${Process_Memory_Info}"|awk '{print $5,$6,$7}'`
        Process_Memory_Time_1=`echo "${Process_Memory_Time}"|grep '^[0-9]'`
        if [ -z "${Process_Memory_Time_1}" ];then
            Process_Memory_Time=`echo "${Process_Memory_Time}"|xargs -i date -d "{}" "+%Y-%m-%d %H:%M:%S"`

        else
            # 进程运行时间
            Process_Memory_Time=`echo "${Process_Memory_Info}"|awk '{print $5}'|xargs -i date "+%Y-%m-%d {}"`

        fi
        Info_Echo "运行PID" "${Process_Memory_Pid}"
        Info_Echo_2 "运行用户" "${Process_Memory_Running_User}"
        Info_Echo_2 "运行时间" "${Process_Memory_Time}"
        Info_Echo_2 "内存使用率" "${Process_Memory_Use_Rate}%"
        Info_Echo_2 "物理内存使用" "$((${Process_Memory_RSS}/1024))M"
        Info_Echo_2 "进程名称" "${Process_Memory_Command}"
        Info_Echo_2 "程序运行路径" "${Process_Running_Path}"
    done
    # 还原分隔符
    IFS=$Old_IFS
    Info_Header "CPU占用前10"
    # CPU占用前10
    Process_CPU_Info_List=`ps ax -o ruser=userForLongName -e -o pid,%cpu,start,time,command| sort -k3rn | head -n 10`
    Old_IFS=$IFS
    IFS=$'\n'
    for Process_CPU_Info in ${Process_CPU_Info_List};do
        # 运行PID
        Process_CPU_Pid=`echo "${Process_CPU_Info}"|awk '{print $2}'`
        # 程序运行路径
        Process_Running_Path=`lsof -p ${Process_CPU_Pid} -a -d txt +c 15|awk 'NR>1 {print $9}'`
        # 进程名称
        Process_CPU_Command=`lsof -p ${Process_CPU_Pid} -a -d txt +c 15|awk 'NR>1 {print $1}'`
        # 运行用户
        Process_CPU_User=`echo "${Process_CPU_Info}"|awk '{print $1}'`
        # CPU使用率
        Process_CPU_Use_Rate=`echo "${Process_CPU_Info}"|awk '{print $3}'`
        # 进程运行时间
        Process_CPU_Running_Time=`echo "${Process_CPU_Info}"|awk '{print $4,$5,$6}'`
        Process_CPU_Running_Time_1=`echo "${Process_CPU_Running_Time}"|grep '^[0-9]'`
        if [ -z "${Process_CPU_Running_Time_1}" ];then
            Process_CPU_Running_Time=`echo "${Process_CPU_Running_Time}"|xargs -i date -d "{}" "+%Y-%m-%d %H:%M:%S"`
        else
            # 进程运行时间
            Process_CPU_Running_Time=`echo "${Process_CPU_Info}"|awk '{print $4}'|xargs -i date "+%Y-%m-%d {}"`
        fi
        Info_Echo "运行PID" "${Process_CPU_Pid}"
        Info_Echo_2 "运行用户" "${Process_CPU_User}"
        Info_Echo_2 "进程运行时间" "${Process_CPU_Running_Time}"
        Info_Echo_2 "CPU使用率" "${Process_CPU_Use_Rate}%"
        Info_Echo_2 "进程名称" "${Process_CPU_Command}"
        Info_Echo_2 "程序运行路径" "${Process_Running_Path}"
    done
    # 还原分隔符
    IFS=$Old_IFS
}

# SNMP服务检查
SNMP_Service_Check(){
    Info_Header "SNMP服务检查"
    # SNMP服务状态
    SNMP_Service_Status=`Check_Service_Status snmpd`
    Info_Echo "服务状态：" "${SNMP_Service_Status}"
    #if [ -e /etc/snmp/snmpd.conf ];then
    #    echo "/etc/snmp/snmpd.conf"
    #    echo "--------------------"
    #    cat /etc/snmp/snmpd.conf 2>/dev/null | grep -v "^#" | sed '/^$/d'
    #fi
}

# NTP服务检查
NTP_Service_Check(){
    Info_Header "NTP服务检查"
    # ntpd服务状态
    Ntpd_Service_Status=`Check_Service_Status ntpd`
    Info_Echo "服务状态：" "${Ntpd_Service_Status}"
    #if [ -e /etc/ntp.conf ];then
    #    echo "/etc/ntp.conf"
    #    echo "-------------"
    #    egrep -v '^#|^$' /etc/ntp.conf
    #fi
}

# Syslog服务检查
Syslog_Service_Check(){
    Info_Header "Syslog服务检查"
    # ntpd服务状态
    Rsyslog_Service_Status=`Check_Service_Status rsyslog`
    Info_Echo "服务状态：" "${Rsyslog_Service_Status}"
    #echo "/etc/rsyslog.conf"
    #echo "-----------------"
    #cat /etc/rsyslog.conf 2>/dev/null | grep -v "^#" | grep -v "^\\$" | sed '/^$/d' | column -t
}

# 用户密码检查
User_Passwd_Check(){
    Info_Header "密码过期检查"
    # 系统密码
    Passwd_List_Info=`cat /etc/passwd`

    # 系统登陆SHELL列表
     System_Login_Shell_List=`grep -Ev "/sbin/nologin|^#|^$" /etc/shells|sed -n 's#/#\\\/#gp'`
     for System_Login_Shell in ${System_Login_Shell_List};do
         System_Login_User_List=`awk -F':' "/${System_Login_Shell}/ {print \\$1}" /etc/passwd`
         for System_Login_User in ${System_Login_User_List};do
            Get_User_Expiry_Date=$(/usr/bin/chage -l $System_Login_User | awk -F':[[:space:]]' '/Password expires/{print $2}')
            if [[ ${Get_User_Expiry_Date} = 'never' ]];then
                Info_Echo_2 "${System_Login_User}" "永不过期"
            else
                password_expiry_date=$(date -d "${Get_User_Expiry_Date}" "+%s")
                current_date=$(date "+%s")
                diff=$(($password_expiry_date-$current_date))
                let DAYS=$(($diff/(60*60*24)))
                Info_Echo_2 "${System_Login_User}" "${DAYS}天后过期"
            fi
         done
     done
    Info_Header "密码策略检查"
    Info_Echo "最晚过期天数" "`awk '/^PASS_MAX_DAYS/ {print $2}' /etc/login.defs`"
    Info_Echo "最早过期天数" "`awk '/^PASS_MIN_DAYS/ {print $2}' /etc/login.defs`"
    Info_Echo "最短密码长度" "`awk '/^PASS_MIN_LEN/ {print $2}' /etc/login.defs`"
    Info_Echo "密码过期提醒" "`awk '/^PASS_WARN_AGE/ {print $2}' /etc/login.defs`"
}

# 用户信息检查
User_Info_Check(){
    Info_Header "用户信息检查"
    # 主机登陆用户列表
    Passwd_List_Info=`cat /etc/passwd`
    Root_User_List=`echo "${Passwd_List_Info}"|awk -F':' '{if($3 == 0){print $1}}'| tr '\n' ',' | sed 's/,$//'`
    Info_Echo "特权用户" "${Root_User_List}"
    Info_Header "空密码用户检查"
    # 系统登陆SHELL列表
     System_Login_Shell_List=`grep -Ev "/sbin/nologin|^#|^$" /etc/shells|sed -n 's#/#\\\/#gp'`
     for System_Login_Shell in ${System_Login_Shell_List};do
         System_Login_User_List=`awk -F':' "/${System_Login_Shell}/ {print \\$1}" /etc/passwd`
         for System_Login_User in ${System_Login_User_List};do
             # 系统登录用户名称
            System_Login_User_Name=`awk -F: "/${System_Login_User}/  {if(\\$2 == \"!!\"){print \\$1}}" /etc/shadow`
            Check_If_Not_Code_Null "空密码用户" "${System_Login_User_Name}"
         done
     done

    Info_Header "相同用户UID检查"
    # 重复用户ID列表
    System_Login_User_ID_List=`cut -d: -f3 /etc/passwd | sort | uniq -c | awk '$1>1{print $2}'`
    for System_Login_User_ID in $System_Login_User_ID_List;do
        # 用户名称列表
        System_Login_User_Name=$(awk -F: 'ORS="";$3=='"$System_Login_User_ID"'{print "",$1}' /etc/passwd)
        Info_Echo "用户名ID ${System_Login_User_ID}" "${System_Login_User_Name}"
    done

    Info_Header "用户列表"
    # 系统登陆SHELL列表
     System_Login_Shell_List=`grep -Ev "/sbin/nologin|^#|^$" /etc/shells|sed -n 's#/#\\\/#gp'`
     for System_Login_Shell in ${System_Login_Shell_List};do
         # 系统用户列表
         System_Login_User_List=`awk -F':' "/${System_Login_Shell}/ {print \\$1}" /etc/passwd`
         for System_Login_User in ${System_Login_User_List};do
             # 系统用户最后登录时间
            System_User_Last_Login="$(who --users /var/log/wtmp|awk "/^${System_Login_User}[[:space:]]/ {print \$3,\$4}"|tail -n1)"
            if [ -z "${System_User_Last_Login}" ];then
                System_User_Last_Login="No Last Login"
            fi
            # 用户ID
            System_User_Uid=`echo "${Passwd_List_Info}"|awk -F':' "/^${System_Login_User}:/ {print \\$3}"`
            # 用户组ID
            System_User_Group_Uid=`echo "${Passwd_List_Info}"|awk -F':' "/^${System_Login_User}:/ {print \\$4}"`
            # 用户组名称
            System_User_Group_Name=`awk -F':' "{if (\\$3 == ${System_User_Group_Uid}){print \\$1}}" /etc/group`
            # 用户家目录
            System_User_Home_Path=`echo "${Passwd_List_Info}"|awk -F':' "/^${System_Login_User}:/ {print \\$6}"`
            Info_Echo "用户名称" "${System_Login_User}"
            Info_Echo_2 "用户ID" "${System_User_Uid}"
            Info_Echo_2 "用户家目录" "${System_User_Home_Path}"
            Info_Echo_2 "用户SHELL" "`echo "${System_Login_Shell}"|sed -n 's#\\\/#/#gp'`"
            Info_Echo_2 "最后登录时间" "${System_User_Last_Login}"
            Info_Echo_2 "用户组名称" "${System_User_Group_Name}"
            Info_Echo_2 "用户组ID" "${System_User_Group_Uid}"
        done
    done
}

# 磁盘检查
Get_Disk_Check(){
    Info_Header "磁盘检查"
    #查看已挂载磁盘空间剩余
    Disk_Info=`df -TP`
    #查看磁盘信息
    Disk_Info_Name=`echo "${Disk_Info}" |awk '/^\// {print $1}'`
    for Disk_Name in $Disk_Info_Name;do
        # 磁盘分区
        Disk_Name_D=`echo "${Disk_Name}"|sed -n 's#/#\\\/#gp'`
        # 可用率
        Disk_Info_D=`echo "${Disk_Info}" |awk "/${Disk_Name_D}/ {print \\$5/\\$3*100}" |awk -F. '{print $1}'`
        # 分区大小
        Disk_Size=`echo "${Disk_Info}" |awk "/${Disk_Name_D}/ {print \\$3/1024/1024}"`
        # 磁盘可用
        Disk_Size_Available=`echo "${Disk_Info}" |awk "/${Disk_Name_D}/ {print \\$5/1024/1024}"`
        Info_Echo "磁盘分区" "${Disk_Name}"
        Info_Echo_2 "分区大小" "${Disk_Size}G"
        Info_Echo_2 "剩余可用率" "${Disk_Info_D}%"
        Info_Echo_2 "可用空间" "${Disk_Size_Available}G"
    done
    #df -hiP | sed 's/Mounted on/Mounted/'> /tmp/inode
    #df -hTP | sed 's/Mounted on/Mounted/'> /tmp/disk
    #join /tmp/disk /tmp/inode | awk '{print $1,$2,"|",$3,$4,$5,$6,"|",$8,$9,$10,$11,"|",$12}'| column -t
}

# 内存检查
Memory_Check(){
    Info_Header "内存使用检查"
    System_Memory_Info=`cat /proc/meminfo`
    # 总内存大小
    System_Memory_Total_Number=`echo "${System_Memory_Info}"|awk -F":[[:space:]]" '/^MemTotal:/ {print $2}'|awk '{print $1/1024/1024}'`
    # 剩余内存
    System_Memory_Free_Number=`echo "${System_Memory_Info}"|awk -F":[[:space:]]" '/^MemFree:/ {print $2}'|awk '{print $1/1024}'`
    # 已使用内存
    System_Memory_Use_Number=`echo|awk "{print ${System_Memory_Total_Number}-(${System_Memory_Free_Number}/1024)}"`
    # 可用内存
    System_Memory_Available_Number=`echo "${System_Memory_Info}"|awk -F":[[:space:]]" '/^MemAvailable:/ {print $2}'|awk '{print $1/1024}'`

    # 内核页缓存使用
    System_Memory_Cached_Number=`echo "${System_Memory_Info}"|awk -F":[[:space:]]" '/^Cached:/ {print $2}'|awk '{print $1/1024}'`
    # 内核缓冲区使用
    System_Memory_Buffers_Number=`echo "${System_Memory_Info}"|awk -F":[[:space:]]" '/^Buffers:/ {print $2}'|awk '{print $1/1024}'`
    # Slab可回收内存 SUnreclaim部分板坯，可能被收回，如高速缓存。
    System_Memory_SReclaimable_Number=`echo "${System_Memory_Info}"|awk -F":[[:space:]]" '/^SReclaimable:/ {print $2}'|awk '{print $1/1024}'`
    # 缓存区总和
    System_Memory_Cached_Buffers_SReclaimable_Number=`echo|awk "{print ${System_Memory_Cached_Number}+${System_Memory_Buffers_Number}+${System_Memory_SReclaimable_Number}}"`
    # Slab不可回收内存 
    System_Memory_SUnreclaim_Number=`echo "${System_Memory_Info}"|awk -F":[[:space:]]" '/^SUnreclaim:/ {print $2}'|awk '{print $1/1024}'`

    # 交换分区总大小
    System_Memory_Swap_Total_Number=`echo "${System_Memory_Info}"|awk -F":[[:space:]]" '/^SwapTotal:/ {print $2}'|awk '{print $1/1024}'`
    # 交换分区剩余内存
    System_Memory_Swap_Free_Number=`echo "${System_Memory_Info}"|awk -F":[[:space:]]" '/^SwapFree:/ {print $2}'|awk '{print $1/1024}'`
    # 交换分区已使用内存
    System_Memory_Swap_Use_Number=`echo|awk "{if(${System_Memory_Swap_Total_Number}-${System_Memory_Swap_Free_Number} != 0){print ${System_Memory_Swap_Total_Number}-(${System_Memory_Swap_Free_Number}/1024)}else{print 0}}"`
    # 交换分区缓存
    System_Memory_Swap_Cached_Number=`echo "${System_Memory_Info}"|awk -F":[[:space:]]" '/^SwapCached:/ {print $2}'|awk '{print $1/1024}'`
    Info_Echo "总内存大小" "${System_Memory_Total_Number}G"
    Info_Echo_2 "已使用内存" "${System_Memory_Use_Number}G"
    Info_Echo_2 "剩余内存" "${System_Memory_Free_Number}M"
    Check_If_Not_Code_Null "可用内存" "${System_Memory_Available_Number}"

    Info_Echo "缓存区总和" "${System_Memory_Cached_Buffers_SReclaimable_Number}M"
    Info_Echo_2 "内核页缓存使用" "${System_Memory_Cached_Number}M"
    Info_Echo_2 "内核缓冲区使用" "${System_Memory_Buffers_Number}M"
    Info_Echo_2 "Slab可回收内存" "${System_Memory_SReclaimable_Number}M"
    Info_Echo_2 "Slab不可回收" "${System_Memory_SUnreclaim_Number}M"
    Info_Echo "交换分区总大小" "${System_Memory_Swap_Total_Number}M"
    Info_Echo_2 "交换分区剩余内存" "${System_Memory_Swap_Free_Number}M"
    Info_Echo_2 "交换分区已使用内存" "${System_Memory_Swap_Use_Number}G"
    Info_Echo_2 "交换分区缓存" "${System_Memory_Swap_Cached_Number}G"
}

Cpu_Check(){
    Info_Header "CPU使用检查"
    #默认时间间隔
    TIME_INTERVAL=1
    # 上一次系统CPU全部使用信息
    Last_System_CPU_Usage_Total_Info=`awk '/^cpu[0-9]{0,9}[[:space:]]/ {print $1,$2,$3,$4,$5,$6,$7,$8}' /proc/stat`
    sleep ${TIME_INTERVAL}
    # 新的系统CPU全部使用信息
    New_System_CPU_Usage_Total_Info=`awk '/^cpu[0-9]{0,9}[[:space:]]/ {print $1,$2,$3,$4,$5,$6,$7,$8}' /proc/stat`
    # 系统CPU核心名称列表
    System_CPU_Name_List=`awk '/^cpu/ {print $1}' /proc/stat`
    for System_CPU_Name in ${System_CPU_Name_List};do
        # 上一次系统CPU使用信息
        Last_System_CPU_Usage_Info=`echo "${Last_System_CPU_Usage_Total_Info}"|awk "/^${System_CPU_Name}[[:space:]]/ {print \\$2,\\$3,\\$4,\\$5,\\$6,\\$7,\\$8}"`
        # 从系统启动开始累计到当前时刻，nice值为负的进程所占用的CPU时间（单位：jiffies）
        Last_System_CPU_USER_BUSY=$(echo $Last_System_CPU_Usage_Info | awk '{print $1}')
        # 从系统启动开始累计到当前时刻，除硬盘IO等待时间以外其它等待时间（单位：jiffies）
        Last_System_CPU_SYS_BUSY=$(echo $Last_System_CPU_Usage_Info | awk '{print $3}')
        # 从系统启动开始累计到当前时刻，硬盘IO等待时间（单位：jiffies）
        Last_System_CPU_SYS_IDLE=$(echo $Last_System_CPU_Usage_Info | awk '{print $4}')
        # CPU时间
        Last_System_CPU_TOTAL_CPU_T=$(echo $Last_System_CPU_Usage_Info | awk '{print $1+$2+$3+$4+$5+$6+$7}')
        # CPU使用
        Last_System_CPU_CPU_USAGE=$(echo $Last_System_CPU_Usage_Info | awk '{print $1+$2+$3}')

        # 新的系统CPU使用信息
        New_System_CPU_Usage_Info=`echo "${New_System_CPU_Usage_Total_Info}"|awk "/^${System_CPU_Name}[[:space:]]/ {print \\$2,\\$3,\\$4,\\$5,\\$6,\\$7,\\$8}"`
        # 从系统启动开始累计到当前时刻，nice值为负的进程所占用的CPU时间（单位：jiffies）
        New_System_CPU_USER_BUSY=$(echo $New_System_CPU_Usage_Info | awk '{print $1}')
        # 从系统启动开始累计到当前时刻，除硬盘IO等待时间以外其它等待时间（单位：jiffies）
        New_System_CPU_SYS_BUSY=$(echo $New_System_CPU_Usage_Info | awk '{print $3}')
        # 从系统启动开始累计到当前时刻，硬盘IO等待时间（单位：jiffies）
        New_System_CPU_SYS_IDLE=$(echo $New_System_CPU_Usage_Info | awk '{print $4}')
        # CPU时间
        New_System_CPU_TOTAL_CPU_T=$(echo $New_System_CPU_Usage_Info | awk '{print $1+$2+$3+$4+$5+$6+$7}')
        # CPU使用
        New_System_CPU_CPU_USAGE=$(echo $New_System_CPU_Usage_Info | awk '{print $1+$2+$3}')

        # 系统空闲时间
        SYSTEM_IDLE=`echo ${New_System_CPU_SYS_IDLE} ${Last_System_CPU_SYS_IDLE} | awk '{print $1-$2}'`
        # 系统使用时间
        SYSTEM_BUSY=`echo ${New_System_CPU_SYS_BUSY} ${Last_System_CPU_SYS_BUSY} | awk '{print $1-$2}'`
        # 用户使用时间
        USER_BUSY=`echo ${New_System_CPU_USER_BUSY} ${Last_System_CPU_USER_BUSY} | awk '{print $1-$2}'`
        # 用户+系统+nice时间
        TOTAL_BUSY=`echo ${New_System_CPU_CPU_USAGE} ${Last_System_CPU_CPU_USAGE} | awk '{print $1-$2}'`
        # CPU总时间
        TOTAL_TIME=`echo ${New_System_CPU_TOTAL_CPU_T} ${Last_System_CPU_TOTAL_CPU_T} | awk '{print $1-$2}'`

        # CPU总时间百分比
        CPU_USAGE=`echo ${TOTAL_BUSY} ${TOTAL_TIME} | awk '{printf "%.2f", $1/$2*100}'`
        # 用户时间百分比
        CPU_USER_USAGE=`echo ${USER_BUSY} ${TOTAL_TIME}|awk '{printf "%.2f", $1/$2*100}'`
        # 系统时间百分比
        CPU_System_Usage=`echo ${SYSTEM_BUSY} ${TOTAL_TIME} |awk '{printf "%.2f", $1/$2*100}'`
        if [ "${System_CPU_Name}" = 'cpu' ];then
            Info_Echo "CPU总体使用率" "${CPU_USAGE}%"
            Info_Echo_2 "用户使用率" "${CPU_USER_USAGE}%"
            Info_Echo_2 "系统使用率" "${CPU_System_Usage}%"
        else
            Info_Echo "${System_CPU_Name} 使用率" "${CPU_USAGE}%"
            Info_Echo_2 "用户使用率" "${CPU_USER_USAGE}%"
            Info_Echo_2 "系统使用率" "${CPU_System_Usage}%"
        fi
        #echo  "${System_CPU_Name} Usage:${CPU_USAGE}% UserUsage:${CPU_USER_USAGE}% SysUsage:${CPU_System_Usage}%"
    done
}

case $1 in
all)
    # 服务器硬件信息
    Hardware_Information

    # 基础系统信息
    System_Info

    # 网络信息
    Network_Info

    # SSH检查信息
    SSH_Check_Info

    # 防火墙检查
    Firewall_Check

    # JAVA检查
    Java_Check

    # Sudoers检查
    Sudoers_Check

    # 端口监听检查
    Port_Answer_Check

    # 自启动检查
    Auto_Start_Check

    # 用户登陆检查
    User_Login_Check

    # 软件包安装检查
    Packages_Install_Check

    # 计划任务检查
    Scheduled_Task_Check

    # 服务检查
    System_Service_Check

    # 服务进程检查
    Service_Process_Check

    # SNMP服务检查
    SNMP_Service_Check

    # NTP服务检查
    NTP_Service_Check

    # Syslog服务检查
    Syslog_Service_Check

    # 用户密码检查
    User_Passwd_Check

    # 用户信息检查
    User_Info_Check

    # 磁盘检查
    Get_Disk_Check

    # 内存使用检查
    Memory_Check

    # CPU使用检查
    Cpu_Check
    ;;
check)
    # 防火墙检查
    Firewall_Check

    # Sudoers检查
    Sudoers_Check

    # 端口监听检查
    Port_Answer_Check

    # 自启动检查
    Auto_Start_Check

    # 用户登陆检查
    User_Login_Check

    # 计划任务检查
    Scheduled_Task_Check

    # 用户密码检查
    User_Passwd_Check

    # 用户信息检查
    User_Info_Check
;;
*)
    echo "all|check"
esac
# 还原系统语言
LANG=$Old_LANG