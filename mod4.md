 # day1
-----------------------------------------
## stack nubber
14

10.50.21.145

xfreerdp /u:student /v:10.50.21.145 /dynamic-resolution +glyph-cache +clipboard


ZANE-M-005
DAY 1
-----------------------------------------------------------
*POWERSHELL*
/> Execution-policy 
  # allows to run scripts based on what the setting is.
/> $PROFILE 
  # this is where persistence can be set
  # supports several profile files and host programs like windows. (Below are the locations of each profile)
  > $PsHome\Profile.ps1 - All Users, All Hosts
  > $PsHome\Microsoft.PowerShell_profile.ps1 - All Users, Current Host
  > $Home\[My]Documents\Profile.ps1 - Current User, All Hosts
  > $Home\[My ]Documents\WindowsPowerShell\Profile.ps1 - Current User, Current Host
/> Start-Transcript
  # this logs commands that have been run
  > Start-Transcript | out-null
    # this pipes command history out to null
/> Invoke-Command
  # starts temporary sessions. It is not a remoting command, and is how everything is done in powershell.
  > -asjob
    # this option can be done if querying a large number of hosts or data to run in the background

CTF
-----------------
COMMAND - SSH-J Student@10.50.21.123 or ssh-j andy.dwyer@10.x.0.3

<<<<<<<REGEX From CTF>>>>>>>>>>
get-content words.txt | where-object {$_ -imatch "az"} | measure-object
  # this counts words that have either an 'a' or a 'z' in the word
get-content words.txt | where-object {$_ -imatch "aa[a-g]"} | measure-object
  # this counts the words that have 2 'a's and any letter between 'a-g' after the 'a's
get-content words.txt | where-object {$_ -imatch "gaab"} | measure-object
  # this counts the words that have 'gaab' in it
do {Expand-Archive -Path C:\Users\CTF\Documents\Omega$a.zip -DestinationPath C:\Users\CTF\Documents; $a-=1} until($a -eq 1)

<<<<<<<<<Profile Stuff>>>>>>>>>>>>>
Test-Path -Path $profile.currentUsercurrentHost
  #if true -> path exitst#>
Test-Path -Path $profile.allusersallhosts
  #if true -> path exists
$Home
  -> Home directory path
$Profile
  -> current user, current host
#get-help about_profiles
#get-content <path of profile>

$PROFILE | Format-List -Force
  #get all profiles on machine
  get-content
  #or
  Notepad 
      to read the profile confs

DAY 2
------------------------------------
HKEY_LOCAL_MACHINE (HKLM)
  # Hardware, Sam, Security, System
HKEY_USERS (HKU)
  # Contains environement settings, Shortcuts, and File Associations
HKEY_CURRENT_USERS (HKCU)
  # symbolic link of logged in users. (SID) 
HKEY_CURRENT_CONFIG (HKCC)
  # symbolic link to the current configurations
HKEY_CLASSES_ROOT (HKCR)
  # Contains file extension assocations

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
  # this is the wireless network reg location
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
  # this is the profilelist reg key

/> Get-PSDrive
  # Creates new powershell drive. Needs Name, PSProvider, and the Root
/> Get-ChildItem Env:
  # this shows all environemental variables

*** Drives are called by the preceding ':' ***
/> cd HKU:

CTF
-----------------
05 : windows_registry : start6223 06 : windows_alternate_data_stream : start2133 
Get-Item lists subkeys within a reg key

SPECIAL CODE
---------
/> get-wmiobject win32_useraccount | select name, sid
/> gci -path C:\ -hidden -recurse -ErrorAction SilentlyContinue | Where-Object {$_.name -like "fort"}
/> dir /b /s C:\*fortune*
/> gcio -force
  # this is the powershell command for dir /a:h

ADS
-----------
/> get-item -Stream *
/> Get-Content .\nothing_here -Stream hidden
/> dir /R
  # This lists any ads that is in a directory
/> dir /R <stream_name>
  # this shows specific ads
  
  DAY 3
------------------------------------
**Main Linux Directories**
  /Root
  /OPT
  /SRV
  /TMP
  /PROC
  /ETC
  /SBIN
  /MNT
  /VAR

**Permissions**
  FILES
  -> read
  -> write
  -> execute
  DIRECORIES
  -> read
    # for directories, this does not mean you (cant) read whats inside the directory
  -> write
    # for directories, this does not mean you (cant) write whats to the directory
Sticky Bit
  # this is the permission to delete the file with the sticky bit set

  1    2    3
> rwx|rwx|rwx
  > 1 (User)
  > 2 (Group)
  > 3 (Other)
>         ## file
> helps find what file it is

CTF
--------------
Flag = start8543

CODE
-----------
openssl enc -d -aes-128-cbc -salt -in cipher -out decrypted -k AES128Key
  # this command decrypts a file using the sha128 key (openssl)
sudo -u <user> <command>
  # executes command as a user
cat numbers | egrep -c '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
  # this finds valid and invalid ip addresses
cat numbers | egrep -c '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
  # this finds only valid ip addresses
cat numbers | egrep -v '\.' | egrep -c '^([0-9A-Za-z]{2}[:-]){5}([0-9A-Za-z]{2})$'
  # this finds invalid and valid mac addresses
awk 'NR >= 420 && NR <= 1337 {print $0}' numbers | sha512sum
  # this finds lines between 420 and 1337 and hashes them
  
DAY 4
---------
cat numbers | grep -E '^([0-9A-Fa-f][26AEae48cC0])([:-]([0-9A-Fa-f]{2})){5}$' | wc -l

http://1.bp.blogspot.com/-MaRtDTHH1Vo/UysJF8KXNbI/AAAAAAAAALo/D6Kt2f8Gpmo/s1600/Walkthrough_Diagram.jpg

DAY 5
--------------
Check for persistence in:
> sysv init
> systemd init

XXD:
  # gives hex dump of MBR
  # 0xeb63 is the start of the hardrive
!Make a copy of the MBR to avoid irriversable mistakes!

GRUB(Grand Unified Bootloader) has one purpose - to load the Linux Kernel a user choses from a location in the hard drive.
  On Bios Systems using MBR:
  > Stage 1: boot.img
  > Stage 1.5: core.img
  > Stage 2: /boot/grub/i386-pc/normal.mod

  On Bios Systems using MBR:
  > Stage 1: rubx64.efi
  > Stage 2: /boot/grub/x86_64-efi/normal.mod

Init Run Levels: (Located in etc/inittab)
> 0: Halt
> 1: Single User
> 2: Multiuser
> 3: Multiuser with Networking
> 4: Not used/user definable
> 5: Multiuser with Networking (GUI) Desktop
> 6: Reboot



Target.unit want and requires dependencies search locations
> /etc/systemd/system/*
> /lib/systemd/system/*
> /run/systemd/generator/*

The kernel is loaded with the command linux. The file /boot/vmlinuz-4.15.0-76-generic contains the Linux Kernel

graphical.target is symbolically linked to default target

CODE
-----------------
dd if=/home/bombadil/mbroken skip=446 bs=1 count=16 | md5sum
  # this reads hex from file and and starts at 446 bytes and counts by 16 (locates the first partition)
dd if=/home/bombadil/mbroken skip=392 bs=1 count=4 of=bruh
  # this skips to 392 and counts 4 bytes and redirects to a file
xxd -l <#bytes> <filename>

systemctl show -p Wants graphical.target
  # this shows the wants of a given unit
find / -name <filename> -type f
-accepteula

DAY 6
-----------------
/> tasklist /svc
  # this lists services
/> tasklist /m /fi "ImageName" eq chrome | more
  # this lists tasks that have the image name of chrome

UAC Color Codes
    > Red - Application or publisher blocked by group policy
    > Blue & gold - Administrative application
    > Blue - Trusted and Authenticode signed application
    > Yellow - Unsigned or signed but not trusted application


netsh advfirewall show allprofiles
  # this is searching for firewall profiles and the options
sc query state= all
  # this lists process that are dead and alive
sc.exe showsid Legit
  # this prints the sid of "Legit" service name

DAY 7
-----------------
Orphan Process is a process that doesnt have a parent.

All Daemons have a PID of 2

Zombies are hung up processes

CODE
--------------------------
pgrep -P 1 | wc -l
  # this counts how many processes have a ppid of 1
ps -elf --forest | grep bombadil
  # this lists who the parent is of each process
sudo lsof -n -P
  # this lists descriptors and makes it fast
/> locate <file>
  # OP as shit. Locates any file on a system
/> grep -HiRl
  # this searches for a string in any directory

