# Linux File System

![https://lcom.static.linuxfound.org/sites/lcom/files/standard-unix-filesystem-hierarchy.png](assets.md/standard-unix-filesystem-hierarchy.png)



#### `/`  : 'Root' Base Directory of all

1.  Every single file and directory starts from the root directory.
2.  Only root user has write privilege under this directory by default.

#### `/root` : Root Home

1.  Home directory for root user.
2.  Only root user has write privilege under this directory.

#### `/bin`: User Binaries

1.  Contains binary executable.
2.  Common Linux commands you need to use in single-user modes are located under this directory.
3.  Commands used by all the users of the system are located here.
4.  For example:` ps`, `ls`, `ping`, `grep`, `cp`.

#### `/sbin` : System Binaries

1.  Just like `/bin`, `/sbin` also contains binary executable.
2.  But, the Linux commands located under this directory are used typically by system administrator, for system maintenance purpose.
3.  For example: `iptables`, `reboot`, `fdisk`, `ifconfig`, `swapon`.

#### `/etc` : Configuration Files

1.  Contains configuration files required by all programs.
2.  This also contains startup and shutdown shell scripts used to start/stop individual programs.
3.  For example: `/etc/resolv.conf`, `/etc/logrotate.conf`.

#### `/dev` : Device Files

1.  Contains device files.
2.  These include terminal devices, USB, or any device attached to the system.
3.  For example: `/dev/tty1`, `/dev/usbmon0`

#### `/proc` : Process Information

1.  Contains information about system process.
2.  This is a pseudo `filesystem` contains information about running  process. For example: `/proc/{pid}` directory contains information about  the process with that particular `pid`.
3.  This is a virtual `filesystem` with text information about system resources. For example: `/proc/uptime`

#### `/var `: Variable Files

1.  var stands for variable files.
2.  Content of the files that are expected to grow can be found under this directory.
3.  This includes — system log files (`/var/log`); packages and database  files (`/var/lib`); emails (`/var/mail`);  print queues (`/var/spool`); lock  files (`/var/lock`); temp files needed across reboots (`/var/tmp`);

#### `/tmp` : Temporary Files

1.  Directory that contains temporary files created by system and users.

2.  Files under this directory are deleted when system is rebooted.

#### `/usr` : User Programs

1.  Contains binaries, libraries, documentation, and source-code for second level programs.

2.  `/usr/bin` contains binary files for user programs. If you can’t find a user binary under `/bin`, look under `/usr/bin`. For example: `at`, `awk`, `cc`,  `less`, `scp`.

3.  `/usr/sbin` contains binary files for system administrators. If you  can’t find a system binary under `/sbin`, look under `/usr/sbin`. For  example: `atd`, `cron`, `sshd`, `useradd`, `userdel`.

4.  `/usr/lib` contains libraries for `/usr/bin` and `/usr/sbin`

5.  `/usr/local` contains users programs that you install from source. For example, when you install `apache` from source, it goes under  `/usr/local/apache2`.

#### `/home` : Home Directories

1.  Home directories for all users to store their personal files.

2.  For example: `/home/user`, `/home/jake`.

#### `/boot` : Boot Loader Files

1.  Contains boot loader related files.
2.  Kernel `initrd`, `vmlinux`, `grub` files are located under `/boot`.
3.  For example: `initrd.img-2.6.32-24-generic`, `vmlinuz-2.6.32-24-generic`.

#### `/lib` : System Libraries

1.  Contains library files that supports the binaries located under `/bin` and `/sbin`
2.  Library filenames are either` ld*` or `lib*.so.*`
3.  For example:` ld-2.11.1.so`, `libncurses.so.5.7`.

#### `/opt` :  Optional add-on Applications

1.  opt stands for optional.
2.  Contains add-on applications from individual vendors.
3.  add-on applications should be installed under either `/opt/` or `/opt/ sub-directory`.

#### `/mnt` : Mount Directory

1.  Temporary mount directory where `sysadmins` can mount `filesystems`.

#### `/media` : Removable Media Devices

1.  Temporary mount directory for removable devices.

2.  For examples, `/media/cdrom` for CD-ROM; `/media/floppy` for floppy drives; `/media/cdrecorder` for CD writer.

#### `/srv` : Service Data

1.  `srv` stands for service.
2.  Contains server specific services related data.
3.  For example, `/srv/cvs` contains CVS related data.

------

# Basic Linux Commands

1.  `man` - Manual Pages

    ![image-20210516071012282](assets.md/image-20210516071012282.png)

    ​	`man -k <pattern>` - To search pattern in `man` pages.

2.  `apropos` - Search for manual pages

3.  `ls` - Listing Files

4.  `cd` - Moving Around (change directory)

5.  `pwd`  - Print Working Directory

6.  `mkdir` - Create Directory

7.  `rmdir` - Remove empty directory

8.  `rm` - Remove Directories and Files

9.  `echo` - Print to terminal

10.  `which` - Find path of file is found under `$PATH`

11.  `locate` - Used to find File and Folders quickly if mapped in `locatedb` 

12.  `find` - Search a file through recursive search

------

# Managing Linux Basic Services

### `SSH` service

```bash
sudo systemctl start ssh				# Starts the SSH service are port 22
sudo systemctl enable ssh				# Enables SSH service to run on startup
sudo ss -antlp | grep sshd 				# To check if SSH is running
```

### `http` service 

```bash
sudo systemctl start apache2					# Starts the http Apache service are port 80
sudo systemctl enable apache2					# Enables http Apache service to run on startup
sudo ss -antlp | grep apache 					# To check if http Apache is running
```

```bash
systemctl list-unit-files						# list services init files
```

------

# The Bash

1.  #### Bash Environment variables
    
    1.  `$PATH`​
    2.  `$USER`
    3.  `$PWD`​
    4.  `$HOME`
    5.  `$$`
2.  #### `history`
    
    1.  `!1`
    2.  `!!`
    3.  `ctrl + R`
3.  #### I/O Redirection
    
    1.  `|`
    2.  `>`
    3.  `<`
    4.  `STDIN = 0`
    5.  `STDOUT = 1`
    6.  `STDERR = 2`
4.  #### Text Manipulation
    
    1.  `grep`
    2.  `sed`
    3.  `cut`
    4.  `awk`
5.  #### File Editors
    
    1.  `nano`
    2.  `vi`
6.  #### Comparing Files
    
    1.  `comm`
    2.  `diff`
        1.  `diff -c <file1> <file2>`
        2.  `diff -u <file1> <file2>`
    3.  #### `vimdiff`
        
        1.  `do` - get changes from other window to current window
        2.  `dp` - puts changes from current window to other one
        3.  `]c` - jump to next change
        4.  `[c` - jumps to previous change
        5.  `ctrl + W ` - switch split window
7.  #### Process Management
    
    1.  `bg`
    2.  `jobs`
    3.  `fg`
    4.  `ps`
    5.  `kill`
8.  #### File Monitoring
    
    1.  `tail`
    2.  `watch`
9.  #### Downloading Files
    
    1.  `wget`
    2.  `curl`
        1.  `curl -o <outputfile> <url>`
    3.  `axel` - Download Accelerator (download files from FTP or HTTPS through multiple connections)
        1.  `-n <number of multiple connections>`
        2.   `-o <output file>`
        3.  `-a ` - to show more concise process indicator
10.  #### Customising Bash
     
     1.  **History Customisation**
         1.  `export HISTCONTROL=ignoredups` - ignore duplicate commands from history
         2.  `export HISTIGNORE="&:ls:[bf]g:exit:history"` - ignore common commands
         3.  `export HISTTIMEFORMAT='%F %T '` - Time format in history command
     2.  **Alias**
         1.  `alias <alias>='<command>'`
         2.  `unalias`

------
