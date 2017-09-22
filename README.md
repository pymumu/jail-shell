Jail-Shell
==============

[中文REAMDME请看这里](README_zh-CN.md)

Jail-shell is a linux security tool mainly using chroot, namespaces technologies, limiting users to perform specific commands, and access sepcific directories.  

Users can login through SSH, SCP, SFTP, Telnet, terminals, etc. and restrict them to a secure operating enviroment.  

Jail-shell can be used for webhost ssh access control, enterprise Administrator's privilege hierarchy management.  

Features
==============
- **Easy to use**

Through the configuration file, jail-shell automatically generates the chroot running environment, through jail-shell management commands, it's very easy to add, list, delete, restrict users, and easy to install, delete chroot running environment. 

- **Chroot technology limits user access**

The Linux chroot technology is used to restrict the user's directory access, to avoid users access to restricted directories and to prevent users from destroying the system.

- **Directory read-only protection**

The chroot running enviroment is readonly, this avoid users to delete proteceded directories and files, avoid users to create device files, access restricted files.

- **Namespace limit user Visible range**

Use Linux namespace technology, limit the visible range of user PID, Mount directories, and avoid information leackage.

- **System command channel**

Provides a system command-and-proxy channel that allows users to execute a real system's restricted command in a chroot environment, protecting the system in the event that it provides the necessary functionality. 

- **Automatic processing of chroot Environment command library dependencies**

Only a list of commands is required to automatically copy the dynamic library that the command relies on to the chroot environment, avoiding the cumbersome work of copying the dynamic library manually

- **Capabilities Restrictions**

Discard critical capabilities privileges to avoid the system, and the chroot running environment cracked by rootkit.

- **Multi-Linux operating system support**

Supports Redhat, SLEs, Debian and their derivative operating systems.

Architecture
==============
![Architecture](docs/Architecture.png)
Jail-shell contains 3 parts, Pam Plugins, jail-cmd command agents, Jail-shell command tools.

- **pam_jail_shell Plugins**

Mainly control the login of users. according th the configuration list, use chroot and namespace technology to restrict the login users to a specific restricted directory.

- **jail-cmd command-and-proxy**

It forwards specific command to the real system, such as `passwd`, or other user-related bussiness command, and it also prevent command injection.

- **jail-shell commandline tool**

Mainly provides the ability to manage the restricted security shell, making it easier for administrators to use, including user's add, delete, shell's configuration, installation, deletion, etc.

**instructions**
1. According to the configuration, pam_jail_shell limit users to the specificed chroot enviroment.
2. Administrators use jail-shell command manage the list of restricted users, manage the list of commands for the chroot enviroment, manage the access range of directories.
3. Jail-cmd proxies specific command, to help implement the nessary business functions.


Compile and install 
==============
**Compile**
```
git clone https://github.com/pymumu/jail-shell.git
cd jail-shell
make 
```

**Install**
```
sudo make install
```

**Uninstall**
```
sudo /usr/local/jail-shell/install -u
```

Usage
==============
After installation, you can use `jail-shell` command to manage jails, `jail-shell -h` for help.  
In use, the steps are as follows:  
1. Use `useradd username` command to add user to the system.
2. Use `jail-shell jail` command to create a chroot enviroment.
3. Use `jail-shell user` command to add user to the jails.


Example
-------------
The following is an example of adding  user `test`  to a jail named `test-jail`.  
1. add user `test`，and set password
```shell
sudo useradd test -s /bin/bash
sudo passwd test
```

2. create chroot enviroment
```shell
sudo jail-shell jail -e test-jail
```
After executing the above command, a new jail configuration will be created from the template, and it is opened by `vi`, you can edit it, after that, remember to save the configuration with vi command `:w!`.

3. install chroot enviroment
```shell
sudo jail-shell jail -i test-jail
```

4. add user `test` to jail `test-jail`
```shell
sudo jail-shell user -a test -j test-jail
```

5. connect and test whether `test` is jailed.
```shell
ssh test@127.0.0.1
```
![Example](https://github.com/pymumu/backup/raw/master/image/example.gif)

Jail Config file format description
-------------
The jail config file is located at `/etc/jail-shell/jail-config/`, and file suffix is `.cfg`    
The configuration supports the following commands: 
- **dir**
  * DESC:  
create a directory into jail
  * COMMAND:  
`dir PATH MODE OWNER`
  * EXAMPLE:  
`dir /bin/ 0755 root:root`

- **file:**
  * DESC:  
copy a file into jail
  * COMMAND:  
`file SRC DEST MODE OWNER`
  * EXAMPLE:  
`file /etc/nsswitch.conf /etc/nsswitch.conf 0644 root:root`

- **hlink:**
  * DESC:  
create a hardlink file into jail
  * COMMAND:  
`file SRC DEST MODE OWNER`
  * EXAMPLE:   
`file /etc/nsswitch.conf /etc/nsswitch.conf 0644 root:root`

- **slink:**
  * DESC:  
create a symbolic link into jail
  * COMMAND:   
`slink TARGET LINKNAME`
  * EXAMPLE:   
`slink /bin/bash /bin/sh`

- **clink:**
  * DESC:  
Try to create hardlinks instead of copying the files. If linking fails it falls back to copying
  * COMMAND:   
`clink TARGET LINKNAME`
  * EXAMPLE:   
`clink /etc/localtime /etc/localtime`

- **node:**
  * DESC:  
create device file.
  * COMMAND:   
`node PATH TYPE MAJON MINOR MODE OWNER`
  * EXAMPLE:  
`node /dev/null c 1 3 666 root:root`
  * NOTE: security tips  
           should avoid adding block device files. 
 
- **bind:**
  * DESC:  
bind a directory to jail
  * COMMAND:  
`bind [SRC] DEST OPTION`  
  * OPTION: rw,ro,dev,nodev,exec,noexec, refer to (man mount) for the parameter description   
%u in path '[SRC] DEST' will be replaced as user name  
  * EXAMPLE:  
`bind / ro,nodev,nosuid`  
`bind /opt/ /opt/ ro,nodev,noexec`  
`bind /opt/upload /opt/upload rw,nodev,noexec,nosuid`  
`bind /opt/%u /opt/upload ro,nodev,noexec,nosuid`  

- **cmd:**
  * DESC:  
executes commands within the system which outside jail.
  * COMMAND:   
`cmd SRC DEST RUN_AS_USER` 
  * RUN_AS_USER: User who executes system commands, -:- means user in jail  
  * EXAMPLE:  
           `cmd /usr/bin/passwd /usr/bin/passwd -:- `  
           `cmd /some/root/command /some/root/command root:root`  
           `cmd /some/user/command /some/user/command user:user `  
  * NOTE: security tips
           This channel may lead users to escape jail, should avoid adding command which can be shell-inject,  
           For example, read the commands entered by the user  

Security Tips
==============
When using jail-shell, the minimum security authorization principle should be adopted. In the premise of ensuring the use of functions, reduce user rights.
1. `bind` tips
  * Except `/dev` directory, it is recommended to add `nodev` parameters, /dev directory must set to `ro, noexec` (read-only, disable executables) permissions.
  * For the chroot environment directory, it is recommended to set `ro, nodev, nosuid` (read only, prohibit device files, and prohibit suid files) permissions. 
  * For writable bind directories, it is recommended to set `nodev, noexec, nosuid` (disable device files, disable executable files, disable suid files) permissions. 

2. avoid commands
  * avoid: debug commands such as `gdb, mount, strace`, etc.. 


File Directory Description
==============
| directory                           |description                                                      |
|-------------------------------------|-----------------------------------------------------------------|
| `/etc/jail-shell/`                  | Configure file Directory                                        |
| `/etc/jail-shell/jail-shell. conf`  | Restricted User Configuration list file                         |
| `/etc/jail-shell/jail-config/`      | The directory where the jail shell configuration file is located, and the suffix. cfg file is recognized as a jail configuration file. |
| `/var/local/jail-shell/`            | Jail-shell Data Directory |
| `/var/local/jail-shell/jails`       | Jail-shell chroot Environment Directory |
| `/usr/local/jail-shell`             | Jail-shell program Directory |

Debugging the chroot environment
==============
When you copy a command to the chroot environment, if the copy command fails, you need to debug to find the missing dependent files, and add them to the chroot environment.  
Copy the `strace` command into the chroot environment, and then use `strace` to execute the commands that need to be debugged to find the missing dependent files.   
The following debugging commands are as follows 
```shell 
strace -F -eopen command
```
-eopen represents a list of files that the trace process opens.  
After executing the above command, troubleshoot to find the open file list.
```shell
open ("/etc/ld.so.preload", "O_RDONLY") = -1 ENOENT (No, such, file, or, directory)
```
As indicated above, the `/etc/ld-so.preload` file does not exist when reading, and may need to add the above files to the chroot environment. At this point, you can use the `clink`, `file` command to add missing files to the chroot environment. 

License
==============
Jail-shell using GPL-V2 License.

Similar tools
==============
[jailkit https://olivier.sessink.nl/jailkit/](https://olivier.sessink.nl/jailkit/)  
[rshell https://en.wikipedia.org/wiki/Restricted_shell](https://en.wikipedia.org/wiki/Restricted_shell)  
[firejail https://github.com/netblue30/firejail](https://github.com/netblue30/firejail)   
