# Debian Reference - Complete Terminal Tutorial Guide

## Table of Contents
1. [Console Basics](#1-console-basics)
2. [Unix-like Filesystem](#2-unix-like-filesystem)
3. [Midnight Commander (MC)](#3-midnight-commander-mc)
4. [Basic Unix-like Work Environment](#4-basic-unix-like-work-environment)
5. [Simple Shell Command](#5-simple-shell-command)
6. [Unix-like Text Processing](#6-unix-like-text-processing)
7. [Debian Package Management](#7-debian-package-management)
8. [System Initialization](#8-system-initialization)
9. [Authentication and Access Controls](#9-authentication-and-access-controls)
10. [Network Setup](#10-network-setup)
11. [Network Applications](#11-network-applications)
12. [GUI System](#12-gui-system)
13. [I18N and L10N](#13-i18n-and-l10n)
14. [System Tips](#14-system-tips)
15. [Data Management](#15-data-management)
16. [Data Conversion](#16-data-conversion)
17. [Programming](#17-programming)


---

## 1. Console Basics

### 1.1 The Shell Prompt

Upon starting the system without a GUI, you are presented with a character-based login screen:

```bash
foo login:
```

**Example:** Type your username (e.g., `penguin`) and press Enter, then type your password and press Enter again.

**Note:** Username and password are case-sensitive. The first user account is created during installation.

After login, you see:
```bash
Debian GNU/Linux 11 foo tty1
foo login: penguin
Password:
```

### 1.2 The Shell Prompt Under GUI

If you installed a GUI environment, you get a graphical login screen. To get a shell prompt under GUI:

- Start an x-terminal-emulator program like `gnome-terminal`, `rxvt`, or `xterm`
- Under GNOME: Press SUPER-key (Windows-key) and type "terminal"
- Under fluxbox: Right-click the desktop background for a menu

**Example:** Open terminal from GUI menu.

### 1.3 The Root Account

The root account (superuser) can:
- Read, write, and remove any files
- Set file ownership and permissions
- Set passwords for non-privileged users
- Login to any accounts without passwords

**Warning:** Never share the root password with others.

### 1.4 The Root Shell Prompt

Methods to gain root shell prompt:

```bash
# Method 1: Login as root
foo login: root

# Method 2: Use su -l (does not preserve environment)
$ su -l

# Method 3: Use su (preserves some environment)
$ su
```

### 1.5 GUI System Administration Tools

Start GUI admin tools from root shell prompt in terminal emulator:

```bash
# Start a GUI admin tool from root shell
# root-shell-prompt> gnome-control-center
```

**Warning:** Never start GUI display/session manager as root. Never run untrusted remote GUI programs when critical information is displayed.

### 1.6 Virtual Consoles

Default Debian system has 6 switchable VT100-like character consoles:

- Switch between virtual consoles: Left-Alt + F1-F6
- In GUI environment: Ctrl-Alt-F3 to get to console 3, Alt-F2 to return to GUI
- From commandline: `# chvt 3` to change to console 3

**Example:**
```bash
# Switch to virtual console 3
$ chvt 3
```

### 1.7 How to Leave the Command Prompt

To close shell activity:
- Type `Ctrl-D` or type `exit`
- At character console: returns to login prompt
- At x-terminal-emulator: closes window

**Example:**
```bash
# Type Ctrl-D or:
$ exit
```

### 1.8 How to Shutdown the System

Proper shutdown procedures:

```bash
# Shutdown under normal multiuser mode
# shutdown -h now

# Shutdown under single-user mode
# poweroff -i -f
```

**Note:** See Section 6.3.8 for remote shutdown.

### 1.9 Recovering a Sane Console

When screen displays garbage after viewing binary files:

```bash
# Reset the terminal
$ reset

# Clear the screen
$ clear
```

**Example:**
```bash
$ cat /bin/ls  # This may display garbage
$ reset        # Fix the terminal
$ clear        # Clear the screen
```

### 1.10 Additional Package Suggestions for Newbies

Install useful commandline packages:

```bash
# Update package lists
# apt-get update

# Install useful packages
# apt-get install mc vim sudo aptitude
```

If packages are already installed, no new packages will be installed.

**Package Table:**
```
mc          - Text-mode full-screen file manager
sudo        - Program to allow limited root privileges
vim         - Vi Improved text editor
vim-tiny    - Compact version of vim
emacs-nox   - Emacs without X11
w3m         - Text-mode WWW browser
gpm         - Unix-style cut-and-paste on text console
```

### 1.11 An Extra User Account

Create a training user account:

```bash
# Create a new user named 'fish'
# adduser fish

# Remove the user and home directory after practice
# deluser --remove-home fish
```

**Example:**
```bash
# adduser fish
# Answer all questions when prompted

# After practice, remove the account
# deluser --remove-home fish
```

### 1.12 Sudo Configuration

For single-user workstation, configure sudo to allow admin privileges:

```bash
# Allow user 'penguin' admin privileges with password
# echo "penguin ALL=(ALL) ALL" >> /etc/sudoers

# Allow user 'penguin' admin privileges without password
# echo "penguin ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
```

**Warning:** Only use NOPASSWD for single-user workstations you administer.

### 1.13 Play Time

Now you're ready to use non-privileged user account safely. Learn:
- Section 1.2: Basic Unix filesystem concepts
- Section 1.3: Midnight Commander (survival method)
- Section 1.4: Basic Unix work environment
- Section 1.5: Shell mechanism
- Section 1.6: Text processing methods

---

## 2. Unix-like Filesystem

### 2.1 Unix File Basics

Key concepts:
- Filenames are case-sensitive (`MYFILE` ≠ `MyFile`)
- Root directory is `/` (not to be confused with `/root`)
- Fully-qualified filename example: `/usr/share/keytables/us.map.gz`
- Basename: `us.map.gz`
- Directory tree structure
- Avoid special characters in filenames: spaces, tabs, {}, (), [], '', "", /, >, <, |, ;, !, #, &, ^, %, @, $, .

**Example directory usage:**
```
/              - Root directory
/etc           - System-wide configuration files
/var/log       - System log files
/home          - Home directories for non-privileged users
```

### 2.2 Filesystem Internals

- Everything represented as files in filesystem
- Inode data structure describes file attributes
- Physical devices represented under `/dev/`
- Process information in filesystem

**Example:** Identify file tree to physical entity correspondence:
```bash
$ mount
```

### 2.3 Filesystem Permissions

Three categories of users:
- User who owns the file (u)
- Group members (g)
- All other users (o)

File permissions:
- Read (r): examine contents
- Write (w): modify file
- Execute (x): run as command

Directory permissions:
- Read (r): list contents
- Write (w): add/remove files
- Execute (x): access files in directory

**Example using ls -l:**
```bash
$ ls -l /etc/passwd /etc/shadow /dev/ppp /usr/sbin/exim4
crw-------T 1 root root 108, 0 Oct 16 20:57 /dev/ppp
-rw-r--r-- 1 root root 2761 Aug 30 10:38 /etc/passwd
-rw-r----- 1 root shadow 1695 Aug 30 10:38 /etc/shadow
-rwxr-xr-x 1 root root 973824 Sep 23 20:04 /usr/sbin/exim4

$ ls -ld /tmp /var/tmp /usr/local /var/mail /usr/src
drwxrwxrwt 14 root root 20480 Oct 16 21:25 /tmp
drwxrwxr-x 10 root staff 4096 Sep 29 22:50 /usr/local
drwxr-xr-x 10 root root 4096 Oct 11 00:28 /usr/src
drwxrwxr-x 2 root mail 4096 Oct 15 21:40 /var/mail
drwxrwxr-t 3 root root 4096 Oct 16 21:20 /var/tmp
```

### 2.4 Changing File Permissions

Commands to change permissions:

```bash
# Change owner
# chown newowner foo

# Change group
# chgrp newgroup foo

# Change permissions
# chmod [ugoa][+-=][rwxXst] foo
```

**Example:** Make directory tree owned by user foo and group bar:
```bash
$ cd /some/location/
# chown -R foo:bar .
# chmod -R ug+rwX,o=rX .
```

Special permission bits:
- Set user ID (s or S): Execute with owner's ID
- Set group ID (s or S): Execute with group's ID
- Sticky bit (t or T): Prevent file removal by non-owners

**Numeric mode for permissions:**
```
1st digit: sum of setuid(=4), setgid(=2), sticky(=1)
2nd digit: sum of user permissions: r=4, w=2, x=1
3rd digit: group permissions
4th digit: other permissions
```

**Example:**
```bash
$ touch foo bar
$ chmod u=rw,go=r foo
$ chmod 644 bar
$ ls -l foo bar
-rw-r--r-- 1 penguin penguin 0 Oct 16 21:39 bar
-rw-r--r-- 1 penguin penguin 0 Oct 16 21:35 foo
```

### 2.5 Control of Permissions for Newly Created Files: umask

File permissions = requested permissions & ~umask

**Example umask values:**
```
umask 0022: files -rw-r--r--, directories drwxr-xr-x
umask 0002: files -rw-rw-r--, directories drwxrwxr-x
```

Debian uses User Private Group (UPG) scheme. Enable with:
```bash
# Add to ~/.bashrc
umask 002
```

### 2.6 Permissions for Groups of Users

To apply group permissions to a user:
```bash
# Edit group files
$ sudo vigr          # for /etc/group
$ sudo vigr -s       # for /etc/gshadow

# Login after logout or run:
$ exec newgrp
```

**System-provided groups for hardware access:**
```
dialout  - Serial ports (/dev/ttyS[0-3])
dip      - Dialup IP connections
cdrom    - CD-ROM/DVD drives
audio    - Audio devices
video    - Video devices
scanner  - Scanners
adm      - System monitoring logs
staff    - Administrative directories
```

**System-provided groups for command execution:**
```
sudo     - Execute sudo without password
lpadmin  - Add/modify/remove printers
```

### 2.7 Timestamps

Three types of timestamps:
- mtime: file modification time (`ls -l`)
- ctime: file status change time (`ls -lc`)
- atime: last file access time (`ls -lu`)

**Note:** ctime is NOT file creation time.

**Example:** View different timestamps:
```bash
$ ls -l foo           # Shows mtime
$ ls -lc foo          # Shows ctime  
$ ls -lu foo          # Shows atime
```

**Mount options affect atime:**
- `strictatime`: Update atime on every read (historic Unix)
- `relatime`: Update atime on first read or after 1 day (default since Linux 2.6.30)
- `noatime`: Never update atime

**Example with different locales:**
```bash
$ LANG=C ls -l foo
-rw-rw-r-- 1 penguin penguin 0 Oct 16 21:35 foo

$ LANG=en_US.UTF-8 ls -l foo
-rw-rw-r-- 1 penguin penguin 0 Oct 16 21:35 foo

$ LANG=fr_FR.UTF-8 ls -l foo
-rw-rw-r-- 1 penguin penguin 0 oct. 16 21:35 foo
```

### 2.8 Links

Two types of links:

**Hard link:** Duplicate name for existing file
```bash
$ ln foo bar
```

**Symbolic link (symlink):** Special file pointing to another file by name
```bash
$ ln -s foo baz
```

**Example demonstrating link behavior:**
```bash
$ umask 002
$ echo "Original Content" > foo
$ ls -li foo
1449840 -rw-rw-r-- 1 penguin penguin 17 Oct 16 21:42 foo

$ ln foo bar          # Hard link
$ ln -s foo baz       # Symlink

$ ls -li foo bar baz
1449840 -rw-rw-r-- 2 penguin penguin 17 Oct 16 21:42 bar
1450180 lrwxrwxrwx 1 penguin penguin 3 Oct 16 21:47 baz -> foo
1449840 -rw-rw-r-- 2 penguin penguin 17 Oct 16 21:42 foo

$ rm foo
$ echo "New Content" > foo

$ ls -li foo bar baz
1449840 -rw-rw-r-- 1 penguin penguin 17 Oct 16 21:42 bar
1450180 lrwxrwxrwx 1 penguin penguin 3 Oct 16 21:47 baz -> foo
1450183 -rw-rw-r-- 1 penguin penguin 12 Oct 16 21:48 foo

$ cat bar
Original Content

$ cat baz
New Content
```

### 2.9 Named Pipes (FIFOs)

First-In-First-Out files that link two processes:

```bash
$ cd
$ mkfifo mypipe
$ echo "hello" > mypipe &  # Put into background
[1] 8022

$ ls -l mypipe
prw-rw-r-- 1 penguin penguin 0 Oct 16 21:49 mypipe

$ cat mypipe
hello
[1]+ Done echo "hello" > mypipe

$ ls mypipe
mypipe

$ rm mypipe
```

### 2.10 Sockets

Similar to named pipes but allows communication between different computers:

```bash
# View open sockets
$ netstat -an
```

### 2.11 Device Files

Two types of device files:

**Character device:** Accessed one character at a time (keyboard, serial port)
**Block device:** Accessed in blocks (hard disk)

**Example device files:**
```bash
$ ls -l /dev/sda /dev/sr0 /dev/ttyS0 /dev/zero
brw-rw----T 1 root disk    8,  0 Oct 16 20:57 /dev/sda
brw-rw----+ 1 root cdrom  11,  0 Oct 16 21:53 /dev/sr0
crw-rw----T 1 root dialout 4, 64 Oct 16 20:57 /dev/ttyS0
crw-rw-rw- 1 root root    1,  5 Oct 16 20:57 /dev/zero
```

### 2.12 Special Device Files

```bash
/dev/null    - Read: returns EOF; Write: discards data
/dev/zero    - Read: returns NUL characters (ASCII 0)
/dev/random  - Read: returns random characters (true entropy)
/dev/urandom - Read: returns pseudo-random characters
/dev/full    - Write: returns disk-full error
```

### 2.13 procfs and sysfs

Pseudo-filesystems exposing kernel data structures:

- `/proc` - Process and system information
- `/sys` - Kernel data structures and attributes

**Example:**
```bash
# View process information
$ ls /proc/

# View kernel parameters
$ cat /proc/sys/kernel/ostype
Linux
```

### 2.14 tmpfs

Temporary filesystem keeping files in virtual memory:

- `/run` - Mounted as tmpfs in early boot
- Replaces: `/var/run`, `/var/lock`, `/dev/shm`

---

## 3. Midnight Commander (MC)

### 3.1 Installation

```bash
$ sudo apt-get install mc
```

### 3.2 Customization

Add to `~/.bashrc`:
```bash
. /usr/lib/mc/mc.sh
```

### 3.3 Starting MC

```bash
$ mc
```

With encoding fix:
```bash
$ mc -a
```

### 3.4 Key Bindings

```
F1  - Help menu
F3  - Internal file viewer
F4  - Internal editor
F9  - Activate pull-down menu
F10 - Exit Midnight Commander
Tab - Move between two windows
Insert/Ctrl-T - Mark file for multiple-file operation
Del - Delete file
```

### 3.5 Command-line Tricks

- `cd` command changes directory on selected screen

### 3.6 Internal Editor

Start editor directly:
```bash
$ mc -e filename_to_edit
$ mcedit filename_to_edit
```

Set as default editor:
```bash
# Add to ~/.bashrc
export EDITOR=mcedit
export VISUAL=mcedit
```

### 3.7 Internal Viewer

Start viewer directly:
```bash
$ mc -v path/to/filename_to_view
$ mcview path/to/filename_to_view
```

### 3.8 Auto-start Features

MC automatically handles files based on type:
- Executable files: Execute command
- Man files: Pipe to viewer
- HTML files: Pipe to web browser
- `*.tar.gz` and `*.deb` files: Browse as subdirectory

### 3.9 Virtual Filesystem

Access files over Internet:
1. Press F9
2. Select "Shell filesystem"
3. Enter URL: `sh://[user@]machine[:options]/[remote-dir]`

---

## 4. Basic Unix-like Work Environment

### 4.1 Login Shell

Default login shell is bash. To use different shell interactively, add to `~/.bashrc`:
```bash
exec /usr/bin/zsh -i -l
# or
exec /usr/bin/fish -i -l
```

### 4.2 Customizing Bash

Example `~/.bashrc` customizations:

```bash
# Enable bash completion
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi

# CD upon exiting MC
. /usr/lib/mc/mc.sh

# Set CDPATH
CDPATH=.:..:/usr/share/doc:~/Desktop
export CDPATH

# Add sbin directories to PATH
PATH="${PATH:+$PATH:}/usr/sbin:/sbin"

# Add user's private bin if exists
if [ -d ~/bin ]; then
  PATH="~/bin${PATH:+:$PATH}"
fi
export PATH

# Set default editor
EDITOR=vi
export EDITOR
```

### 4.3 Special Key Strokes

```
Ctrl-U      - Erase line before cursor
Ctrl-H      - Erase character before cursor
Ctrl-D      - Terminate input (exit shell)
Ctrl-C      - Terminate running program
Ctrl-Z      - Temporarily stop program (move to background)
Ctrl-S      - Halt output to screen
Ctrl-Q      - Reactivate output to screen
Ctrl-Alt-Del - Reboot/halt system
Up-arrow    - Command history search
Ctrl-R      - Incremental command history search
Tab         - Filename completion
Ctrl-V Tab  - Input Tab without expansion
```

### 4.4 Mouse Operations

**Traditional Unix style (3 buttons):**
- Left-click-and-drag: Select range as PRIMARY selection
- Left-click: Start of range for PRIMARY selection
- Right-click: End of range for PRIMARY selection
- Middle-click/Shift-Ins: Insert PRIMARY selection

**Modern GUI style (2 buttons with drag+click):**
- Ctrl-X: Cut PRIMARY selection to CLIPBOARD
- Ctrl-C/Shift-Ctrl-C: Copy PRIMARY selection to CLIPBOARD
- Ctrl-V: Paste CLIPBOARD at cursor

For mouse in Linux character consoles, run gpm daemon.

### 4.5 The Pager

`less` is enhanced pager:
```bash
$ less filename
# Press 'h' for help
```

Enable ANSI color escape sequences:
```bash
$ less -R filename
```

Supercharge less:
```bash
# Add to shell startup script
eval "$(lesspipe)"
# or
eval "$(lessfile)"
```

### 4.6 Text Editor

Learn Vim or Emacs. Vim tutorial:
```bash
$ vim
# Press F1 for help
# Move cursor to |tutor| and press Ctrl-] for interactive tutorial
```

### 4.7 Setting Default Text Editor

Debian provides unified access via `/usr/bin/editor`:
```bash
$ sudo update-alternatives --config editor
```

Set environment variables for consistency:
```bash
# Add to ~/.bashrc
export EDITOR=/usr/bin/editor
export VISUAL=/usr/bin/editor
```

### 4.8 Using Vim

Interactive tutorial:
```bash
$ vimtutor
```

**Vim modes:**
- INSERT-mode: Typing text
- NORMAL-mode: Moving cursor
- VISUAL-mode: Interactive selection
- Ex-mode: Type ':' in NORMAL-mode

**Basic Vim key strokes:**
```
NORMAL :help          - Display help
NORMAL :e filename    - Open new buffer
NORMAL :w             - Overwrite current buffer
NORMAL :w filename    - Write to filename
NORMAL :q             - Quit vim
NORMAL :q!            - Force quit
NORMAL i              - Enter INSERT mode
NORMAL R              - Enter REPLACE mode
NORMAL v              - Enter VISUAL mode
NORMAL V              - Enter linewise VISUAL mode
NORMAL Ctrl-V         - Enter blockwise VISUAL mode
ESC                   - Enter NORMAL mode
```

### 4.9 Recording Shell Activities

Using `script` command:
```bash
$ script
Script started, file is typescript
# Do commands...
# Press Ctrl-D to exit
$ vim typescript
```

### 4.10 Basic Unix Commands

```bash
pwd                           # Display current directory
whoami                        # Display current user name
id                            # Display current user identity
file foo                      # Display type of file "foo"
type -p commandname           # Display file location of command
which commandname             # Display file location of command
man -k keyword                # Search manual pages
whatis commandname            # One-line explanation of command
man -a commandname            # Display manual page (Unix style)
info commandname              # Display info page (GNU style)
ls                            # List contents (non-dot files)
ls -a                         # List all contents (including dot files)
ls -A                         # List almost all (skip "." and "..")
ls -la                        # List all with details
ls -lai                       # List all with inode and details
ls -d                         # List directories
tree                          # Display file tree
lsof foo                      # List open status of file "foo"
lsof -p pid                   # List files opened by process ID
mkdir foo                     # Make directory "foo"
rmdir foo                     # Remove directory "foo"
cd foo                        # Change to directory "foo"
cd /                          # Change to root directory
cd                            # Change to home directory
cd /foo                       # Change to absolute path
cd ..                         # Change to parent directory
cd ~foo                       # Change to home of user "foo"
cd -                          # Change to previous directory
</etc/motd pager              # Display /etc/motd using pager
touch junkfile                # Create empty file
cp foo bar                    # Copy file
rm junkfile                   # Remove file
mv foo bar                    # Rename file
mv foo bar/                   # Move file to directory (bar must exist)
mv foo bar/baz                # Move and rename (bar must exist, bar/baz must not)
chmod 600 foo                 # Make file non-readable/writable by others
chmod 644 foo                 # Make file readable but not writable by others
chmod 755 foo                 # Make file readable but not writable, executable by all
find . -name pattern          # Find matching filenames (slow)
locate -d . pattern           # Find matching filenames (quick, uses database)
grep -e "pattern" *.html      # Find pattern in all .html files
top                           # Display process info (full screen, 'q' to quit)
ps aux | pager                # Display all running processes (BSD style)
ps -ef | pager                # Display all running processes (System V style)
ps aux | grep -e "[e]xim4*"   # Display processes running exim/exim4
ps axf | pager                # Display processes with ASCII art
kill 1234                     # Kill process with PID 1234
```

**Note:** Hide filenames starting with "." (configuration files).

---

## 5. Simple Shell Command

### 5.1 Command Execution and Environment Variables

Environment variables change command behavior:

```bash
$ echo $LANG
en_US.UTF-8

$ date -u
Wed 19 May 2021 03:18:43 PM UTC

$ LANG=fr_FR.UTF-8 date -u
mer. 19 mai 2021 15:19:02 UTC
```

### 5.2 The LANG Variable

Locale format: `xx_YY.ZZZZ`
- `xx`: ISO 639 language code (lowercase)
- `YY`: ISO 3166 country code (uppercase)
- `ZZZZ`: Codeset (always "UTF-8")

**Example locales:**
```
en_US.UTF-8    English (USA)
en_GB.UTF-8    English (Great Britain)
fr_FR.UTF-8    French (France)
de_DE.UTF-8    German (Germany)
ja_JP.UTF-8    Japanese (Japan)
```

For bug reports, use `en_US.UTF-8` locale.

### 5.3 The PATH Variable

Shell search path for commands. Default may not include `/sbin` and `/usr/sbin`.

Add to `~/.bashrc`:
```bash
PATH="${PATH:+$PATH:}/usr/sbin:/sbin"
export PATH
```

### 5.4 The HOME Variable

User's home directory identified by `$HOME`.

**Shell expansions:**
- `~/` expands to `$HOME/`
- `~foo/` expands to `/home/foo/`

**HOME values in different contexts:**
```
/                    - Program run by init process (daemon)
/root                - Program run from normal root shell
/home/normal_user    - Program run from normal user shell
/home/normal_user    - Program run from GUI desktop menu
/root                - Program run as root with "sudo program"
/root                - Program run as root with "sudo -H program"
```

### 5.5 Command Line Options

Arguments starting with `-` or `--` control command behavior:

```bash
$ date
Thu 20 May 2021 01:08:08 AM JST

$ date -R
Thu, 20 May 2021 01:08:12 +0900
```

### 5.6 Shell Glob

Filename expansion patterns:

```bash
*        - Filename not starting with "."
.*       - Filename starting with "."
?        - Exactly one character
[abc]    - Exactly one character from a, b, or c
[a-z]    - Exactly one character between a and z
[^abc]   - Exactly one character not a, b, or c
```

**Example:**
```bash
$ mkdir junk; cd junk; touch 1.txt 2.txt 3.c 4.h .5.txt .6.txt
$ echo *.txt
1.txt 2.txt
$ echo *
1.txt 2.txt 3.c 4.h
$ echo *.[hc]
3.c 4.h
$ echo .*
.5.txt .6.txt
$ echo [^.]*
.5.txt .6.txt
$ echo [^1-3]*
4.h
$ cd ..; rm -rf junk
```

### 5.7 Return Value of Command

Exit status: `$?`
- 0: Success (TRUE)
- Non-zero: Error (FALSE)

**Example:**
```bash
$ [ 1 = 1 ]; echo $?
0
$ [ 1 = 2 ]; echo $?
1
```

### 5.8 Typical Command Sequences and Shell Redirection

```bash
command &                      # Background execution
command1 | command2            # Pipe stdout of command1 to stdin of command2
command1 2>&1 | command2       # Pipe both stdout and stderr
command1 ; command2            # Execute sequentially
command1 && command2           # Execute command2 only if command1 succeeds
command1 || command2           # Execute command2 only if command1 fails
command > foo                  # Redirect stdout to file (overwrite)
command 2> foo                 # Redirect stderr to file (overwrite)
command >> foo                 # Redirect stdout to file (append)
command 2>> foo                # Redirect stderr to file (append)
command > foo 2>&1             # Redirect both stdout and stderr to file
command < foo                  # Redirect stdin from file
command << delimiter           # Here document (until "delimiter")
command <<- delimiter          # Here document (strip leading tabs)
```

**Example:**
```bash
# All equivalent ways to display /etc/motd
$ </etc/motd pager
$ pager </etc/motd
$ pager /etc/motd
$ cat /etc/motd | pager
```

**Using file descriptors:**
```bash
$ echo Hello >foo
$ exec 3<foo 4>bar            # Open files
$ cat <&3 >>&4                # Redirect stdin to 3, stdout to 4
$ exec 3<&- 4>&-              # Close files
$ cat bar
Hello
```

**Predefined file descriptors:**
- 0: stdin (standard input)
- 1: stdout (standard output)
- 2: stderr (standard error)

### 5.9 Command Alias

Create shortcuts for frequently used commands:

```bash
$ alias la='ls -la'
$ alias
alias la='ls -la'

$ type ls
ls is hashed (/bin/ls)
$ type la
la is aliased to ls -la
$ type echo
echo is a shell builtin
$ type file
file is /usr/bin/file
```

---

## 6. Unix-like Text Processing

### 6.1 Unix Text Tools

**No regular expression:**
- `cat` - Concatenate files
- `tac` - Concatenate in reverse
- `cut` - Select parts of lines
- `head` - Output first part
- `tail` - Output last part
- `sort` - Sort lines
- `uniq` - Remove duplicate lines
- `tr` - Translate/delete characters
- `diff` - Compare files line by line

**Basic Regular Expression (BRE):**
- `ed` - Primitive line editor
- `sed` - Stream editor
- `grep` - Match text with patterns
- `vim` - Screen editor
- `emacs` - Screen editor (extended BRE)

**Extended Regular Expression (ERE):**
- `awk` - Simple text processing
- `egrep` - Match text with patterns
- `tcl` - Text processing with `re_syntax(3)`
- `perl` - Text processing with `perlre(1)`
- `pcregrep` - Match with Perl Compatible Regular Expressions
- `python` - Text processing with `re` module

### 6.2 Regular Expressions

Two major styles: BRE and ERE

**Metacharacters:**
```
.        - Match any character including newline
^        - Position at beginning of string
$        - Position at end of string
\<       - Position at beginning of word
\>       - Position at end of word
[abc]    - Match any character in "abc"
[^abc]   - Match any character not in "abc"
r*       - Match zero or more of r
r+       - Match one or more of r
r?       - Match zero or one of r
r1|r2    - Match r1 or r2
(r1|r2)  - Match r1 or r2 (grouped)
```

**BRE vs ERE differences:**
- BRE: `\+`, `\?`, `\(`, `\)`
- ERE: `+`, `?`, `(`, `)`

### 6.3 Replacement Expressions

Special characters in replacement:
- `&` - What the regular expression matched
- `\n` - What the n-th bracketed expression matched

**Perl replacement:** Use `$&` instead of `&`, `$n` instead of `\n`

**Example:**
```bash
$ echo zzz1abc2efg3hij4 | sed -e 's/1[a-z]*[0-9]*$/=&=/'
zzz=1abc2efg3hij4=

$ echo zzz1abc2efg3hij4 | sed -e 's/1[a-z]*[0-9]*\(.*\)$/\2===\1/'
zzzefg3hij4===1abc

$ echo zzz1abc2efg3hij4 | perl -pe 's/(1[a-z]*)[0-9]*(.*)$/$2===$1/'
zzzefg3hij4===1abc

$ echo zzz1abc2efg3hij4 | perl -pe 's/(1[a-z]*)[0-9]*(.*)$/=$&=/'
zzz=1abc2efg3hij4=
```

### 6.4 Global Substitution with Regular Expressions

**Using ed:**
```bash
$ ed file <<EOF
,s/FROM_REGEX/TO_TEXT/g
w
q
EOF
```

**Using sed:**
```bash
$ sed -i -e 's/FROM_REGEX/TO_TEXT/g' file
```

**Using vim:**
```bash
$ vim '+%s/FROM_REGEX/TO_TEXT/gc' '+w' '+q' file
# 'c' flag for interactive confirmation
```

**Multiple files with vim:**
```bash
$ vim '+argdo %s/FROM_REGEX/TO_TEXT/ge|update' '+q' file1 file2 file3
# 'e' flag prevents "No match" error from breaking mapping
```

**Multiple files with perl:**
```bash
$ perl -i -p -e 's/FROM_REGEX/TO_TEXT/g;' file1 file2 file3
# -i for in-place editing, -p for implicit loop
# Use -i.bak to keep backup with .bak extension
```

### 6.5 Extracting Data from Text File Table

Example file `DPL`:
```
Ian Murdock August 1993
Bruce Perens April 1996
Ian Jackson January 1998
Wichert Akkerman January 1999
Ben Collins April 2001
Bdale Garbee April 2002
Martin Michlmayr March 2003
```

**Using awk:**
```bash
$ awk '{ print $3 }' <DPL
August
April
January
January
April
April
March

$ awk '($1=="Ian") { print }' <DPL
Ian Murdock August 1993
Ian Jackson January 1998

$ awk '($2=="Perens") { print $3,$4 }' <DPL
April 1996
```

**Using shell:**
```bash
$ while read first last month year; do
    echo $month
  done <DPL
```

**Parsing /etc/passwd with shell:**
```bash
$ oldIFS="$IFS"          # Save old value
$ IFS=':'
$ while read user password uid gid rest_of_line; do
    if [ "$user" = "bozo" ]; then
      echo "$user's ID is $uid"
    fi
  done < /etc/passwd
bozo's ID is 1000
$ IFS="$oldIFS"          # Restore old value
```

**Note on IFS:** Also used to split results of parameter expansion, command substitution, and arithmetic expansion.

**Example of IFS effects:**
```bash
$ IFS=":,"               # Use ":" and "," as IFS
$ echo IFS=$IFS,
IFS=: , IFS=:,
$ date -R
Sat, 23 Aug 2003 08:30:15 +0200
$ echo $(date -R)        # Subshell -> input to main shell
Sat 23 Aug 2003 08 30 36 +0200
$ unset IFS              # Reset IFS to default
$ echo $(date -R)
Sat, 23 Aug 2003 08:30:50 +0200
```

### 6.6 Script Snippets for Piping Commands

```bash
find /usr -print               # Find all files under /usr
seq 1 100                      # Print 1 to 100
xargs -n 1 command             # Run command with each item from pipe
xargs -n 1 echo                # Split whitespace items into lines
xargs echo                     # Merge all lines into one line
grep -e regex_pattern          # Extract lines containing pattern
grep -v -e regex_pattern       # Extract lines not containing pattern
cut -d: -f3                    # Extract third field separated by ":"
awk '{ print $3 }'             # Extract third field separated by whitespace
awk -F'\t' '{ print $3 }'      # Extract third field separated by tab
col -bx                        # Remove backspace and expand tabs
expand                         # Expand tabs
sort | uniq                    # Sort and remove duplicates
tr 'A-Z' 'a-z'                 # Convert uppercase to lowercase
tr -d '\n'                     # Concatenate lines into one line
tr -d '\r'                     # Remove CR
sed 's/^/#/'                   # Add '#' to start of each line
sed 's/\.\.ext//g'             # Remove "..ext"
sed -n -e 2p                   # Print the second line
head -n 2                      # Print first 2 lines
tail -n 2                      # Print last 2 lines
```

---

## 7. Debian Package Management

### 7.1 Package Configuration

Key points:
- Manual configuration by administrator is respected
- Each package has configuration script using debconf(7)
- Upgrades aim to be flawless
- Full functionalities available but security risks disabled by default

### 7.2 Basic Precautions

**Warnings:**
- Don't install packages from random mixture of suites
- Don't include testing/unstable in `/etc/apt/sources.list` unless you know what you're doing
- Don't mix Debian with non-Debian archives (e.g., Ubuntu)
- Don't create `/etc/apt/preferences` without understanding
- Don't change default behavior without knowing impacts
- Don't install random packages with `dpkg -i`
- Never use `dpkg --force-all -i random_package`
- Don't erase/alter files in `/var/lib/dpkg/`
- Don't overwrite system files with software compiled from source

### 7.3 Life with Eternal Upgrades

For production servers: Stable suite with security updates recommended.

For self-administered desktop considering testing/unstable:
- Use testing suite as rolling release
- Set codename (e.g., "bookworm") in `/etc/apt/sources.list`
- Update codename about a month after major suite release

**Precautionary measures:**
- Make system dual bootable with stable on another partition
- Keep installation CD for rescue boot
- Consider installing `apt-listbugs`
- Learn package system infrastructure
- Install sandboxed upstream binary packages
- Create chroot environment for latest system

### 7.4 Debian Archive Basics

Example `/etc/apt/sources.list` for stable (bullseye):
```bash
deb http://deb.debian.org/debian/ bullseye main non-free-firmware contrib non-free
deb-src http://deb.debian.org/debian/ bullseye main non-free-firmware contrib non-free

deb http://security.debian.org/debian-security bullseye-security main non-free-firmware contrib non-free
deb-src http://security.debian.org/debian-security bullseye-security main non-free-firmware contrib non-free
```

**Archive areas:**
- main: DFSG compliant, no dependency to non-free (67,672 packages)
- non-free-firmware: Not DFSG compliant, firmware required for system (31 packages)
- contrib: DFSG compliant but depends on non-free (338 packages)
- non-free: Not DFSG compliant, not in non-free-firmware (939 packages)

**Debian archive sites:**
```
http://deb.debian.org/debian/stable           - Stable release
http://deb.debian.org/debian/testing          - Testing release  
http://deb.debian.org/debian/unstable         - Unstable release
http://deb.debian.org/debian/experimental     - Experimental pre-release
http://deb.debian.org/debian/stable-updates   - Compatible updates for stable
http://deb.debian.org/debian/stable-backports - Newer backported packages
http://security.debian.org/debian-security/stable-security - Security updates
```

### 7.5 Debian is 100% Free Software

Debian Social Contract ensures:
- Debian installs only free software by default
- Main area contains only free software
- Non-free and contrib areas are not part of Debian system

**Risks of non-free/contrib packages:**
- Lack of freedom
- Lack of support from Debian
- Contamination of free system

### 7.6 Package Dependencies

**Dependency fields:**
- `Depends`: Absolute dependency
- `Pre-Depends`: Like Depends, requires installation in advance
- `Recommends`: Strong but not absolute dependency
- `Suggests`: Weak dependency
- `Enhances`: Weak dependency (opposite direction of Suggests)
- `Breaks`: Package incompatibility with version specification
- `Conflicts`: Absolute incompatibility
- `Replaces`: Files replace files in listed packages
- `Provides`: Package provides all files/functionality of listed packages

### 7.7 Basic Package Management Operations

**apt vs apt-get/apt-cache vs aptitude:**
- `apt`: High-level commandline interface (recommended for interactive use)
- `apt-get`/`apt-cache`: Basic APT tools (good for scripts)
- `aptitude`: Versatile with interactive text interface

**Basic operations:**
```bash
# Update package metadata
$ sudo apt update
$ sudo aptitude update
$ sudo apt-get update

# Install package
$ sudo apt install foo
$ sudo aptitude install foo
$ sudo apt-get install foo

# Upgrade packages
$ sudo apt upgrade              # Without removing packages
$ sudo apt full-upgrade        # May remove packages if needed
$ sudo aptitude safe-upgrade   # Without removing
$ sudo aptitude full-upgrade   # May remove packages
$ sudo apt-get upgrade         # Without removing
$ sudo apt-get dist-upgrade    # May remove packages

# Remove package
$ sudo apt remove foo          # Keep config files
$ sudo aptitude remove foo
$ sudo apt-get remove foo

# Purge package
$ sudo apt purge foo           # Remove config files too
$ sudo aptitude purge foo
$ sudo apt-get purge foo

# Clean up
$ sudo apt clean
$ sudo aptitude clean
$ sudo apt-get clean

# Show package info
$ apt show foo
$ aptitude show foo
$ apt-cache show foo

# Search packages
$ apt search regex
$ aptitude search regex
$ apt-cache search regex
```

### 7.8 Interactive Use of Aptitude

Start aptitude interactively:
```bash
$ sudo aptitude -u
```

**Key bindings in aptitude:**
```
F10 or Ctrl-t - Menu
?             - Help
u             - Update package info
+             - Mark for upgrade/install
-             - Mark for remove (keep config)
_             - Mark for purge (remove config)
U             - Place package on hold
U             - Mark all upgradable packages
g             - Start downloading/installing
q             - Quit and save changes
x             - Quit and discard changes
Enter         - View package info
C             - View changelog
L             - Change display limit
/             - Search for first match
\             - Repeat last search
```

### 7.9 Examples of Aptitude Operations

**List packages with regex matching:**
```bash
$ aptitude search '-n(pam|nss).*ldap'
p libnss-ldap - NSS module for using LDAP as a naming service
p libpam-ldap - Pluggable Authentication Module allowing LDAP interfaces
```

**Purge removed packages:**
```bash
# Check packages to purge
$ aptitude search '~c'

# Purge all
# aptitude purge '~c'
```

**Tidy auto/manual install status:**
1. Start aptitude as root
2. Type `u`, `U`, `f`, `g` to update and upgrade
3. Type `l` and enter `~i(~R~i|~Rrecommends:~i)`, type `M` over "Installed Packages"
4. Type `l` and enter `~prequired|~pimportant|~pstandard|~E`, type `m` over "Installed Packages"
5. Type `l` and enter `~i!~M`, remove unused packages
6. Type `l` and enter `~i`, type `m` over "Tasks"
7. Exit aptitude
8. Check with `apt-get -s autoremove|less`
9. Restart aptitude, mark needed packages as `m`
10. Recheck with `apt-get -s autoremove|less`
11. Run `apt-get autoremove|less`

### 7.10 Advanced Package Management Operations

**Verification of installed files:**
```bash
# Install debsums
$ sudo apt-get install debsums

# Verify files
$ debsums -a
```

**Other advanced operations:**
```bash
# List package contents
$ dpkg -L package_name

# List manpages for package
$ dpkg -L package_name | grep '/man/man.*/'

# Search for file in packages
$ apt-file search file_name_pattern

# Reconfigure package
$ sudo dpkg-reconfigure package_name

# Show available versions
$ apt-cache policy package_name

# Download source
$ apt-get source package_name

# Install build dependencies
$ apt-get build-dep package_name

# Install local package with dependencies
$ sudo apt install ./package.deb
```

### 7.11 Package Management Internals

**Package file names:**
- Binary: `package-name_upstream-version-debian.revision_architecture.deb`
- Source: `package-name_upstream-version-debian.revision.dsc`

**dpkg process order:**
1. Unpack deb file
2. Execute `preinst` script
3. Install package content
4. Execute `postinst` script

**Important dpkg files:**
```
/var/lib/dpkg/status          - Package status information
/var/lib/dpkg/available       - Availability information
/var/lib/dpkg/info/           - Package scripts and lists
/var/cache/apt/archives/      - Downloaded package files
```

### 7.12 Recovery from Broken System

**Failed installation due to missing dependencies:**
```bash
# Configure all partially installed packages
$ sudo dpkg --configure -a
```

**Caching errors:**
```bash
# Remove cached data
$ sudo rm -rf /var/lib/apt/*
# If using apt-cacher-ng
$ sudo rm -rf /var/cache/apt-cacher-ng/*
```

**Emergency downgrading:**
1. Change `/etc/apt/sources.list` from unstable to testing
2. Create `/etc/apt/preferences`:
   ```
   Package: *
   Pin: release a=testing
   Pin-Priority: 1010
   ```
3. Run `apt-get update; apt-get dist-upgrade`
4. Remove `/etc/apt/preferences` after recovery

**Recovering package selection data:**
If `/var/lib/dpkg/status` is corrupt:
- Check backups at `/var/lib/dpkg/status-old` or `/var/backups/dpkg.status*`
- Or reinstall minimal system and check `/usr/share/doc/` on old system

---

## 8. System Initialization

### 8.1 Boot Process Overview

Four stages:
1. UEFI/BIOS
2. Boot loader (GRUB2)
3. Mini-Debian system (initramfs)
4. Normal Debian system

### 8.2 Boot Loaders

**GRUB2 configuration:**
```bash
# GRUB2 menu entry example in /boot/grub/grub.cfg
menuentry 'Debian GNU/Linux' ... {
  load_video
  insmod gzio
  insmod part_gpt
  insmod ext2
  search --no-floppy --fs-uuid --set=root fe3e1db5-6454-46d6-a14c-071208ebe4b1
  echo 'Loading Linux 5.10.0-6-amd64 ...'
  linux /boot/vmlinuz-5.10.0-6-amd64 root=UUID=fe3e1db5-6454-46d6-a14c-071208ebe4b1
  echo 'Loading initial ramdisk ...'
  initrd /boot/initrd.img-5.10.0-6-amd64
}
```

**To see kernel boot messages:** Remove "quiet" from `/boot/grub/grub.cfg`

### 8.3 Systemd Init

**Key systemd commands:**
```bash
# List services
$ systemctl list-units --type=service

# Start/stop service
$ sudo systemctl start service_name
$ sudo systemctl stop service_name

# Enable/disable service at boot
$ sudo systemctl enable service_name
$ sudo systemctl disable service_name

# Check service status
$ systemctl status service_name

# View logs
$ journalctl -u service_name
$ journalctl -b          # Logs from current boot
$ journalctl -f          # Follow logs
```

**Systemd unit files locations:**
- `/lib/systemd/system/` - OS default
- `/etc/systemd/system/` - Administrator overrides
- `/run/systemd/system/` - Runtime generated

### 8.4 Kernel Messages

Configure kernel message level:
```bash
# Set to level 3 (KERN_ERR)
# dmesg -n 3
```

**Kernel error levels:**
```
0 - KERN_EMERG    System unusable
1 - KERN_ALERT    Immediate action needed
2 - KERN_CRIT     Critical conditions
3 - KERN_ERR      Error conditions
4 - KERN_WARNING  Warning conditions
5 - KERN_NOTICE   Normal but significant
6 - KERN_INFO     Informational
7 - KERN_DEBUG    Debug messages
```

---

## 9. Authentication and Access Controls

### 9.1 Normal Unix Authentication

**Key files:**
```bash
/etc/passwd    - User account information
/etc/shadow    - Secure password information
/etc/group     - Group information
```

**/etc/passwd format:**
```
username:password_field:UID:GID:GECOS:homedir:shell
```

**Example:**
```
user1:x:1000:1000:User1 Name,,,:/home/user1:/bin/bash
```

**/etc/shadow format:**
```
username:encrypted_password:last_change:min_age:max_age:warn:inactive:expire:reserved
```

### 9.2 Managing Accounts

**Commands:**
```bash
# Change password
$ passwd

# Set one-time password
$ passwd -e username

# Manage password aging
$ chage username

# Browse account info
$ getent passwd username
$ getent shadow username
$ getent group groupname
```

### 9.3 PAM and NSS

**PAM configuration:**
- Files in `/etc/pam.d/` for each service
- Example: `/etc/pam.d/login`

**NSS configuration:**
- File: `/etc/nsswitch.conf`
- Controls order of name service lookups

**Important PAM modules:**
```
pam_unix.so     - Traditional Unix authentication
pam_ldap.so     - LDAP authentication
pam_cracklib.so - Password strength checking
pam_limits.so   - Resource limits
pam_env.so      - Environment variables
```

### 9.4 Sudo Configuration

**Edit sudoers file:**
```bash
$ sudo visudo
```

**Examples in /etc/sudoers:**
```
# Allow user to run all commands as any user
penguin ALL=(ALL) ALL

# Allow without password (use with caution!)
penguin ALL=(ALL) NOPASSWD:ALL

# Allow specific commands
penguin ALL=(ALL) /usr/bin/apt-get, /usr/bin/aptitude

# Allow command with arguments
penguin ALL=(ALL) /bin/kill, /usr/bin/killall
```

**Sudo logging:** Check `/var/log/auth.log`

## 10. Network Setup

### 10.1 The Basic Network Infrastructure

#### 10.1.1 Hostname Resolution

**Files involved:**
- `/etc/hostname` - System hostname
- `/etc/hosts` - Local hostname to IP mapping
- `/etc/resolv.conf` - DNS resolver configuration
- `/etc/nsswitch.conf` - Name service switch configuration

**Example `/etc/hosts`:**
```
127.0.0.1       localhost
127.0.1.1       debian.localdomain  debian

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

**Example `/etc/resolv.conf`:**
```
nameserver 8.8.8.8
nameserver 8.8.4.4
search example.com
```

**Name resolution order in `/etc/nsswitch.conf`:**
```
hosts:          files dns
networks:       files
```

#### 10.1.2 Network Interface Names

Traditional names vs predictable names:
- Traditional: `eth0`, `eth1`, `wlan0`
- Predictable: `enp3s0`, `wlp2s0`

**View network interfaces:**
```bash
# Traditional command
$ ifconfig -a

# Modern command
$ ip addr show

# List all network interfaces
$ ls /sys/class/net/
```

#### 10.1.3 Network Address Ranges for LAN

Common private IP ranges:
- 10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
- 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
- 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)

**Example subnet calculation:**
```bash
# Calculate network address for 192.168.1.10/24
$ ipcalc 192.168.1.10/24
Address:   192.168.1.10         11000000.10101000.00000001.00001010
Netmask:   255.255.255.0 = 24   11111111.11111111.11111111.00000000
Wildcard:  0.0.0.255            00000000.00000000.00000000.11111111
Network:   192.168.1.0/24       11000000.10101000.00000001.00000000
HostMin:   192.168.1.1          11000000.10101000.00000001.00000001
HostMax:   192.168.1.254        11000000.10101000.00000001.11111110
Broadcast: 192.168.1.255        11000000.10101000.00000001.11111111
Hosts/Net: 254
```

### 10.2 Modern Network Configuration for Desktop

#### 10.2.1 GUI Network Configuration Tools

**NetworkManager:**
```bash
# Check NetworkManager status
$ systemctl status NetworkManager

# Start NetworkManager
$ sudo systemctl start NetworkManager

# Enable at boot
$ sudo systemctl enable NetworkManager

# Command line interface
$ nmcli
```

**Using nmcli:**
```bash
# List connections
$ nmcli connection show

# List devices
$ nmcli device status

# Connect to WiFi
$ nmcli device wifi list
$ nmcli device wifi connect SSID password PASSWORD

# Create a new connection
$ nmcli connection add type ethernet ifname eth0 con-name my-eth
```

### 10.3 Modern Network Configuration Without GUI

**Using systemd-networkd:**
```bash
# Enable systemd-networkd
$ sudo systemctl enable systemd-networkd
$ sudo systemctl start systemd-networkd

# Configuration file example: /etc/systemd/network/20-wired.network
[Match]
Name=eth0

[Network]
Address=192.168.1.10/24
Gateway=192.168.1.1
DNS=8.8.8.8
DNS=8.8.4.4
```

**Using netplan (Ubuntu/Debian):**
```bash
# Example: /etc/netplan/01-netcfg.yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: true
      optional: true
    enp3s0:
      addresses:
        - 192.168.1.10/24
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]

# Apply configuration
$ sudo netplan apply
```

### 10.4 Low Level Network Configuration

#### 10.4.1 Iproute2 Commands

**Replacing traditional net-tools:**
```bash
# ifconfig -> ip addr/ip link
$ ip addr show
$ ip link show

# route -> ip route
$ ip route show
$ ip route add default via 192.168.1.1

# arp -> ip neigh
$ ip neigh show

# netstat -> ss
$ ss -tulpn
$ ss -tun
```

**Complete translation table:**
```
Old command          New command
ifconfig            ip addr, ip link
ifconfig (up/down)  ip link set dev <iface> up/down
route               ip route
arp                 ip neigh
netstat             ss, ip route, ip -s link
iptunnel            ip tunnel
nameif              ip link set name
mii-tool            ethtool
```

#### 10.4.2 Safe Low Level Network Operations

**Changing IP address temporarily:**
```bash
# Set IP address
$ sudo ip addr add 192.168.1.10/24 dev eth0

# Bring interface up
$ sudo ip link set eth0 up

# Add default gateway
$ sudo ip route add default via 192.168.1.1

# Test connectivity
$ ping -c 3 8.8.8.8
```

**Flush all IP addresses from interface:**
```bash
$ sudo ip addr flush dev eth0
```

### 10.5 Network Optimization

#### 10.5.1 Finding Optimal MTU

**Test MTU with ping:**
```bash
# Test MTU with don't fragment flag
$ ping -M do -s 1472 -c 3 8.8.8.8
# If success, MTU is at least 1500 (1472 + 28 header)

# Find maximum MTU
$ ping -M do -s 8972 -c 1 8.8.8.8
# Decrease size until it works
```

**Set MTU:**
```bash
$ sudo ip link set eth0 mtu 1500
```

#### 10.5.2 WAN TCP Optimization

**TCP tuning parameters:**
```bash
# View current TCP parameters
$ sysctl net.ipv4.tcp_available_congestion_control
$ sysctl net.ipv4.tcp_congestion_control

# Enable TCP window scaling
$ sudo sysctl -w net.ipv4.tcp_window_scaling=1

# Enable TCP timestamps
$ sudo sysctl -w net.ipv4.tcp_timestamps=1

# Increase TCP buffer sizes
$ sudo sysctl -w net.core.rmem_max=16777216
$ sudo sysctl -w net.core.wmem_max=16777216
$ sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
$ sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"
```

### 10.6 Netfilter Infrastructure (iptables/nftables)

#### 10.6.1 Basic iptables Commands

**View current rules:**
```bash
# List all rules
$ sudo iptables -L -n -v

# List with line numbers
$ sudo iptables -L -n -v --line-numbers

# List NAT rules
$ sudo iptables -t nat -L -n -v
```

**Basic firewall rules:**
```bash
# Default policies
$ sudo iptables -P INPUT DROP
$ sudo iptables -P FORWARD DROP
$ sudo iptables -P OUTPUT ACCEPT

# Allow loopback
$ sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
$ sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
$ sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP/HTTPS
$ sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
$ sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow ping
$ sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
```

#### 10.6.2 nftables Basics

**nftables configuration:**
```bash
# List tables
$ sudo nft list tables

# List ruleset
$ sudo nft list ruleset

# Create a simple firewall
$ sudo nft add table inet filter
$ sudo nft add chain inet filter input { type filter hook input priority 0\; }
$ sudo nft add chain inet filter forward { type filter hook forward priority 0\; }
$ sudo nft add chain inet filter output { type filter hook output priority 0\; }

# Add rules
$ sudo nft add rule inet filter input iif lo accept
$ sudo nft add rule inet filter input ct state established,related accept
$ sudo nft add rule inet filter input tcp dport 22 accept
$ sudo nft add rule inet filter input tcp dport 80 accept
$ sudo nft add rule inet filter input tcp dport 443 accept
$ sudo nft add rule inet filter input icmp type echo-request accept
$ sudo nft add rule inet filter input drop
```

---

## 11. Network Applications

### 11.1 Web Browsers

**Command-line browsers:**
```bash
# Install text-based browsers
$ sudo apt-get install w3m lynx links2

# Browse with w3m
$ w3m https://www.debian.org

# Browse with lynx
$ lynx https://www.debian.org

# Browse with links2
$ links2 https://www.debian.org
```

**Browser automation with curl:**
```bash
# Download webpage
$ curl -O https://www.debian.org/index.html

# Follow redirects
$ curl -L https://www.debian.org

# With headers
$ curl -I https://www.debian.org

# POST request
$ curl -X POST -d "param1=value1&param2=value2" https://example.com/form
```

#### 11.1.1 Spoofing User-Agent String

**With curl:**
```bash
$ curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" https://example.com
```

**With wget:**
```bash
$ wget --user-agent="Custom Agent String" https://example.com
```

### 11.2 Mail System

#### 11.2.1 Email Basics

**Mail User Agents (MUA):**
```bash
# Install command-line mail clients
$ sudo apt-get install mutt alpine nail

# Send mail with mail command
$ echo "Body of email" | mail -s "Subject" user@example.com

# Send mail with attachment
$ echo "Body" | mail -s "Subject" -a /path/to/file user@example.com
```

#### 11.2.2 Modern Mail Service Configuration

**Postfix configuration:**
```bash
# Install postfix
$ sudo apt-get install postfix

# During installation, choose:
# Internet Site
# System mail name: example.com

# Basic configuration files:
# /etc/postfix/main.cf
# /etc/postfix/master.cf

# Check postfix status
$ sudo systemctl status postfix

# Test mail delivery
$ echo "Test email" | mail -s "Test" your-email@example.com

# View mail queue
$ mailq
$ sudo postqueue -p

# Flush mail queue
$ sudo postqueue -f
```

**Exim4 configuration:**
```bash
# Install exim4
$ sudo apt-get install exim4

# Configure exim4
$ sudo dpkg-reconfigure exim4-config

# Choose configuration type:
# internet site; mail is sent and received directly using SMTP

# Check exim4 status
$ sudo systemctl status exim4

# Test configuration
$ sudo exim4 -bP
```

### 11.3 Remote Access with SSH

#### 11.3.1 SSH Basics

**Generate SSH keys:**
```bash
# Generate RSA key pair
$ ssh-keygen -t rsa -b 4096

# Generate Ed25519 key pair
$ ssh-keygen -t ed25519

# Generate with comment
$ ssh-keygen -t rsa -b 4096 -C "user@hostname"

# View public key
$ cat ~/.ssh/id_rsa.pub
```

**Basic SSH connection:**
```bash
# Connect to remote host
$ ssh username@remote-host

# Connect with specific port
$ ssh -p 2222 username@remote-host

# Connect with specific key
$ ssh -i ~/.ssh/custom_key username@remote-host

# Execute command remotely
$ ssh username@remote-host "ls -la"
```

#### 11.3.2 SSH Configuration File

**~/.ssh/config example:**
```bash
Host myserver
    HostName server.example.com
    User username
    Port 2222
    IdentityFile ~/.ssh/myserver_key
    ServerAliveInterval 60
    ServerAliveCountMax 3

Host *
    AddKeysToAgent yes
    UseKeychain yes
    IdentityFile ~/.ssh/id_rsa
```

**System-wide SSH configuration (/etc/ssh/sshd_config):**
```bash
# Change default port
Port 2222

# Disable root login
PermitRootLogin no

# Allow specific users
AllowUsers username1 username2

# Allow groups
AllowGroups sshusers

# Public key authentication only
PasswordAuthentication no
PubkeyAuthentication yes

# Restart SSH service after changes
$ sudo systemctl restart ssh
```

#### 11.3.3 SSH Agent

**Start SSH agent:**
```bash
# Start agent
$ eval "$(ssh-agent -s)"

# Add key to agent
$ ssh-add ~/.ssh/id_rsa

# List keys in agent
$ ssh-add -l

# Remove key from agent
$ ssh-add -d ~/.ssh/id_rsa

# Clear all keys
$ ssh-add -D
```

**Persistent SSH agent with keychain:**
```bash
# Install keychain
$ sudo apt-get install keychain

# Add to ~/.bashrc
eval $(keychain --eval --agents ssh id_rsa)
```

#### 11.3.4 SSH Tunneling

**Local port forwarding:**
```bash
# Forward local port 8080 to remote server's port 80
$ ssh -L 8080:localhost:80 username@remote-host

# Access remote MySQL through SSH tunnel
$ ssh -L 3306:localhost:3306 username@remote-host
```

**Remote port forwarding:**
```bash
# Make local port 3000 accessible on remote host port 8080
$ ssh -R 8080:localhost:3000 username@remote-host
```

**Dynamic port forwarding (SOCKS proxy):**
```bash
# Create SOCKS proxy on local port 1080
$ ssh -D 1080 username@remote-host

# Configure browser to use SOCKS proxy:
# SOCKS Host: localhost Port: 1080
```

#### 11.3.5 SSH File Transfer

**Using scp:**
```bash
# Copy file to remote host
$ scp localfile.txt username@remote-host:/remote/path/

# Copy file from remote host
$ scp username@remote-host:/remote/path/file.txt .

# Copy directory recursively
$ scp -r localdir username@remote-host:/remote/path/

# Preserve file attributes
$ scp -p file.txt username@remote-host:/remote/path/
```

**Using rsync over SSH:**
```bash
# Sync directory to remote host
$ rsync -avz localdir/ username@remote-host:/remote/path/

# Sync from remote host
$ rsync -avz username@remote-host:/remote/path/ localdir/

# Dry run (show what would be transferred)
$ rsync -avzn localdir/ username@remote-host:/remote/path/

# Delete files on destination not in source
$ rsync -avz --delete localdir/ username@remote-host:/remote/path/
```

**Using sftp:**
```bash
# Interactive SFTP session
$ sftp username@remote-host

# SFTP commands:
sftp> ls
sftp> lls          # Local ls
sftp> cd remote-dir
sftp> lcd local-dir
sftp> put localfile
sftp> get remotefile
sftp> mput *.txt   # Multiple put
sftp> mget *.pdf   # Multiple get
sftp> exit
```

### 11.4 Print Server and Utilities

#### 11.4.1 CUPS Setup

**Install CUPS:**
```bash
$ sudo apt-get install cups cups-client

# Start CUPS service
$ sudo systemctl start cups
$ sudo systemctl enable cups

# Add user to lpadmin group
$ sudo usermod -a -G lpadmin username
```

**Command-line printer management:**
```bash
# List printers
$ lpstat -p -d

# Set default printer
$ lpoptions -d printer_name

# Print file
$ lpr filename.txt

# Print with options
$ lpr -o media=A4 -o sides=two-sided-long-edge filename.pdf

# Check print queue
$ lpq

# Cancel print job
$ lprm job_id
```

**Using lpadmin:**
```bash
# Add network printer
$ sudo lpadmin -p printer_name -E -v ipp://printer-ip/ipp/print -m everywhere

# Remove printer
$ sudo lpadmin -x printer_name

# Enable/disable printer
$ sudo cupsenable printer_name
$ sudo cupsdisable printer_name
```

### 11.5 Other Network Services

#### 11.5.1 NTP Time Synchronization

```bash
# Install NTP
$ sudo apt-get install ntp

# Check NTP status
$ timedatectl status
$ ntpq -p

# Force time sync
$ sudo systemctl restart ntp
$ sudo ntpdate -s pool.ntp.org

# Configure NTP servers in /etc/ntp.conf
server 0.debian.pool.ntp.org iburst
server 1.debian.pool.ntp.org iburst
server 2.debian.pool.ntp.org iburst
server 3.debian.pool.ntp.org iburst
```

#### 11.5.2 Samba File Sharing

**Install and configure Samba:**
```bash
$ sudo apt-get install samba

# Edit /etc/samba/smb.conf
[shared]
    comment = Shared Directory
    path = /srv/samba/shared
    browseable = yes
    read only = no
    guest ok = yes
    create mask = 0755

# Create shared directory
$ sudo mkdir -p /srv/samba/shared
$ sudo chmod 0777 /srv/samba/shared

# Add Samba user
$ sudo smbpasswd -a username

# Restart Samba
$ sudo systemctl restart smbd
$ sudo systemctl enable smbd
```

**Access Samba shares:**
```bash
# List shares on server
$ smbclient -L //server-name -U username

# Connect to share
$ smbclient //server-name/sharename -U username

# Mount Samba share
$ sudo mount -t cifs //server-name/sharename /mnt/share -o username=user,password=pass
```

---

## 12. GUI System

### 12.1 GUI Desktop Environments

**Install desktop environments:**
```bash
# GNOME
$ sudo apt-get install gnome

# KDE Plasma
$ sudo apt-get install kde-plasma-desktop

# XFCE
$ sudo apt-get install xfce4

# LXDE
$ sudo apt-get install lxde

# MATE
$ sudo apt-get install mate-desktop-environment

# Cinnamon
$ sudo apt-get install cinnamon-desktop-environment
```

**Select display manager:**
```bash
# Choose display manager
$ sudo dpkg-reconfigure gdm3   # GNOME
$ sudo dpkg-reconfigure sddm   # KDE
$ sudo dpkg-reconfigure lightdm # Lightweight
```

### 12.2 X Server Configuration

**X server commands:**
```bash
# Start X server
$ startx

# With specific window manager
$ startx /usr/bin/i3

# X server configuration file
# /etc/X11/xorg.conf
# /etc/X11/xorg.conf.d/
```

**X server troubleshooting:**
```bash
# Generate X configuration
$ sudo X -configure
# Creates xorg.conf.new in current directory

# Test X configuration
$ X -config xorg.conf.new

# View X logs
$ cat /var/log/Xorg.0.log

# Check display information
$ xdpyinfo
$ xrandr
```

### 12.3 Remote Desktop

**VNC server setup:**
```bash
# Install VNC server
$ sudo apt-get install tigervnc-standalone-server

# Set VNC password
$ vncpasswd

# Start VNC server
$ vncserver :1 -geometry 1920x1080 -depth 24

# List VNC sessions
$ vncserver -list

# Kill VNC session
$ vncserver -kill :1
```

**XRDP for RDP access:**
```bash
$ sudo apt-get install xrdp

# Start xrdp
$ sudo systemctl start xrdp
$ sudo systemctl enable xrdp

# Configure in /etc/xrdp/xrdp.ini
```

### 12.4 Clipboard Management

**X clipboard commands:**
```bash
# Copy to clipboard
$ echo "text" | xclip -selection clipboard
$ cat file.txt | xclip -selection clipboard

# Paste from clipboard
$ xclip -selection clipboard -o
$ xclip -selection clipboard -o > file.txt

# Copy file contents
$ xclip -selection clipboard -in < file.txt

# Copy image to clipboard
$ convert image.png png:- | xclip -selection clipboard -t image/png
```

**Primary vs clipboard selections:**
```bash
# Primary selection (middle mouse)
$ echo "text" | xclip           # Copy to primary
$ xclip -o                     # Paste from primary

# Clipboard selection (Ctrl+C/Ctrl+V)
$ echo "text" | xclip -selection clipboard
$ xclip -selection clipboard -o
```

---

## 13. I18N and L10N

### 13.1 Locale Configuration

**Check current locale:**
```bash
$ locale
$ echo $LANG
$ locale -a  # List available locales
```

**Generate locales:**
```bash
# Edit /etc/locale.gen and uncomment needed locales
# en_US.UTF-8 UTF-8
# fr_FR.UTF-8 UTF-8
# ja_JP.UTF-8 UTF-8

$ sudo locale-gen
```

**Set system locale:**
```bash
# Configure locale
$ sudo dpkg-reconfigure locales

# Set locale variables in /etc/default/locale
LANG="en_US.UTF-8"
LC_ALL="en_US.UTF-8"

# Apply immediately
$ . /etc/default/locale
```

### 13.2 Keyboard Input

**Console keyboard layout:**
```bash
# List available keymaps
$ localectl list-keymaps

# Set console keymap
$ sudo loadkeys us
$ sudo loadkeys fr

# Persistent console keymap in /etc/default/keyboard
XKBMODEL="pc105"
XKBLAYOUT="us"
XKBVARIANT=""
XKBOPTIONS=""
```

**X Window keyboard layout:**
```bash
# Set X keyboard layout
$ setxkbmap us
$ setxkbmap fr

# With options
$ setxkbmap -layout us,fr -option grp:alt_shift_toggle

# View current layout
$ setxkbmap -query
```

#### 13.2.1 Input Method Framework (IBus)

**Install IBus:**
```bash
$ sudo apt-get install ibus ibus-anthy ibus-hangul ibus-mozc ibus-table

# Start IBus daemon
$ ibus-daemon -drx

# Configure IBus
$ ibus-setup
```

### 13.3 Character Encoding

**Check file encoding:**
```bash
$ file -i filename.txt
$ enca filename.txt

# Detect encoding
$ chardet filename.txt
```

**Convert encoding:**
```bash
# Convert to UTF-8
$ iconv -f ISO-8859-1 -t UTF-8 input.txt > output.txt

# List available encodings
$ iconv -l

# Convert filenames
$ convmv -f shift_jis -t utf8 -r --notest directory/
```

**Fix encoding issues:**
```bash
# Remove BOM (Byte Order Mark)
$ sed -i '1s/^\xEF\xBB\xBF//' file.txt

# Convert DOS to Unix line endings
$ dos2unix file.txt

# Convert Unix to DOS line endings
$ unix2dos file.txt
```

---

## 14. System Tips

### 14.1 Console Tips

#### 14.1.1 Recording Shell Activities

**Using script command:**
```bash
# Start recording
$ script -t 2> timing.log -a session.log

# Record with timing for replay
$ scriptreplay timing.log session.log

# Record with typescript command
$ typescript session.log
```

**Screen recording with asciinema:**
```bash
$ sudo apt-get install asciinema
$ asciinema rec
# Ctrl-D to stop
$ asciinema play recording.cast
```

#### 14.1.2 Screen Program

**GNU Screen basics:**
```bash
# Start screen
$ screen

# Screen commands (Ctrl-a then):
# c - Create new window
# n - Next window
# p - Previous window
# d - Detach screen
# A - Set window title
# " - List windows
# 0-9 - Switch to window number
# S - Split screen horizontally
# Q - Remove split

# Reattach to screen
$ screen -r

# List screen sessions
$ screen -ls

# Named screen session
$ screen -S session_name
$ screen -r session_name
```

**Screen configuration (~/.screenrc):**
```bash
# Enable mouse support
mousetrack on

# Status bar
hardstatus alwayslastline
hardstatus string '%{= kG}[ %{G}%H %{g}][%= %{= kw}%?%-Lw%?%{r}(%{W}%n*%f%t%?(%u)%?%{r})%{w}%?%+Lw%?%?%= %{g}][%{B} %m-%d %{W}%c %{g}]'

# Scrollback buffer
defscrollback 10000
```

#### 14.1.3 Navigating Directories

**Directory navigation tricks:**
```bash
# Quick directory navigation
$ cd -          # Previous directory
$ pushd /path   # Save current, cd to /path
$ popd          # Return to saved directory
$ dirs          # Show directory stack

# Use CDPATH for quick access
export CDPATH=.:~:/etc:/usr/share/doc

# Directory bookmarks
$ cd /very/long/path/to/directory
$ export M1=$PWD
$ cd $M1
```

### 14.2 Monitoring System

#### 14.2.1 Process Monitoring

**Using ps:**
```bash
# Show all processes
$ ps aux
$ ps -ef

# Show process tree
$ ps axjf
$ pstree

# Show processes by user
$ ps -u username

# Show processes by group
$ ps -G groupname

# Custom format
$ ps -eo pid,user,pcpu,pmem,cmd --sort=-pcpu | head -10
```

**Using top/htop:**
```bash
# Interactive process viewer
$ top
$ htop

# Batch mode
$ top -b -n 1 > top_output.txt

# Sort by CPU
$ top -o %CPU

# Sort by memory
$ top -o %MEM

# Monitor specific process
$ top -p pid1,pid2,pid3
```

#### 14.2.2 System Resource Monitoring

**Memory usage:**
```bash
$ free -h
$ cat /proc/meminfo

# Detailed memory info
$ vmstat -s

# Monitor memory usage over time
$ watch -n 1 free -h
```

**Disk usage:**
```bash
$ df -h
$ du -sh /path
$ du -h --max-depth=1 /path

# Find large files
$ find / -type f -size +100M -exec ls -lh {} \; 2>/dev/null

# Monitor disk I/O
$ iostat -x 1
$ iotop
```

**Network monitoring:**
```bash
$ netstat -tulpn
$ ss -tulpn

# Real-time network traffic
$ iftop
$ nethogs
$ bmon

# Bandwidth monitoring
$ vnstat
$ vnstati -s -i eth0 -o /tmp/network.png
```

### 14.3 System Maintenance

#### 14.3.1 Log Management

**Viewing logs:**
```bash
# System logs
$ sudo journalctl
$ sudo journalctl -f          # Follow
$ sudo journalctl -u service  # By service
$ sudo journalctl --since "2024-01-01" --until "2024-01-02"
$ sudo journalctl --boot      # Current boot
$ sudo journalctl -k          # Kernel messages

# Traditional log files
$ tail -f /var/log/syslog
$ tail -f /var/log/auth.log
$ tail -f /var/log/kern.log
$ dmesg | tail -20
```

**Log rotation:**
```bash
# Configure log rotation in /etc/logrotate.d/
# Example: /etc/logrotate.d/myapp
/path/to/logfile {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    postrotate
        /bin/kill -HUP $(cat /var/run/myapp.pid 2>/dev/null) 2>/dev/null || true
    endscript
}

# Test logrotate configuration
$ sudo logrotate -d /etc/logrotate.conf

# Force log rotation
$ sudo logrotate -f /etc/logrotate.conf
```

#### 14.3.2 Disk Maintenance

**Filesystem check:**
```bash
# Check filesystem
$ sudo fsck /dev/sda1

# Check ext2/3/4 filesystem
$ sudo e2fsck -f /dev/sda1

# Check and repair
$ sudo fsck -y /dev/sda1
```

**Disk optimization:**
```bash
# Defragment ext2/3/4
$ sudo e4defrag /mount/point

# Check disk health with SMART
$ sudo smartctl -a /dev/sda

# Short test
$ sudo smartctl -t short /dev/sda

# Long test
$ sudo smartctl -t long /dev/sda
```

### 14.4 Backup and Recovery

#### 14.4.1 Simple Backups with tar

```bash
# Full backup
$ sudo tar -czpf /backup/full-backup-$(date +%Y%m%d).tar.gz --exclude=/backup --exclude=/proc --exclude=/sys --exclude=/dev --exclude=/run /

# Incremental backup
$ sudo tar -g /backup/snapshot.snar -czpf /backup/inc-backup-$(date +%Y%m%d).tar.gz /home

# Extract backup
$ sudo tar -xzpf backup.tar.gz -C /restore/path

# List backup contents
$ tar -tzf backup.tar.gz
```

#### 14.4.2 Rsync Backups

```bash
# Mirror backup
$ rsync -av --delete /source/ /backup/destination/

# Backup with progress
$ rsync -av --progress /source/ /backup/

# Backup over SSH
$ rsync -avz -e ssh /local/path/ user@remote:/backup/path/

# Exclude files
$ rsync -av --exclude='*.tmp' --exclude='temp/' /source/ /backup/
```

---

## 15. Data Management

### 15.1 Archive and Compression

**Common compression tools:**
```bash
# gzip
$ gzip file.txt
$ gunzip file.txt.gz
$ zcat file.txt.gz

# bzip2
$ bzip2 file.txt
$ bunzip2 file.txt.bz2
$ bzcat file.txt.bz2

# xz
$ xz file.txt
$ unxz file.txt.xz
$ xzcat file.txt.xz

# zip
$ zip archive.zip file1 file2
$ unzip archive.zip
$ unzip -l archive.zip  # List contents
```

**tar examples:**
```bash
# Create tar archive
$ tar -cvf archive.tar file1 file2 dir1

# Create compressed tar
$ tar -czvf archive.tar.gz file1 file2
$ tar -cjvf archive.tar.bz2 file1 file2
$ tar -cJvf archive.tar.xz file1 file2

# Extract tar archive
$ tar -xvf archive.tar
$ tar -xzvf archive.tar.gz
$ tar -xjvf archive.tar.bz2
$ tar -xJvf archive.tar.xz

# List contents
$ tar -tvf archive.tar
$ tar -tzvf archive.tar.gz

# Extract specific files
$ tar -xzvf archive.tar.gz file1 dir1/file2
```

### 15.2 Data Encryption

#### 15.2.1 GnuPG Basics

**Generate keys:**
```bash
$ gpg --gen-key
# Choose: (1) RSA and RSA (default)
# Keysize: 4096
# Expiration: 0 (does not expire)
# Real name: Your Name
# Email: your@email.com
# Comment: Optional comment

# Generate revocation certificate
$ gpg --gen-revoke your@email.com > revocation.cert

# List keys
$ gpg --list-keys
$ gpg --list-secret-keys
```

**Encrypt and decrypt files:**
```bash
# Encrypt file for recipient
$ gpg --encrypt --recipient recipient@email.com file.txt

# Decrypt file
$ gpg --decrypt file.txt.gpg > file.txt

# Symmetric encryption (password-based)
$ gpg --symmetric file.txt
$ gpg --decrypt file.txt.gpg > file.txt

# Sign and encrypt
$ gpg --sign --encrypt --recipient recipient@email.com file.txt

# Verify signature
$ gpg --verify file.txt.asc file.txt
```

### 15.3 Version Control with Git

**Basic Git workflow:**
```bash
# Initialize repository
$ git init

# Configure user
$ git config --global user.name "Your Name"
$ git config --global user.email "your@email.com"

# Clone repository
$ git clone https://github.com/user/repo.git

# Check status
$ git status

# Add files
$ git add file.txt
$ git add .                     # Add all

# Commit changes
$ git commit -m "Commit message"

# View history
$ git log
$ git log --oneline --graph --all

# Push to remote
$ git push origin main

# Pull from remote
$ git pull origin main

# Create branch
$ git branch feature-branch
$ git checkout feature-branch
$ git checkout -b feature-branch  # Create and switch

# Merge branch
$ git checkout main
$ git merge feature-branch

# Resolve conflicts
$ git mergetool
```

---

## 16. Data Conversion

### 16.1 Text Data Conversion

**Character set conversion:**
```bash
# Convert between encodings
$ iconv -f ISO-8859-1 -t UTF-8 input.txt > output.txt

# Check encoding
$ file -i file.txt
$ enca -L none file.txt

# Convert line endings
$ dos2unix file.txt
$ unix2dos file.txt

# Convert tabs to spaces
$ expand -t 4 file.txt > file-spaces.txt

# Convert spaces to tabs
$ unexpand -t 4 file.txt > file-tabs.txt
```

**Document conversion:**
```bash
# PDF to text
$ pdftotext document.pdf document.txt

# HTML to text
$ lynx -dump -nolist file.html > file.txt
$ html2text file.html > file.txt

# Word document to text
$ antiword document.doc > document.txt
$ catdoc document.doc > document.txt

# Markdown to HTML
$ pandoc document.md -o document.html
```

### 16.2 Image Conversion

**Using ImageMagick:**
```bash
# Convert format
$ convert image.jpg image.png

# Resize image
$ convert image.jpg -resize 800x600 resized.jpg

# Create thumbnail
$ convert image.jpg -thumbnail 100x100 thumb.jpg

# Convert multiple images
$ mogrify -format png *.jpg

# Add watermark
$ convert image.jpg watermark.png -gravity southeast -composite watermarked.jpg

# Create montage
$ montage *.jpg -tile 3x3 -geometry +5+5 montage.jpg
```

---

## 17. Programming

### 17.1 Shell Scripting

**Basic shell script template:**
```bash
#!/bin/bash
# Script name: myscript.sh
# Description: Brief description
# Usage: ./myscript.sh [options]

set -euo pipefail  # Exit on error, undefined var, pipe fail
IFS=$'\n\t'        # Set Internal Field Separator

# Constants
readonly SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Functions
usage() {
    echo "Usage: $SCRIPT_NAME [options]"
    echo "Options:"
    echo "  -h, --help     Show this help"
    echo "  -v, --version  Show version"
}

main() {
    local option=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--version)
                echo "Version 1.0"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done
    
    # Main script logic
    echo "Hello, World!"
}

# Run main function
main "$@"
```

**Shell script examples:**
```bash
#!/bin/bash
# Example 1: File processing
for file in *.txt; do
    echo "Processing $file"
    # Process each file
done

# Example 2: User input
read -p "Enter your name: " name
echo "Hello, $name!"

# Example 3: Error handling
if ! command -v git >/dev/null 2>&1; then
    echo "Error: git is not installed" >&2
    exit 1
fi

# Example 4: Logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> script.log
}

log "Script started"
```

### 17.2 Python Scripting

**Basic Python script:**
```python
#!/usr/bin/env python3
"""
Script name: myscript.py
Description: Brief description
"""

import sys
import os
import argparse
import logging

def setup_logging():
    """Configure logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Process some files.')
    parser.add_argument('files', nargs='+', help='Files to process')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Verbose output')
    return parser.parse_args()

def process_file(filename):
    """Process a single file."""
    try:
        with open(filename, 'r') as f:
            content = f.read()
        # Process content here
        return content.upper()
    except IOError as e:
        logging.error(f"Cannot read file {filename}: {e}")
        return None

def main():
    """Main function."""
    args = parse_arguments()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logging.info(f"Processing {len(args.files)} files")
    
    for filename in args.files:
        if not os.path.exists(filename):
            logging.warning(f"File {filename} does not exist")
            continue
        
        result = process_file(filename)
        if result and args.output:
            with open(args.output, 'a') as f:
                f.write(result + '\n')
        elif result:
            print(result)

if __name__ == '__main__':
    main()
```

This completes the comprehensive terminal tutorial guide covering all major topics from the Debian Reference document. Each section includes practical examples that can be executed on a Debian system, with detailed explanations of concepts and their applications in real-world scenarios.

The guide covers:
1. Console basics and shell usage
2. Filesystem operations and permissions
3. Package management with apt and dpkg
4. System initialization and services
5. Network configuration and services
6. GUI systems and desktop environments
7. Internationalization and localization
8. System monitoring and maintenance
9. Data management and backup
10. Scripting and programming basics

Each topic is presented with executable examples that users can follow step-by-step to build their Debian system administration skills.

