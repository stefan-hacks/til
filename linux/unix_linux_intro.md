# UNIX/Linux Command Line Mastery

## Section 1: The UNIX/Linux Operating System

### History and Overview

```bash
# Check your current shell
echo $SHELL

# Check system information
uname -a
cat /etc/os-release

# View Linux distribution details (if available)
lsb_release -a
```

### Basic System Navigation

```bash
# Display current directory
pwd

# List directory contents
ls
ls -l          # Long listing
ls -la         # Include hidden files
ls -lh         # Human readable sizes

# Change directories
cd /path/to/directory
cd ~           # Home directory
cd ..          # Parent directory
cd -           # Previous directory

# View system information
whoami         # Current user
who            # Logged in users
w              # Detailed user information
```

### File System Structure

```bash
# Explore key directories
ls /
ls /etc
ls /var
ls /home
ls /usr/bin

# Check disk usage
df -h          # Human readable disk space
du -sh ~       # Home directory size
```

## Section 2: Basic Commands

### File Operations

```bash
Manpages
man -k
man -navigation
command --help
man man

# Create files
touch file1.txt
touch file2.txt file3.txt

# Display file content
cat file1.txt
more file1.txt
less file1.txt

# Partial file display
head -10 /etc/passwd     # First 10 lines
tail -10 /etc/passwd     # Last 10 lines
tail -f /var/log/syslog  # Follow log file

# File information
file /bin/ls
wc file1.txt             # Line, word, character count
```

### File Management

```bash
# Copy files
cp file1.txt file1_backup.txt
cp -r dir1 dir2          # Recursive copy

# Move/rename files
mv file1.txt newname.txt
mv file1.txt ~/documents/

# Delete files
rm file1.txt
rm -r directory/         # Recursive delete
rm -i file*.txt          # Interactive delete

# Create directories
mkdir newdir
mkdir -p parent/child/grandchild  # Create parent directories
mktemp -d
```

### Wildcards and Pattern Matching

```bash
# Wildcard examples
ls *.txt                 # All text files
ls file?.txt             # file1.txt, file2.txt, etc.
ls [abc]*.txt            # Files starting with a, b, or c
ls file[0-9].txt         # file0.txt through file9.txt

# Advanced pattern matching
ls {file,doc}*.txt       # file*.txt or doc*.txt
ls !(file1).txt          # All txt files except file1.txt (extended glob)
```

### Command Sequencing

```bash
# Sequential execution
cd /etc && ls -l         # Only if first command succeeds
cd /nonexistent || pwd   # Second command runs if first fails

# Multiple commands
date; whoami; pwd        # Execute sequentially
(cd /etc && ls)          # Execute in subshell
```

## Section 3: Redirection and Pipes

### Input/Output Redirection

```bash
# Output redirection
ls -l > listing.txt              # Overwrite file
ls -l >> listing.txt             # Append to file

# Error redirection
ls /nonexistent 2> error.log     # Redirect errors only
ls /etc /nonexistent &> output.log  # Both stdout and stderr

# Input redirection
sort < unsorted.txt > sorted.txt
mail user@domain < message.txt
```

### Pipes and Filters

```bash
# Basic pipes
ls -l /etc | less
who | wc -l                     # Count logged in users

# Multiple pipes
ps aux | grep ssh | wc -l
cat /var/log/syslog | grep error | tail -20

# Using tee
ls -l /etc | tee listing.txt | wc -l
```

### Advanced Redirection

```bash
# Process substitution
# diff <(sort file1.txt) <(sort file2.txt)

# Here documents
cat << EOF
This is a multi-line
text block that will
be displayed
EOF

# Here strings
grep "search" <<< "this string contains search term"
```

## Section 4: vi/Vim Editor

### Basic Navigation

```bash
# Start vim
vim wordfile
vim +10 wordfile     # Start at line 10
```

### Command Mode Operations

```
# Cursor movement
h - left, j - down, k - up, l - right
w - next word, b - previous word
0 - start of line, $ - end of line
gg - first line, G - last line
50G - go to line 50

# Editing commands
i - insert before cursor
a - append after cursor
o - open new line below
O - open new line above
x - delete character
dd - delete line
5dd - delete 5 lines
yy - yank (copy) line
p - paste after cursor
P - paste before cursor
u - undo
Ctrl+r - redo
```

### Last Line Mode

```
# Saving and quitting
:w                    # Save
:q                    # Quit
:wq or :x            # Save and quit
:q!                   # Quit without saving
:w newfile.txt        # Save as new file

# Search and replace
/search_term          # Search forward
?search_term          # Search backward
:%s/old/new/g         # Replace all
:10,20s/old/new/g     # Replace in lines 10-20

# Configuration
:set number           # Show line numbers
:set nonumber         # Hide line numbers
:set ignorecase       # Case insensitive search
```

## Section 5: Searching and Replacing Text

### grep Commands

```bash
# Basic grep usage
grep "pattern" file.txt
grep -i "pattern" file.txt          # Case insensitive
grep -v "pattern" file.txt          # Invert match
grep -n "pattern" file.txt          # Show line numbers
grep -c "pattern" file.txt          # Count matches
grep -r "pattern" /path/to/dir      # Recursive search

# Extended grep
egrep "pattern1|pattern2" file.txt  # OR operation
grep -E "pattern{3}" file.txt       # Extended regex
```

### sed for Search and Replace

```bash
# Basic substitution
sed 's/old/new/' file.txt
sed 's/old/new/g' file.txt          # Global replacement
sed 's/old/new/2' file.txt          # Replace 2nd occurrence only

# In-place editing
sed -i 's/old/new/g' file.txt
sed -i.bak 's/old/new/g' file.txt   # Create backup

# Range operations
sed '10,20s/old/new/g' file.txt     # Lines 10-20
sed '10,$s/old/new/g' file.txt      # Line 10 to end
```

### Advanced Text Processing

```bash
# Multiple patterns
sed -e 's/old/new/' -e 's/foo/bar/' file.txt

# Delete lines
sed '/pattern/d' file.txt           # Delete matching lines
sed '10,20d' file.txt               # Delete lines 10-20

# Insert/append text
sed '5i\Insert this line' file.txt  # Insert before line 5
sed '5a\Append this line' file.txt  # Append after line 5
```

## Section 6: Recalling and Editing Commands

### Bash History

```bash
# View command history
history
history 20              # Last 20 commands
history | grep "pattern"

# Recall commands
!!                      # Last command
!n                      # Command number n
!-n                     # n commands back
!string                 # Last command starting with string

# Search history
Ctrl + r                # Reverse search
Ctrl + s                # Forward search
```

### Command Line Editing

```bash
# Keyboard shortcuts
Ctrl + a                # Beginning of line
Ctrl + e                # End of line
Ctrl + u                # Clear to beginning
Ctrl + k                # Clear to end
Ctrl + w                # Delete previous word
Alt + d                 # Delete next word
Ctrl + y                # Paste deleted text
```

# Vi Mode Tutorial for Bash Command Line

## Table of Contents

1.  [Introduction](#introduction)
2.  [Enabling Vi Mode](#enabling-vi-mode)
3.  [Modes of Operation](#modes-of-operation)
4.  [Basic Movement Commands](#basic-movement-commands)
5.  [Editing Commands](#editing-commands)
6.  [Searching and History](#searching-and-history)
7.  [Yanking and Putting](#yanking-and-putting)
8.  [Advanced Operations](#advanced-operations)
9.  [Customization](#customization)
10. [Tips and Tricks](#tips-and-tricks)

## Introduction

Vi mode in Bash provides a modal editing interface similar to the vi/vim text editor. Instead of using Emacs-style keybindings (which are Bash's default), you can use vi keybindings for more efficient command line editing.

## Enabling Vi Mode

### Temporary Enablement

```bash
set -o vi
```

### Permanent Enablement

Add to your `~/.bashrc` or `~/.bash_profile`:

```bash
set -o vi
```

### Check Current Mode

```bash
set -o | grep vi
# If enabled, shows: vi             on
```

## Modes of Operation

### 1\. Insert Mode (`i`, `a`, `I`, `A`)

- **Default mode** when you start typing
- Behaves like normal terminal input
- Press `ESC` to switch to Command mode

### 2\. Command Mode (Normal Mode)

- Activated by pressing `ESC`
- Navigate and edit using vi commands
- Press any insert command (`i`, `a`, etc.) to return to Insert mode

## Basic Movement Commands

### Character Movement

```
h    Move left (←)
j    Move down (in history) / next line
k    Move up (in history) / previous line
l    Move right (→)
```

### Word Movement

```
w    Move forward to next word beginning
W    Move forward to next WORD beginning (ignores punctuation)
b    Move backward to previous word beginning
B    Move backward to previous WORD beginning
e    Move to end of current word
E    Move to end of current WORD
```

### Line Movement

```
0    Move to beginning of line
^    Move to first non-whitespace character
$    Move to end of line
```

### History Navigation

```
j    Next command from history (like ↓)
k    Previous command from history (like ↑)
G    Go to last command in history
/    Search history (forward)
?    Search history (backward)
```

## Editing Commands

### Inserting Text

```
i    Insert before cursor
I    Insert at beginning of line
a    Append after cursor
A    Append at end of line
o    Open new line below current
O    Open new line above current
```

### Changing Text

```
r    Replace single character
R    Enter replace mode (overwrite)
c    Change (works with motion commands)
cc    Change entire line
C    Change from cursor to end of line
s    Substitute character (delete and insert)
S    Substitute entire line
```

### Deleting Text

```
x    Delete character under cursor
X    Delete character before cursor
d    Delete (works with motion commands)
dd    Delete entire line
D    Delete from cursor to end of line
```

### Undo/Redo

```
u    Undo last change
Ctrl+r    Redo (in Insert mode)
```

## Searching and History

### History Search

```
/pattern    Search forward in history
?pattern    Search backward in history
n    Repeat search in same direction
N    Repeat search in opposite direction
```

### History Navigation

```
Ctrl+p    Previous command (works in Insert mode)
Ctrl+n    Next command (works in Insert mode)
```

## Yanking and Putting (Copy/Paste)

### Yanking (Copy)

```
y    Yank (works with motion commands)
yy    Yank entire line
Y    Yank from cursor to end of line
```

### Putting (Paste)

```
p    Put after cursor
P    Put before cursor
```

## Advanced Operations

### Text Objects

```
di"    Delete inside quotes
da"    Delete around quotes (including quotes)
ci(    Change inside parentheses
ca[    Change around brackets
```

### Marks

```
m{a-z}    Set mark at cursor position
`{a-z}    Jump to mark
``    Jump back to previous position
```

### Counts and Repetition

```
3w        Move forward 3 words
5k        Move up 5 history entries
2dd       Delete 2 lines
3p        Paste 3 times
```

### Shell-Specific Commands

```
v    Open current command in $EDITOR (usually vim)
Ctrl+l    Clear screen (works in both modes)
Ctrl+w    Delete word before cursor (Insert mode)
Ctrl+u    Delete from cursor to beginning (Insert mode)
Ctrl+k    Delete from cursor to end (Insert mode)
```

## Customization

### Show Mode Indicator

Add to your `~/.bashrc`:

```bash
set show-mode-in-prompt on
# Or use a custom prompt:
# export PS1="\$(if [[ \$VI_MODE == 'cmd' ]]; then echo '[CMD] '; else echo '[INS] '; fi)$PS1"
```

### Vi Mode Variables

```bash
# Set key timeout (milliseconds)
set keyseq-timeout 100

# Control bell on invalid command
set bell-style none
```

### Key Bindings

Create/edit `~/.inputrc`:

```bash
set editing-mode vi
set keymap vi-command
# Add custom bindings
"\C-p": history-search-backward
"\C-n": history-search-forward
```

## Tips and Tricks

### 1\. Quick Movement

```bash
# Move to 3rd word: 3w
# Move to 2nd character: 2l
# Move to line beginning: 0
```

### 2\. Efficient Editing

```bash
# Change from cursor to end of word: cw
# Delete inside parentheses: di(
# Change entire line: cc
```

### 3\. History Mastery

```bash
# Search for previous apt command: /apt
# Repeat last search: n
# Go to last command: G
```

### 4\. Common Workflows

1.  **Edit complex command**: Press `v` to open in editor
2.  **Fix typo**: `ESC`, `b` to word, `r` to replace char
3.  **Reuse argument**: `ESC`, `!$` or `Alt+.` (in Insert mode)

### 5\. Mode Switching Efficiency

```bash
# Use Ctrl+[ instead of ESC
# Or remap Caps Lock to ESC for easier access
```

### 6\. Visual Selection

```bash
# Not available in standard bash vi mode
# Use Ctrl+v for block selection in some terminals
```

## Practice Exercises

1.  **Navigate**: Type a command, switch to Command mode, practice `h`, `j`, `k`, `l`
2.  **Edit**: Type `echo hello world`, change `hello` to `hi` using `cw`
3.  **History**: Search for previous commands with `/`
4.  **Yank/Paste**: Copy a word with `yw` and paste with `p`
5.  **Combination**: Use `d2w` to delete two words

## Common Issues and Solutions

### Problem: Stuck in Command Mode

**Solution**: Press `i` to return to Insert mode

### Problem: Can't see current mode

**Solution**: Add mode indicator to your prompt

### Problem: Some keys don't work

**Solution**: Check terminal settings, use `showkey -a` to test keycodes

## Further Resources

- `man bash` (search for "Readline" section)
- `bind -p` to see all bindings
- Vi/Vim tutorials for deeper understanding of modal editing

## Conclusion

Vi mode in Bash provides powerful, efficient command line editing once you overcome the initial learning curve. Start with basic movement (`h`, `j`, `k`, `l`), then gradually incorporate editing commands. The modal nature allows you to keep your hands on home row keys, reducing reliance on arrow keys and mouse.

**Remember**: You can always switch back to Emacs mode with `set -o emacs` if needed!

### History Configuration

```bash
# Customize history
export HISTSIZE=1000
export HISTFILESIZE=2000
export HISTCONTROL=ignoreboth    # Ignore duplicates and space-starting commands
export HISTTIMEFORMAT="%d/%m/%y %T "  # Add timestamps

# Persistent history across sessions
export PROMPT_COMMAND="history -a; history -c; history -r"
```

## Section 7: File Permissions and Access Control

### Understanding Permissions

```bash
lp and lpstat - mention

wc - wordcount

# View permissions
ls -l
ls -ld /directory       # Directory permissions
stat filename           # Detailed file information

# Permission components
# u - user, g - group, o - others
# r - read (4), w - write (2), x - execute (1)
```

### Changing Permissions

```bash
# Symbolic notation
chmod u+x file.txt              # Add execute for user
chmod g-w file.txt              # Remove write for group
chmod o=r file.txt              # Set others to read only
chmod a+w file.txt              # Add write for all
chmod u=rwx,g=rx,o= file.txt    # Set specific permissions

# Octal notation
chmod 755 file.txt              # rwxr-xr-x
chmod 644 file.txt              # rw-r--r--
chmod 600 file.txt              # rw-------

# Recursive permissions
chmod -R 755 directory/
```

### Ownership and Special Permissions

```bash
# Change ownership
chown user:group file.txt
chown user file.txt
chown :group file.txt
chown -R user:group directory/   # Recursive

# Change group
chgrp groupname file.txt

# Special permissions
chmod +t directory/              # Sticky bit
chmod u+s executable             # Setuid
chmod g+s executable             # Setgid
```

### User and Group Management

```bash
# User information
id
whoami
groups

# Switch users
su - username                    # Login shell
su username                      # Current shell
sudo -u username command         # Run as different user

# Switch groups
newgrp groupname

Hard links & sumbolic links
Create a symbolic link to a file or directory:

      ln [-s|--symbolic] /path/to/file_or_directory path/to/symlink

  Create a symbolic link relative to where the link is located:

      ln [-s|--symbolic] path/to/file_or_directory path/to/symlink

  Overwrite an existing symbolic link to point to a different file:

      ln [-sf|--symbolic --force] /path/to/new_file path/to/symlink

  Create a hard link to a file:

      ln /path/to/file path/to/hardlink

```

## Section 8: Filtering and Formatting Text

### cut Command

```bash
# Extract columns
cut -d: -f1,3 /etc/passwd       # Fields 1 and 3, colon delimiter
cut -c1-10,20-30 file.txt       # Characters 1-10 and 20-30
cut -f2- file.txt               # From field 2 to end
```

### awk Programming

```bash
# Basic field extraction
awk '{print $1}' file.txt               # First field
awk -F: '{print $1, $3}' /etc/passwd    # Custom delimiter
awk '{print NR, $0}' file.txt           # Add line numbers

# Conditional processing
awk '$3 > 1000 {print $1}' /etc/passwd  # Filter by field
awk '/pattern/ {print $2}' file.txt     # Filter by pattern
awk 'NF > 5' file.txt                   # Lines with more than 5 fields

# Advanced formatting
awk 'BEGIN {FS=":"; OFS="\t"} {print $1, $3}' /etc/passwd
awk '{sum += $3} END {print sum}' file.txt  # Sum column
```

### paste Command

```bash
# Merge files horizontally
paste file1.txt file2.txt
paste -d, file1.txt file2.txt           # Comma delimiter
paste -s file1.txt                      # Serial merge
```

### Text Formatting Tools

```bash
# Line numbering
nl file.txt
nl -ba file.txt                         # Number all lines
nl -i5 -v100 file.txt                   # Increment 5, start at 100

# Sorting and unique
sort file.txt
sort -r file.txt                        # Reverse sort
sort -n file.txt                        # Numeric sort
sort -u file.txt                        # Unique lines
sort -k2,2 file.txt                     # Sort by second field

# Finding duplicates
uniq file.txt
uniq -c file.txt                        # Count occurrences
uniq -d file.txt                        # Only duplicates
```

## Section 9: 

### Process Monitoring

```bash
# View processes
ps
ps aux                    # All processes detailed
ps -ef                    # Full format
ps -u username            # User's processes
ps --forest               # Show process tree

# Real-time monitoring
top
htop                      # Enhanced top (if installed)
```

### Process Control

```bash
# Killing processes
kill PID                  # Graceful termination
kill -9 PID               # Force kill
killall process_name      # Kill by name
pkill pattern             # Kill by pattern

# Job control
command &                 # Run in background
jobs                      # List background jobs
fg %1                     # Bring job 1 to foreground
bg %1                     # Resume job 1 in background
Ctrl + z                  # Suspend current job
```

### Process Priority

```bash
# Nice values
nice -n 10 command        # Start with nice value 10
renice 10 PID             # Change nice value of running process

# Background processing
nohup long_running_command &  # Continue after logout
disown %1                  # Remove job from shell's job table
```

### Process Groups

```bash
# Command grouping
(command1; command2; command3) > output.txt
{ command1; command2; command3; } > output.txt

# Time commands
time ls -l /etc
/usr/bin/time -v ls -l /etc  # Detailed timing
```

## Section 10: The User Environment

### Environment Variables

```bash
# View environment
env
printenv
set                        # Shell variables

# Common variables
echo $HOME
echo $PATH
echo $USER
echo $SHELL
echo $PWD
```

### Customizing Environment

```bash
# Set variables
export VARIABLE=value
export PATH=$PATH:/new/directory

# Persistent settings (add to ~/.bashrc)
export EDITOR=vim
export PS1='\u@\h:\w\$ '
export HISTSIZE=1000

# Source configuration files
source ~/.bashrc
. ~/.bashrc
```

### Shell Configuration Files

```bash
# Personal configuration
vim ~/.bashrc              # Bash configuration
vim ~/.profile             # Login configuration
vim ~/.bash_profile        # Bash login configuration

# Global configuration
/etc/profile
/etc/bash.bashrc
/etc/environment
```

### Aliases and Functions

```bash
# Create aliases
alias ll='ls -l'
alias la='ls -la'
alias rm='rm -i'
alias ..='cd ..'

# Persistent aliases (add to ~/.bashrc)
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'

# Shell functions
mkcd() { mkdir -p "$1" && cd "$1"; }
extract() {
    if [ -f $1 ] ; then
        case $1 in
            *.tar.bz2) tar xjf $1 ;;
            *.tar.gz) tar xzf $1 ;;
            *.bz2) bunzip2 $1 ;;
            *.rar) unrar x $1 ;;
            *.gz) gunzip $1 ;;
            *.tar) tar xf $1 ;;
            *.tbz2) tar xjf $1 ;;
            *.tgz) tar xzf $1 ;;
            *.zip) unzip $1 ;;
            *.Z) uncompress $1 ;;
            *.7z) 7z x $1 ;;
            *) echo "'$1' cannot be extracted via extract()" ;;
        esac
    else
        echo "'$1' is not a valid file"
    fi
}
```

## Section 11: More Basic Commands

### find Command

```bash
# Basic file finding
find /path -name "pattern"
find . -name "*.txt"
find /home -user username
find /var -type f -mtime -7    # Modified in last 7 days

# Advanced searching
find . -size +1M               # Files larger than 1MB
find . -empty                   # Empty files/directories
find . -perm 644               # Specific permissions
find . -name "*.txt" -exec ls -l {} \;  # Execute command on results

# Combined criteria
find /var \( -name "*.log" -o -name "*.out" \) -mtime +30
```

### Advanced File Operations

```bash
# File comparison
diff file1.txt file2.txt
cmp file1.txt file2.txt
comm file1.txt file2.txt

# File statistics
stat filename
wc file.txt                    # Line, word, character count
md5sum file.txt               # Checksum
sha256sum file.txt
```

### System Information

```bash
# Disk usage
df -h
du -sh *
du -h --max-depth=1 /path

# Memory information
free -h
cat /proc/meminfo

# System uptime and load
uptime
cat /proc/loadavg
```

### Network Commands

```bash
# Network configuration
#ip addr show
#ifconfig                      # Legacy
#netstat -tulpn               # Listening ports
#ss -tulpn                    # Modern socket statistics

# Network testing
ping hostname
traceroute hostname
curl -I website.com          # HTTP headers
wget url                     # File download
```

### Archive and Compression

```bash
# tar commands
tar -cvf archive.tar files/   # Create archive
tar -xvf archive.tar          # Extract archive
tar -czvf archive.tar.gz files/ # Compressed archive
tar -xzvf archive.tar.gz      # Extract compressed

# Compression
gzip file.txt                # Compress to file.txt.gz
gunzip file.txt.gz           # Decompress
bzip2 file.txt               # Better compression
bunzip2 file.txt.bz2
```

* * *

## Section 11: More Basic Commands (Continued)

### Advanced find Usage

```bash
# Complex search criteria
find /var/log -name "*.log" -mtime -1          # Logs modified in last day
find /home -user $(whoami) -size +10M          # My files > 10MB
find /etc -type f -perm 644                    # Files with specific permissions
find . -empty -exec rm -f {} \;                # Find and delete empty files

# Time-based searches
find /var -mmin -60                           # Modified in last hour
find /tmp -atime +30                          # Accessed more than 30 days ago
find . -newer reference_file                  # Newer than reference file

# Combined conditions
find /home \( -name "*.tmp" -o -name "*.temp" \) -delete
find /var \( -name "*.log" -a -size +100M \) -exec ls -lh {} \;
```

### xargs for Efficient Processing

```bash
# Basic xargs usage
find . -name "*.txt" | xargs ls -l
find /tmp -type f -mtime +7 | xargs rm -f

# Control arguments per command
find . -name "*.jpg" | xargs -n 10 cp -t /backup/  # 10 files per cp command
echo "file1 file2 file3" | xargs -n 1 touch

# Handle spaces in filenames
find . -name "*.doc" -print0 | xargs -0 ls -l
```

### locate Command

```bash
# Fast file searching (requires updatedb)
locate filename.txt
locate "*.conf"                          # Configuration files
locate -i "readme"                       # Case insensitive
locate -l 20 "*.txt"                     # Limit to 20 results

# Update locate database (requires sudo)
sudo updatedb
```

### Advanced sort and uniq

```bash
# Complex sorting
sort -t: -k3n -k1 /etc/passwd            # Sort by UID then username
ls -l | sort -k5 -nr                     # Sort by size descending
sort -u file.txt                         # Remove duplicates

# Using uniq effectively
sort file.txt | uniq -c                  # Count occurrences
sort file.txt | uniq -d                  # Show only duplicates
sort file.txt | uniq -u                  # Show only unique lines
```

### seq Command for Number Sequences

```bash
# Generate number sequences
seq 1 10                                # 1 to 10
seq 0 2 10                             # 0 to 10 in steps of 2
seq 10 -1 1                            # Countdown from 10 to 1
seq -f "File%03g.txt" 1 5              # Formatted output
seq -s ", " 1 10                       # Comma-separated
```

## Appendix A: Additional Exercises

### Exercise 1: File Creation and Basic Operations

```bash
# Create and navigate directories
mkdir -p ~/unix_practice/{documents,backups,scripts}
cd ~/unix_practice/documents

# Create sample files
touch {report1,report2,data}_{jan,feb,mar}.txt
ls -la

# Create a text file with content
cat > notes.txt << EOF
Important meeting notes:
- Project deadline: 2024-12-31
- Team members: Alice, Bob, Charlie
- Budget: $50,000
EOF
```

### Exercise 2: File Permissions Practice

```bash
# Create test files and directories
mkdir test_dir
touch test_dir/{file1,file2,file3}.txt

# Practice permission changes
chmod 755 test_dir
chmod 644 test_dir/*.txt
chmod +x test_dir/file1.txt

# Verify permissions
ls -l test_dir/
stat test_dir/file1.txt
```

### Exercise 3: Text Processing Challenge

```bash
# Create a sample data file
cat > employees.csv << EOF
John Doe,Engineering,75000,5
Jane Smith,Marketing,65000,3
Bob Johnson,Engineering,80000,7
Alice Brown,Sales,60000,2
Charlie Wilson,Engineering,90000,10
EOF

# Processing tasks
# 1. Extract names only
cut -d, -f1 employees.csv

# 2. Sort by salary (numeric)
sort -t, -k3 -n employees.csv

# 3. Find engineers with salary > 70000
awk -F, '$2 == "Engineering" && $3 > 70000' employees.csv

# 4. Count employees by department
cut -d, -f2 employees.csv | sort | uniq -c
```

### Exercise 4: Advanced find and Processing

```bash
# Create test structure
mkdir -p ~/test/{logs,data,backup}
touch ~/test/logs/{app,server,error}.log
touch ~/test/data/{2023,2024}_{q1,q2}.dat
echo "test content" > ~/test/important.txt

# Find exercises
# 1. Find all .log files modified in last 2 days
find ~/test -name "*.log" -mtime -2

# 2. Find files larger than 1KB
find ~/test -type f -size +1k

# 3. Find and compress old data files
find ~/test -name "2023_*.dat" -exec gzip {} \;

# 4. Find and backup important files
find ~/test -name "*important*" -exec cp {} ~/test/backup/ \;
```

## Appendix B: Command Quick Reference

### File and Directory Operations

```bash
# Navigation
pwd, cd, ls, pushd, popd, dirs

# File Operations
touch, cp, mv, rm, ln, file, stat

# Directory Operations
mkdir, rmdir, find, locate, tree

# Permissions
chmod, chown, chgrp, umask, getfacl, setfacl
```

### Text Processing

```bash
# Viewing Content
cat, more, less, head, tail, nl

# Searching
grep, egrep, fgrep, agrep, ack, rg

# Editing
sed, awk, cut, paste, join, tr

# Sorting and Filtering
sort, uniq, comm, diff, patch
```

### Process Management

```bash
# Process Information
ps, top, htop, pidof, pgrep, pstree

# Process Control
kill, killall, pkill, nice, renice, nohup

# Job Control
jobs, fg, bg, disown, wait, screen, tmux
```

### System Information

```bash
# System Status
uname, hostname, uptime, who, w, last

# Hardware Information
lscpu, free, df, du, lsblk, lspci, lsusb

# Network
ip, ifconfig, netstat, ss, ping, traceroute, curl, wget
```

### Archive and Compression

```bash
# Archive Tools
tar, cpio, dd, rsync

# Compression
gzip, gunzip, bzip2, bunzip2, xz, unxz, zip, unzip

# Examples
tar -czvf archive.tar.gz directory/
tar -xzvf archive.tar.gz
zip -r archive.zip directory/
```

### Advanced Text Manipulation

```bash
# Column-based processing
column -t file.txt                        # Format as table
paste file1.txt file2.txt                 # Merge files side by side
pr -2 file.txt                            # Two-column format

# Advanced grep
grep -A 3 -B 2 "pattern" file.txt         # Context lines
grep -r --include="*.c" "function" .      # Recursive with file pattern
grep -v "^#" file.txt                     # Exclude comment lines

# Stream editing
sed '1,5d' file.txt                       # Delete lines 1-5
sed '/pattern/d' file.txt                 # Delete matching lines
sed 's/old/new/g' file.txt                # Global replacement
```

### Shell Scripting Basics

```bash
# Create a simple backup script
cat > ~/bin/backup.sh << 'EOF'
#!/bin/bash
# Simple backup script
BACKUP_DIR="/backup/$(date +%Y%m%d)"
SOURCE_DIR="$1"

if [ -z "$SOURCE_DIR" ]; then
    echo "Usage: $0 <source_directory>"
    exit 1
fi

if [ ! -d "$SOURCE_DIR" ]; then
    echo "Error: Directory $SOURCE_DIR does not exist"
    exit 1
fi

mkdir -p "$BACKUP_DIR"
tar -czf "$BACKUP_DIR/backup_$(date +%H%M%S).tar.gz" "$SOURCE_DIR"
echo "Backup created: $BACKUP_DIR/backup_$(date +%H%M%S).tar.gz"
EOF

chmod +x ~/bin/backup.sh
```

### Environment Customization

```bash
# Advanced prompt customization
export PS1='\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '

# Useful aliases for your ~/.bashrc
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'

# History optimization
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTCONTROL=ignoreboth
export HISTIGNORE="ls:ll:la:cd:pwd:exit:history"

# Safety aliases
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
```

### Performance Monitoring

```bash
# Real-time monitoring
watch -n 1 'df -h /'                      # Disk space every second
vmstat 1 10                               # Virtual memory stats
iostat -dx 1                              # Disk I/O statistics
sar -u 1 10                               # CPU utilization

# Process monitoring
ps aux --sort=-%cpu | head -10           # Top CPU processes
ps aux --sort=-%mem | head -10           # Top memory processes

# Network monitoring
netstat -tulpn                           # Listening ports
ss -tulpn                                # Modern socket stats
iftop                                    # Bandwidth usage (if installed)
```

### Advanced System Administration

```bash
# User management
getent passwd                            # All users
getent group                             # All groups
id username                             # User information
last                                    # Login history

# Service management (systemd)
systemctl status servicename
systemctl start servicename
systemctl stop servicename
systemctl restart servicename
systemctl enable servicename

# Package management (varies by distribution)
# Debian/Ubuntu
apt update && apt upgrade
apt install package_name
apt remove package_name

# RedHat/CentOS
yum update
yum install package_name
yum remove package_name
```

### Regular Expressions Reference

```bash
# Basic regex patterns for grep/sed/awk
grep "^word" file.txt                    # Lines starting with word
grep "word$" file.txt                    # Lines ending with word
grep "wo.rd" file.txt                    # Any character between
grep "word.*word" file.txt               # Anything between words
grep "[0-9]" file.txt                    # Any digit
grep "[A-Za-z]" file.txt                 # Any letter
grep "\<word\>" file.txt                 # Whole word only

# Extended regex (egrep or grep -E)
egrep "(word1|word2)" file.txt           # OR condition
egrep "word{3}" file.txt                 # Exactly 3 occurrences
egrep "word{2,4}" file.txt               # 2 to 4 occurrences
egrep "word+" file.txt                   # One or more occurrences
egrep "word?" file.txt                   # Zero or one occurrence
```

This comprehensive tutorial covers all the essential command-line skills from the course material. Practice these commands regularly to build muscle memory and deepen your understanding of UNIX/Linux systems administration.

Remember:

- Use `man command` for detailed documentation
- Practice in a safe environment
- Always double-check destructive commands
- Build scripts to automate repetitive tasks

Happy learning! 🐧
