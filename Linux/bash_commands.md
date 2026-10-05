1. show operative system
~~~bash
date; uname -a; hostname
cat /etc/os-release || cat /etc/release
~~~


2. Network Connections & Artifacts
~~~bash
ss -antp || netstat -antp
~~~
Lists all active TCP network connections alongside their process IDs 
~~~bash
ss -antp || netstat -antp
~~~
Inspects network interfaces
~~~bash
ip a || ifconfig -a
~~~
Displays the kernel routing table
~~~bash
route -n 
~~~


3. Process & Binary Analysis
Generates a highly detailed hierarchical tree of all running processes
~~~bash
ps auxfww
~~~
Lists all open files and network sockets tied to active processes
~~~bash
lsof -i
~~~
Reveals the actual command line that launched a specific process
~~~bash
cat /proc/<PID>/cmdline
~~~
Extracts human-readable ASCII text from a suspicious binary to look for URLs or IPs
~~~bash
strings /path/to/binary | grep -i "http"
~~~



4. Users, Logins & Persistence
Shows who is currently logged in and what they are running
~~~bash
w
~~~
Displays a comprehensive history of user logins and reboots with exact times.
~~~bash
last -Faiwx
~~~
Filters out system accounts to show all users authorized to access a login shell.
~~~bash
cat /etc/passwd | grep -E -v 'nologin$|false$'
~~~
Inspects the command history file for a specific user to see what they executed.
~~~bash
cat ~/.bash_history
~~~
Lists scheduled cron jobs used for malicious persistence
~~~bash
crontab -l || ls -la /etc/cron*
~~~


5. Timeline & File System Analysis
Finds all files modified globally within the last 48 hours
~~~bash
find / -type f -mtime -2
~~~
Locates all SUID files (executables that run with root privileges and are often abused for privilege escalation).
~~~bash
find / -perm -4000 -type f
~~~
Pulls a file's raw metadata, showing its atime (access), mtime (modify), and ctime (change) timestamps.
~~~bash
stat /path/to/file
~~~
Searches through all local system logs recursively for specific alert terms.
~~~bash
grep -rin "error" /var/log/ 
~~~

