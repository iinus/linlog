# linlog
Compiled with python 3.6.3. \
A linux log analyzer that can (hopefully) help within the field of file forensics. It is designed to exract authentication events from 
var/log/auth.log and general events from var/log/syslog. The user can specify its own rules, a time interval, a certain user and a certain
logfile. 

#### Installation
<pre>
git clone git@github.com:iinus/linlog.git 
cd linlog
</pre>

#### Usage 
<pre>
python3 linlog.py [options] [arg1] [arg2] 

Options: 
  --version        show program's version number and exit 
  -h, --help       show this help message and exit 
  -l LOG           Specify log file. Default is summary of auth.log and
                   syslog. 
  -u USER          Specify user to output from auth.log. Default is all users. 
  -r NAME "REGEX"  Add your own rule as a regex. Format: NAME "REGEX".
                   Example: VERSION "(\bversion)((.*))" 
  --clear          Clear your rules. 
  -t "TIME"        Specify minimum time interval in format "Jan 7 17:35:37". 

</pre>

#### Examples
<pre>
python3 linlog.py
outputs all extracted events from sylog and auth.log

python3 linlog.py -u user
[*] user
* INVALID USER *
Counted 3 times in /var/log/auth.log
[+] SSH:  
May 25 04:22:19 SSH authentication failure from 105.235.116.254 port 48680
May 25 03:32:59 SSH authentication failure from 46.101.235.214 port 39336
May 25 02:16:09 SSH authentication failure from 128.199.221.18 port 38716

python3 linlog.py -t "May 25 13:52:33"
outputs all extracted events after the date specified

python3 linlog.py -r VERSION "\bversion(.*)"
Add your rule to the list of rules. You will se it summarized at the bottom next time you run linlog.

python3 linlog.py --clear
Clear all rules you specified
</pre>
