# linlog
Compiled with python 3.6.3. \
A linux log analyzer that can (hopefully) help within the field of file forensics. It is designed to extract authentication events from 
var/log/auth.log and general events from var/log/syslog. It also catches certain events from other logfiles, like firewall from /var/log/messages. The user can specify its own rules, a time interval, a certain user and a certain
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
May 25 04:22:19 SSH authentication failure from 105.235.116.254:48680
May 25 03:32:59 SSH authentication failure from 46.101.235.214:39336
May 25 02:16:09 SSH authentication failure from 128.199.221.18:38716

python3 linlog.py -t "May 25 13:52:33"
outputs all extracted events after the date specified

python3 linlog.py -r VERSION "\bversion(.*)"
Add your rule to the list of rules. You will se it summarized at the bottom next time you run linlog.

python3 linlog.py --clear
Clear all rules you specified

python3 linlog.py -l messages
Prints summary of specified logfile. Output is similar to:
[*] System clock 
2019-06-17 14:26:27 UTC (1560781587)

[*] Firewall 
Jun 17 18:47:45 BLOCK 198.252.206.25:443 ---> 10.52.109.13:41642
Jun 17 18:45:28 BLOCK 216.58.207.206:443 ---> 10.52.109.13:46452
Jun 17 18:45:10 BLOCK 216.58.207.206:443 ---> 10.52.109.13:46450
....

</pre>

#### Further work
* Optimize or restructure code.
* Make it possible to specify combinations of options.
* Check out more VPN clients (unfortunatley the messages differs from VPN to VPN).
* Abstract away more unuseful information and add more information that can be relevant. E.g. installed packages and reboots.
* Work more on visual presentation. An idea is to let the user interact and expand elements.
