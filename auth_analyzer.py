#!/usr/bin/python

import sys
import gzip 
import re
import datetime
import colors
import rules
import pathlib

users =[]
logs = {}

def main(logfile, useroption, time_int):
    try:
        log = gzip.open(logfile, 'r') if '.gz' in logfile else open(logfile, 'r')
    except FileNotFoundError:
        print("Wrong file or file path")
        sys.exit(1)
    username = None
    ip = None

    for line in log:
        # extract date, ip, port and user  
        if (rules.DATE(line)):
            date = rules.DATE(line).group(0).rstrip()
        if (date > time_int):
            date = colors.TIME + date + colors.CEND
            if(rules.USER(line)):
                username = rules.USER(line).group(2)
                if username not in users:
                    addUser(username, date, useroption)
            elif (rules.USER_ROOT(line)):
                username = rules.USER_ROOT(line).group(2)
                if username not in users:
                    addUser(username, date, useroption)
            if username in logs and (rules.USER_ROOT(line) or rules.USER(line)): # don't add all users if option is set 
                logs[username].counter +=1
                if rules.INVALID_USER(line):
                    logs[username].invalid = True
                if(rules.IP(line)):
                    ip = colors.IP + rules.IP(line).group(0).rstrip() + colors.CEND
                if (rules.PORT(line)):
                    port = colors.PORT + ":" + rules.PORT(line).group(2) + colors.CEND
                    ip = ip + port

                # su
                if rules.SUC_SU(line):
                    su = rules.SUC_SU(line).group(3)
                    logs[username].su[su] = date
                elif rules.FAILED_SU(line):
                    su = rules.FAILED_SU(line).group(3)
                    logs[username].su[su] = date

                # sudo 
                elif rules.SUDO(line):
                    cmd =" "
                    if (rules.SUDOERS(line)):
                        cmd += rules.SUDOERS(line).group(0) + " "
                    cmd += rules.SUDO(line).group(3) + rules.SUDO(line).group(4)
                    logs[username].sudo[cmd] = date

                # ssh
                elif rules.SSH_FAILURE(line):
                    logs[username].failed_ssh[date] = ip

                # sessions
                elif rules.SESSIONS(line):
                    session = rules.SESSIONS(line).group(0)
                    logs[username].sessions[session] = date
                
                # Failed and accepted passwords
                elif rules.PASSWORD_ATTEMPTS(line):
                    if ("Failed password") in line: 
                        logs[username].failed[ip] = date                
                    else: 
                        logs[username].success[ip] = date 

                # Other auth failures
                elif rules.AUTH_FAILURE(line) and ip is None:
                    auth_type = " " + rules.AUTH_FAILURE(line).group(2).strip("(")
                    logs[username].auth_fail[date] = auth_type + " authentication failure"
                

    log.close()

    if len(users) > 0: 
        print("\n" + colors.HEADER  +  " *** SUMMARY " + logfile + " ***   " + "\n" + colors.CEND)    
        for user in users:
            print( colors.USER  + "[*] " +  user + colors.CEND  )
            if logs[user].invalid:
                print( colors.WARNING + "* INVALID USER *" + colors.CEND  )
            print( "Counted " + colors.ID +  str(logs[user].counter) + colors.CEND  + " times in " + logfile )
            if (len(logs[str(user)].failed) > 0 ): 
                print(colors.BOLD + "[+] Failed pwd logins: " + colors.CEND)
                for failed in sorted(logs[str(user)].failed, key=logs[str(user)].failed.get, reverse=True):
                    print(logs[str(user)].failed[failed] + " failed password from " + failed)
            if (len(logs[str(user)].success) > 0 ):
                print(colors.BOLD + "[+] Successfull pwd logins: " + colors.CEND)
                for suc in sorted(logs[str(user)].success, key=logs[str(user)].success.get, reverse=True):
                    print(str(logs[str(user)].success[suc]) + " accepted password from " + 
                    suc)  
            if (len(logs[str(user)].su) > 0):
                print(colors.BOLD + "[+] Su:  " + colors.CEND)
                for su in sorted(logs[str(user)].su, key=logs[str(user)].su.get, reverse=True):
                    print( str(logs[str(user)].su[su]) + " failed su " + su )    
            if (len(logs[str(user)].failed_ssh) > 0):
                print(colors.BOLD + "[+] SSH:  " + colors.CEND)
                for ssh in sorted(logs[str(user)].failed_ssh, key=logs[str(user)].failed_ssh.get, reverse=True):
                    print( ssh + " SSH authentication failure from " +  str(logs[str(user)].failed_ssh[ssh].strip("\n")) )  
            if (len(logs[str(user)].sessions) > 0):
                print( colors.BOLD + "[+] Sessions: " + colors.CEND)
                for session in sorted(logs[str(user)].sessions, key=logs[str(user)].sessions.get, reverse=True):
                    print( str(logs[str(user)].sessions[session].strip("\n")) + " " + session )
            if (len(logs[str(user)].sudo) > 0):
                print( colors.BOLD + "[+] Sudo: " + colors.CEND)
                for cmd in sorted(logs[str(user)].sudo, key=logs[str(user)].sudo.get, reverse=True):
                    print(logs[str(user)].sudo[cmd] + cmd.strip("\n"))
            if (len(logs[str(user)].auth_fail) > 0):
                print( colors.BOLD + "[+] Authentication failures " + colors.CEND)
                for msg in sorted(logs[str(user)].auth_fail,  reverse=True):
                    print( msg + logs[str(user)].auth_fail[msg])
            print("\n")
    
def addUser(username, date, useroption):
    if useroption is None and username is not None:
        users.append(username)
        logs[username] = Log(username)
        if date is not None and logs[username].firstAttempt is None:
            logs[username].lastAttempt = date
            logs[username].firstAttempt = date
    else:
        if username == useroption:
            users.append(username)
            logs[username] = Log(username)


class Log:
    def __init__(self, usr):
        self.usr = usr
        self.counter = 0
        self.failed = {}
        self.success = {}
        self.failed_ssh = {}
        self.su = {}
        self.commands = {}
        self.lastAttempt = None
        self.firstAttempt = None   
        self.invalid = False
        self.sessions = {}
        self.sudo = {}
        self.auth_fail = {}

if __name__ == "__main__": 
    main()