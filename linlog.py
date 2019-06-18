#!/usr/bin/python
# Compiled with python 3.6.3

import sys, stat, os
from optparse import OptionParser
import pathlib
import auth_analyzer
import sys_analyzer

if __name__=="__main__":

    if sys.version_info < (3, 0, 0):
        sys.stderr.write("linlog requires python version 3.6, please upgrade your python installation.")
        sys.exit(1)

    authlog = '/var/log/auth.log'
    syslog = '/var/log/syslog'
    time_int = '0'

    usage = "usage: python3 %prog [options] [arg1] [arg2]" 
    parser = OptionParser(usage=usage, version = "%prog 1.0")
    parser.add_option("-l", help="Specify log file. Default is summary of auth.log and syslog.", default=None, dest="log")
    parser.add_option("-u", help="Specify user to output from auth.log. Default is all users.", default=None, dest="user")
    parser.add_option("-r", help="Add your own rule as a regex. Format: NAME \"REGEX\".  Example: VERSION \"(\\bversion)((.*))\"", metavar="NAME \"REGEX\"", default=None, dest="rule")
    parser.add_option("--clear", help="Clear your rules.", action='store_true', default=None, dest="clear")
    parser.add_option("-t", help="Specify minimum time interval in format \"Jan 7 17:35:37\".", metavar="\"TIME\"", default=None, dest="time")
                
    (options, args) = parser.parse_args()

    if options.time:
        time_int = sys.argv[-1]

    if options.log: 
        logfile = sys.argv[-1]
        if "auth" in logfile:
            auth_analyzer.main(logfile, None, time_int)
        else:
            sys_analyzer.main(logfile, time_int)

    elif options.user:
        user = sys.argv[-1]
        auth_analyzer.main(authlog, user, time_int)

    elif options.rule:
        if len(sys.argv) == 4:
            user_rule = sys.argv[-1]
            name = sys.argv[2]
            rules = open('rules.py', 'a')
            rules.write ("\n" + name + " = lambda line : re.search(r'" + user_rule + "', line)")
            user_rules = pathlib.Path('user_rules')
            if not user_rules.is_file():
                user_rules_names = open('user_rules', 'w+')
            else:
                user_rules_names = open('user_rules', 'a')
            user_rules_names.write(name + "\n")
            rules.close()
            user_rules_names.close()
            print("Rule added.")
        else:
            print("You need to specify name and rule" + "\n")
            print (parser.print_help())
            sys.exit(1)

    elif options.clear:
        user_rule_names = []
        old_rules = []
        if pathlib.Path('user_rules').is_file():
            user_rules = open('user_rules', 'r', encoding='utf-8')
            for line in user_rules:
                user_rule_names.append(line.strip("\n"))
            user_rules.close()
            old = open("rules.py", "r", encoding='utf-8')
            for line in old:
                old_rules.append(line.strip("\n"))
            old.close()
            with open('rules.py', 'w') as rules:
                for old_rule in old_rules:
                    new_rule = True
                    for user_rule in user_rule_names:
                        user_rule = user_rule + " = "
                        if user_rule in old_rule:
                            new_rule = False
                    if (new_rule):
                        rules.write(old_rule + "\n")
                rules.close()
            os.remove('user_rules')
            print("Successfully cleared rules.")
        else:
            print("Rules already cleared.")
        
    else:
        if not os.getuid() is 0:
            print ("[-] Please run with SUDO")
            sys.exit(1)
        else: 
            auth_analyzer.main(authlog, None, time_int)
            sys_analyzer.main(syslog, time_int)
