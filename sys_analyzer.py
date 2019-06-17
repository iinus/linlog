#!/usr/bin/python

import re
import sys
import colors
import gzip
import rules
import color_rules
import pathlib

def main(logfile, time):
    systemClock = "Unknown (not set) "
    linuxVersion = "Unknown (not set) "
    hostname = "Unknown (not set) "
    logs = {}
    USBs = {}
    dhcpReq = {}
    dhcpPack = {}
    inputs = {}
    networkManagers = {}
    openVPN = {}
    daemonStart = {}
    cronjobs = {}
    avahi_dns = {}
    user_specified = {}
    user_rule_names = []

    try:
        log = gzip.open(logfile, 'r') if '.gz' in logfile else open(logfile, 'r', encoding='utf-8')
    except FileNotFoundError:
        print("Wrong file or file path")
        sys.exit(1)
    
    if pathlib.Path('user_rules').is_file():
        user_rules = open('user_rules', 'r', encoding='utf-8')
        for line in user_rules:
            user_rule_names.append(line.strip("\n"))
        user_rules.close()
    
    for line in log:
        date = rules.DATE(line).group(0)
        if (date > time):
            date = colors.TIME + date + colors.CEND
            if rules.PID(line):
                pid = "[pid:" + rules.PID(line).group(2).strip(" ") +  "] "
            if rules.LINUX_VERSION(line):
                linuxVersion = rules.LINUX_VERSION(line).group(0)
            elif rules.SYSTEM_CLOCK(line): 
                systemClock = rules.SYSTEM_CLOCK(line).group(3).strip("\n")
            elif rules.HOST_NAME(line):
                hostname = rules.HOST_NAME(line).group(2).strip("\n")
            elif rules.USB(line):
                msg = colorize(color_rules.USB_ID, colors.ID, rules.USB(line).group(0).strip("\n"))
                msg = colorize(color_rules.EXITING, colors.OKRED, msg)
                USBs[pid + msg] = date
            elif rules.DHCP_REQUEST(line):
                ip_port = colorize(color_rules.IP, colors.IP, rules.DHCP_IP(line).group(2))
                if rules.PORT(line):
                    ip_port += " " + colors.PORT + rules.PORT(line).group(0) + colors.CEND
                dhcpReq[date] = ip_port
            elif rules.DHCP_DHCPACK(line):
                ip_port = colorize(color_rules.IP, colors.IP, rules.DHCP_IP(line).group(2))
                if rules.PORT(line):
                    ip_port += " " + colors.PORT + rules.PORT(line).group(0) + colors.CEND
                dhcpPack[date] = ip_port
            elif rules.INPUT(line):
                input_ = rules.INPUT(line).group(3).strip("\n")
                input_ = colorize(color_rules.PATH, colors.PATH, input_)
                inputs[input_] = date 
            elif rules.NETWORK_MANAGER_ELEMENT(line) and rules.NETWORK_MANAGER_FILTER(line):
                element = rules.NETWORK_MANAGER_ELEMENT(line).group(3).strip("\n")
                msg = rules.NETWORK_MANAGER_ELEMENT(line).group(4).strip("\n")
                msg = colorize(color_rules.PATH, colors.PATH, msg)
                if element not in networkManagers:
                    networkManagers[element] = NetworkManagers(element)
                networkManagers[element].messages[msg] = date
            elif rules.OPENVPN(line):
                msg = rules.OPENVPN(line).group(0).strip("\n")
                openVPN[pid + msg] = date
            elif rules.OPENVPN_ERROR(line):
                msg = rules.OPENVPN_ERROR(line).group(5).strip("\n")
                openVPN[pid + msg] = date
            elif rules.DAEMON_START_EXIT(line):
                msg = colorize(color_rules.EXITING, colors.OKRED, rules.DAEMON_START_EXIT(line).group(3).strip("\n"))
                msg = pid + colorize(color_rules.STARTING, colors.OKGREEN, msg)
                daemonStart[msg] = date
            elif rules.CRON_JOBS(line):
                msg = rules.CRON_JOBS(line).group(0)
                cronjobs[date] = msg
            elif rules.AVAHI_DNS(line):
                msg = rules.AVAHI_DNS(line).group(4).strip("\n")
                msg = colorize(color_rules.IP, colors.IP, msg)
                msg = colorize(color_rules.STARTING, colors.OKGREEN, msg)
                msg = colorize(color_rules.EXITING, colors.OKRED, msg)
                avahi_dns[pid + msg] = date       
            for rule in user_rule_names:
                if rule not in user_specified and rule is not None:
                    user_specified[rule] = NetworkManagers(rule)
                method_to_call = getattr(rules,  rule)
                result = method_to_call(line)
                if result:
                    msg = result.group(0).strip("\n")
                    user_specified[rule].messages[date] = msg
                
    log.close()

    print("\n" + colors.HEADER + " *** SUMMARY " + logfile + " ***   " + colors.CEND + "\n")
    print(colors.USER + "[*] System clock " + colors.CEND + "\n" + systemClock + "\n")
    print(colors.USER + "[*] Linux version " + colors.CEND + "\n" + linuxVersion + "\n")
    print(colors.USER + "[*] Host name " + colors.CEND + "\n" + hostname )
    if len(USBs) > 0:
        print("\n" + colors.USER + "[*] USB " + colors.CEND)
        for usb in sorted(USBs, key=USBs.get, reverse=True):
            print(USBs[usb] + " " + transform(r'\[(.*)\]\s', "", usb))
    if (len(dhcpReq) > 0):
        print("\n" + colors.USER + "[*] DHCP requests " + colors.CEND)
        for ip in sorted(dhcpReq,  reverse=True):
            print (ip + " to "+  dhcpReq[ip] )
    if (len(dhcpPack) > 0):
        print("\n" + colors.USER + "[*] DHCP packs " + colors.CEND)
        for ip in sorted(dhcpPack, reverse=True):
           print (ip + " from "+  dhcpPack[ip]  ) 
    if (len(inputs) > 0):
        print("\n" + colors.USER + "[*] Input " + colors.CEND)
        for input_ in sorted(inputs, key=inputs.get, reverse=True):
            print (inputs[input_] + " " + input_) 
    if (len(openVPN) > 0):
        print("\n" + colors.USER + "[*] OpenVPN " + colors.CEND)
        for vpn in sorted(openVPN, reverse=True):
            print(openVPN[vpn] + " " + vpn)
    if (len(daemonStart) > 0):
        print("\n" + colors.USER + "[*] daemon start and exit " + colors.CEND)
        for start in sorted(daemonStart, key=daemonStart.get, reverse=True):
            print(daemonStart[start] + " " + start)
    if (len(cronjobs) > 0 ):
        print("\n" + colors.USER + "[*] cron jobs " + colors.CEND)
        for msg in sorted(cronjobs, reverse=True):
            print(msg + " " + cronjobs[msg])
    if (len(avahi_dns) > 0):
        print("\n" + colors.USER + "[*] mDNS/DNS-SD (Avahi daemon) " + colors.CEND)
        for msg in sorted(avahi_dns, key=avahi_dns.get, reverse=True):
            print(avahi_dns[msg]+ " " + msg)
    if len(networkManagers) > 0:
        print("\n" + colors.USER + "[*] Network Manager " + colors.CEND)
        for nm in networkManagers:
            if len(networkManagers[nm].messages) > 0:
                print(colors.BOLD + "[+] " + nm  + colors.CEND)
                for msg in sorted(networkManagers[nm].messages, key=networkManagers[nm].messages.get, reverse=True):
                    print(networkManagers[nm].messages[msg] + " " + msg)
    if len(user_specified) > 0:
        for rule in user_specified:
            print("\n" + colors.USER + "[*]  " + rule + colors.CEND)
            if len(user_specified[rule].messages) > 0:
                for msg in sorted(user_specified[rule].messages, reverse=True):
                    print( msg + " " + user_specified[rule].messages[msg])

def colorize(regex, color, text):
    return re.sub(regex, lambda m: color+'{}\x1b[0m'.format(m.group()), text)

def transform(regex, exp, text):
    return re.sub(regex, lambda m: exp.format(m.group()), text)

class NetworkManagers:
    def __init__(self, element):
        self.element = None
        self.messages = {}


if __name__ == "__main__": 
    main()