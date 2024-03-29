import re

IP = lambda line : re.search(r'(\bIP-DELETED)|(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9]))', line)
DATE = lambda line : re.search(r'^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}', line)
USER = lambda line : re.search(r'(\bfor user\s|\binvalid user\s|\buser=\s*|\blogname=|\bsu for\s|\bUSER=\s*|\bsudo:\s{2})(\S+)([^#]*)', line)
USER_ROOT = lambda line : re.search(r'(\bfor\s)(\broot)(\s)([^#]*)', line)
INVALID_USER = lambda line : re.search(r'\binvalid user\s', line)
PID = lambda line : re.search(r'(\[)(.*)(\]:\s)', line)
PORT = lambda line : re.search(r'(\bport\s)([0-9]{1,6})', line)
USB = lambda line : re.search(r'((\bUSB disconnect)([^#]*))|((\bnew|\bNew)([^#]*)(\busb | \bUSB)(.*)(\bdevice\s)([^#]*))', line)
USB_REC = lambda line : re.search(r'(\bid(.*)|\bSerialNumber=(.*)(\s))', line)
DHCP_REQUEST = lambda line : re.search(r'(\bDHCPREQUEST\s)', line)
DHCP_DHCPACK = lambda line : re.search(r'(\bDHCPACK\s)', line)
DHCP_IP = lambda line : re.search(r'(\bfrom\s|\bto\s)(\b(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9])))', line)
DHCP_IP = lambda line : re.search(r'(\bfrom\s|\bto\s)(\b(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9])))', line)
LINUX_VERSION = lambda line : re.search(r'(\bLinux\s)(\bversion\s)([^#]*)', line)
INPUT = lambda line : re.search(r'((\binput:\s)([^#]*))', line)
NETWORK_MANAGER_ELEMENT = lambda line : re.search(r'(\bNetworkManager)(.+)(\bConfig:\s|\bmanager:\s|\bpolicy:\s|\bkeyfile:\s|\bActivation:\s|\bdevice added\s)([^#]*)', line)
NETWORK_MANAGER_FILTER = lambda line : re.search(r'(\bpolicy:\s)|(\bnew\s)|(\badded\s)|(\bstate\s)|(\benabled\s)|(\badd)|(\bpath)|(\bstarting)',line)
SYSTEM_CLOCK = lambda line : re.search(r'(\bsystem clock\s)(\bto\s)([^#]*)', line)
PASSWORD_ATTEMPTS = lambda line : re.search(r'(\bAccepted password\s|\bFailed password\s)([^#]*)', line)
SUC_SU = lambda line : re.search(r'(\bSuccessful su\s)(.*)((\bby\s)(\w+))', line)
FAILED_SU = lambda line : re.search(r'(\bFAILED su\s)(.*)((\bby\s)(\w+))', line)
SSH_FAILURE = lambda line : re.search(r'(\bsshd)(.*)(\bauthentication failure|\binvalid user\s)', line)
AUTH_FAILURE = lambda line : re.search(r'((\(.*):auth)(.*)(\bauthentication failure)', line)
SESSIONS = lambda line : re.search(r'(\((.*):session\):\s)(.*)', line)
SUDO = lambda line : re.search(r'(\bsudo:)(.*)(\bCOMMAND=)([^#]*)', line)
SUDOERS = lambda line : re.search(r'(\buser NOT in sudoers)', line)
OPENVPN = lambda line : re.search(r'(\bStarted OpenVPN service)|(Failed to start OpenVPN connection to server)', line)
OPENVPN_ERROR = lambda line : re.search(r'(\bovpn-server)(\[(.*)\]:\s)(.*)(\berror:([^#]*))', line)
DAEMON_START_EXIT = lambda line : re.search(r'(\[(.*)\]:\s)((.*)(\bdaemon)(.*)(\bstarting|\bexiting)([^#]*))', line)
CRON_JOBS = lambda line : re.search(r'\b(Running @reboot jobs)', line)
HOST_NAME = lambda line : re.search(r'(\bHost name is\s)([^\s]*)', line)
AVAHI_DNS = lambda line : re.search(r'(\bavahi-daemon)(\[(.*)\]:\s)((.*)(\bJoining|\bLeaving)(.*)(\bmDNS|\bDNS-SD)(.*)(v4)([^#]*))', line)
FIREWALL = lambda line : re.search(r'([UFW BLOCK])(.*)(\bSRC=)(\S+)(.*)(\bDST=)(\S+)(.*)(\bSPT=)(\S+)(.*)(\bDPT=)(\S+)', line)
