const rules = [
    // T1087 - Account Discovery
    {
        id: 'T1087',
        name: 'Account Discovery',
        description: 'Adversaries may enumerate accounts on a system or network.',
        mitre_link: 'https://attack.mitre.org/techniques/T1087/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/net user|net group|whoami/)) {
                    return true;
                }
                if (eid === '4624' && event.TargetUserName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('account discovery');
        }
    },
    {
        id: 'T1087.001',
        name: 'Account Discovery: Local Account',
        description: 'Adversaries may enumerate local accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1087/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net user') && 
                    !commandLine.toLowerCase().includes('domain')) {
                    return true;
                }
                if (eid === '4624' && event.TargetDomainName?.toLowerCase().includes('local')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('local account');
        }
    },
    {
        id: 'T1087.002',
        name: 'Account Discovery: Domain Account',
        description: 'Adversaries may enumerate domain accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1087/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net user /domain')) {
                    return true;
                }
                if (eid === '4624' && event.TargetDomainName && !event.TargetDomainName.toLowerCase().includes('local')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain account');
        }
    },
    {
        id: 'T1087.003',
        name: 'Account Discovery: Email Account',
        description: 'Adversaries may enumerate email accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1087/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/outlook|exchange/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/outlook\.office|exchange/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('email account');
        }
    },
    {
        id: 'T1087.004',
        name: 'Account Discovery: Cloud Account',
        description: 'Adversaries may enumerate cloud accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1087/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws iam|az ad user/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud account');
        }
    },
    // T1482 - Domain Trust Discovery
    {
        id: 'T1482',
        name: 'Domain Trust Discovery',
        description: 'Adversaries may discover domain trusts to identify attack paths.',
        mitre_link: 'https://attack.mitre.org/techniques/T1482/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/nltest|netdom/)) {
                    return true;
                }
                if (eid === '4662' && event.ObjectName?.toLowerCase().includes('trust')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain trust');
        }
    },
    // T1083 - File and Directory Discovery
    {
        id: 'T1083',
        name: 'File and Directory Discovery',
        description: 'Adversaries may enumerate files and directories.',
        mitre_link: 'https://attack.mitre.org/techniques/T1083/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/dir|ls|find/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('file discovery');
        }
    },
    // T1619 - Cloud Storage Object Discovery
    {
        id: 'T1619',
        name: 'Cloud Storage Object Discovery',
        description: 'Adversaries may enumerate cloud storage objects.',
        mitre_link: 'https://attack.mitre.org/techniques/T1619/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws s3 ls|gcloud storage ls/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/s3\.amazonaws\.com|storage\.googleapis\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud storage');
        }
    },
    // T1046 - Network Service Discovery
    {
        id: 'T1046',
        name: 'Network Service Discovery',
        description: 'Adversaries may scan for network services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1046/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/nmap|netstat|telnet/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network service discovery');
        }
    },
    // T1135 - Network Share Discovery
    {
        id: 'T1135',
        name: 'Network Share Discovery',
        description: 'Adversaries may enumerate network shares.',
        mitre_link: 'https://attack.mitre.org/techniques/T1135/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net share')) {
                    return true;
                }
                if (eid === '5140' && event.ShareName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network share discovery');
        }
    },
    // T1040 - Network Sniffing
    {
        id: 'T1040',
        name: 'Network Sniffing',
        description: 'Adversaries may sniff network traffic to gather information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1040/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/wireshark|tcpdump/)) {
                    return true;
                }
                if (eid === '3' && event.Protocol?.toLowerCase().includes('tcp') && 
                    event.DestinationPort?.toString().match(/80|443/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network sniffing');
        }
    },
    // T1201 - Password Policy Discovery
    {
        id: 'T1201',
        name: 'Password Policy Discovery',
        description: 'Adversaries may discover password policies.',
        mitre_link: 'https://attack.mitre.org/techniques/T1201/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net accounts')) {
                    return true;
                }
                if (eid === '4662' && event.ObjectName?.toLowerCase().includes('password policy')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('password policy');
        }
    },
    // T1120 - Peripheral Device Discovery
    {
        id: 'T1120',
        name: 'Peripheral Device Discovery',
        description: 'Adversaries may enumerate peripheral devices.',
        mitre_link: 'https://attack.mitre.org/techniques/T1120/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/wmic path win32_pnpentity|lsusb/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('pnpdevice')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('peripheral device');
        }
    },
    // T1069 - Permission Groups Discovery
    {
        id: 'T1069',
        name: 'Permission Groups Discovery',
        description: 'Adversaries may enumerate permission groups.',
        mitre_link: 'https://attack.mitre.org/techniques/T1069/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/net group|net localgroup/)) {
                    return true;
                }
                if (eid === '4662' && event.ObjectName?.toLowerCase().includes('group')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('permission groups');
        }
    },
    {
        id: 'T1069.001',
        name: 'Permission Groups Discovery: Local Groups',
        description: 'Adversaries may enumerate local permission groups.',
        mitre_link: 'https://attack.mitre.org/techniques/T1069/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net localgroup')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('local groups');
        }
    },
    {
        id: 'T1069.002',
        name: 'Permission Groups Discovery: Domain Groups',
        description: 'Adversaries may enumerate domain permission groups.',
        mitre_link: 'https://attack.mitre.org/techniques/T1069/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net group /domain')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain groups');
        }
    },
    {
        id: 'T1069.003',
        name: 'Permission Groups Discovery: Cloud Groups',
        description: 'Adversaries may enumerate cloud permission groups.',
        mitre_link: 'https://attack.mitre.org/techniques/T1069/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws iam list-groups|az ad group/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud groups');
        }
    },
    // T1057 - Process Discovery
    {
        id: 'T1057',
        name: 'Process Discovery',
        description: 'Adversaries may enumerate running processes.',
        mitre_link: 'https://attack.mitre.org/techniques/T1057/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/tasklist|ps/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('process discovery');
        }
    },
    // T1010 - Application Window Discovery
    {
        id: 'T1010',
        name: 'Application Window Discovery',
        description: 'Adversaries may enumerate application windows.',
        mitre_link: 'https://attack.mitre.org/techniques/T1010/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('getforegroundwindow')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('application window');
        }
    },
    // T1217 - Browser Bookmark Discovery
    {
        id: 'T1217',
        name: 'Browser Bookmark Discovery',
        description: 'Adversaries may enumerate browser bookmarks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1217/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('bookmarks')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/bookmarks\.html|places\.sqlite/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('browser bookmark');
        }
    },
    // T1613 - Container and Resource Discovery
    {
        id: 'T1613',
        name: 'Container and Resource Discovery',
        description: 'Adversaries may enumerate containers and resources.',
        mitre_link: 'https://attack.mitre.org/techniques/T1613/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/docker ps|kubectl get pods/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('container discovery');
        }
    },
    // T1622 - Debugger Evasion
    {
        id: 'T1622',
        name: 'Debugger Evasion',
        description: 'Adversaries may evade debuggers to avoid detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1622/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('isdebuggerpresent')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('debugger evasion');
        }
    },
    // T1082 - System Information Discovery
    {
        id: 'T1082',
        name: 'System Information Discovery',
        description: 'Adversaries may gather system information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1082/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/systeminfo|wmic bios|uname/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system information');
        }
    },
    // T1614 - System Location Discovery
    {
        id: 'T1614',
        name: 'System Location Discovery',
        description: 'Adversaries may discover system location information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1614/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/tzutil|locale/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system location');
        }
    },
    {
        id: 'T1614.001',
        name: 'System Location Discovery: System Language Discovery',
        description: 'Adversaries may discover system language settings.',
        mitre_link: 'https://attack.mitre.org/techniques/T1614/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('get-uiculture')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system language');
        }
    },
    // T1016 - System Network Configuration Discovery
    {
        id: 'T1016',
        name: 'System Network Configuration Discovery',
        description: 'Adversaries may gather network configuration information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1016/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/ipconfig|ifconfig|route print/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network configuration');
        }
    },
    {
        id: 'T1016.001',
        name: 'System Network Configuration Discovery: Internet Connection Discovery',
        description: 'Adversaries may check for internet connectivity.',
        mitre_link: 'https://attack.mitre.org/techniques/T1016/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('ping 8.8.8.8')) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp?.toString().includes('8.8.8.8')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('internet connection');
        }
    },
    // T1049 - System Network Connections Discovery
    {
        id: 'T1049',
        name: 'System Network Connections Discovery',
        description: 'Adversaries may enumerate network connections.',
        mitre_link: 'https://attack.mitre.org/techniques/T1049/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/netstat|ss/)) {
                    return true;
                }
                if (eid === '3' && event.SourcePort) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network connections');
        }
    },
    // T1033 - System Owner/User Discovery
    {
        id: 'T1033',
        name: 'System Owner/User Discovery',
        description: 'Adversaries may identify the system owner or users.',
        mitre_link: 'https://attack.mitre.org/techniques/T1033/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/whoami|id/)) {
                    return true;
                }
                if (eid === '4624' && event.TargetUserName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('user discovery');
        }
    },
    // T1007 - System Service Discovery
    {
        id: 'T1007',
        name: 'System Service Discovery',
        description: 'Adversaries may enumerate system services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/sc query|systemctl/)) {
                    return true;
                }
                if (eid === '7045') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system service');
        }
    },
    // T1124 - System Time Discovery
    {
        id: 'T1124',
        name: 'System Time Discovery',
        description: 'Adversaries may gather system time information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1124/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/date|time|w32tm/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system time');
        }
    },
    // T1497 - Virtualization/Sandbox Evasion
    {
        id: 'T1497',
        name: 'Virtualization/Sandbox Evasion',
        description: 'Adversaries may evade virtualization or sandbox environments.',
        mitre_link: 'https://attack.mitre.org/techniques/T1497/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/virtualization|sandbox|vmware/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('virtualization evasion');
        }
    },
    {
        id: 'T1497.001',
        name: 'Virtualization/Sandbox Evasion: System Checks',
        description: 'Adversaries may use system checks to evade virtualization detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1497/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/cpuid|vmware/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system checks');
        }
    },
    {
        id: 'T1497.002',
        name: 'Virtualization/Sandbox Evasion: User Activity Based Checks',
        description: 'Adversaries may use user activity checks to evade virtualization detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1497/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('user activity')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('user activity based checks');
        }
    },
    {
        id: 'T1497.003',
        name: 'Virtualization/Sandbox Evasion: Time Based Evasion',
        description: 'Adversaries may use time-based evasion to avoid detection in virtualized environments.',
        mitre_link: 'https://attack.mitre.org/techniques/T1497/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/sleep|delay/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('time based evasion');
        }
    },
    // T1518 - Software Discovery
    {
        id: 'T1518',
        name: 'Software Discovery',
        description: 'Adversaries may enumerate installed software.',
        mitre_link: 'https://attack.mitre.org/techniques/T1518/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/wmic product|dpkg|rpm/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('software discovery');
        }
    },
    {
        id: 'T1518.001',
        name: 'Software Discovery: Security Software Discovery',
        description: 'Adversaries may enumerate security software.',
        mitre_link: 'https://attack.mitre.org/techniques/T1518/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/wmic process where name.*antivirus|security/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('security software');
        }
    },
    // T1615 - Group Policy Discovery
    {
        id: 'T1615',
        name: 'Group Policy Discovery',
        description: 'Adversaries may enumerate group policies.',
        mitre_link: 'https://attack.mitre.org/techniques/T1615/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('gpresult')) {
                    return true;
                }
                if (eid === '4662' && event.ObjectName?.toLowerCase().includes('grouppolicy')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('group policy');
        }
    },
    // T1652 - Device Driver Discovery
    {
        id: 'T1652',
        name: 'Device Driver Discovery',
        description: 'Adversaries may enumerate device drivers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1652/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/driverquery|wmic path win32_systemdriver/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('device driver');
        }
    },
    // T1654 - Log Enumeration
    {
        id: 'T1654',
        name: 'Log Enumeration',
        description: 'Adversaries may enumerate system logs.',
        mitre_link: 'https://attack.mitre.org/techniques/T1654/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/wevtutil|tail \/var\/log/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.evtx|\.log/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('log enumeration');
        }
    },
    // T1018 - Remote System Discovery
    {
        id: 'T1018',
        name: 'Remote System Discovery',
        description: 'Adversaries may discover remote systems in the network.',
        mitre_link: 'https://attack.mitre.org/techniques/T1018/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/ping|arp -a|nslookup/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('remote system discovery');
        }
    },
    // T1620 - Reflective Code Loading
    {
        id: 'T1620',
        name: 'Reflective Code Loading',
        description: 'Adversaries may use reflective code loading to gather information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1620/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('reflective dll')) {
                    return true;
                }
                if (eid === '7' && event.ImageLoaded?.toLowerCase().includes('.dll')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('reflective code');
        }
    }
];