const rules = [
    // T1087 - Account Discovery
    {
        id: 'T1087',
        name: 'Account Discovery',
        description: 'Adversaries may attempt to get a listing of accounts on a system or within a domain.',
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
        description: 'Adversaries may attempt to get a listing of local system accounts.',
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
        description: 'Adversaries may attempt to get a listing of domain accounts.',
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
        description: 'Adversaries may attempt to get a listing of email accounts.',
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
        description: 'Adversaries may attempt to get a listing of cloud accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1087/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws|azure|gcp/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/aws\.amazon|azure|googleapis/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud account');
        }
    },
    // T1016 - System Network Configuration Discovery
    {
        id: 'T1016',
        name: 'System Network Configuration Discovery',
        description: 'Adversaries may look for details about the network configuration.',
        mitre_link: 'https://attack.mitre.org/techniques/T1016/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/ipconfig|ifconfig|netstat/)) {
                    return true;
                }
                if (eid === '5156' && event.Application) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system network configuration');
        }
    },
    {
        id: 'T1016.001',
        name: 'System Network Configuration Discovery: System Network Connections Discovery',
        description: 'Adversaries may attempt to get a listing of network connections.',
        mitre_link: 'https://attack.mitre.org/techniques/T1016/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('netstat')) {
                    return true;
                }
                if (eid === '5156' && event.DestinationPort) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system network connections');
        }
    },
    // T1033 - System Owner/User Discovery
    {
        id: 'T1033',
        name: 'System Owner/User Discovery',
        description: 'Adversaries may attempt to identify the primary user of a system.',
        mitre_link: 'https://attack.mitre.org/techniques/T1033/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/whoami|query user/)) {
                    return true;
                }
                if (eid === '4624' && event.TargetUserName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system owner/user');
        }
    },
    // T1049 - System Network Connections Discovery
    {
        id: 'T1049',
        name: 'System Network Connections Discovery',
        description: 'Adversaries may attempt to get information on network connections.',
        mitre_link: 'https://attack.mitre.org/techniques/T1049/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('netstat')) {
                    return true;
                }
                if (eid === '5156' && event.DestinationPort) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system network connections');
        }
    },
    // T1057 - Process Discovery
    {
        id: 'T1057',
        name: 'Process Discovery',
        description: 'Adversaries may attempt to get information about running processes.',
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
                if (eid === '4688' && event.NewProcessName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('process discovery');
        }
    },
    // T1069 - Permission Groups Discovery
    {
        id: 'T1069',
        name: 'Permission Groups Discovery',
        description: 'Adversaries may attempt to identify permission groups.',
        mitre_link: 'https://attack.mitre.org/techniques/T1069/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/net localgroup|net group/)) {
                    return true;
                }
                if (eid === '4672' && event.Privileges) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('permission groups');
        }
    },
    // T1082 - System Information Discovery
    {
        id: 'T1082',
        name: 'System Information Discovery',
        description: 'Adversaries may gather information about the system.',
        mitre_link: 'https://attack.mitre.org/techniques/T1082/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/systeminfo|hostname/)) {
                    return true;
                }
                if (eid === '6' && event.TargetUserName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system information');
        }
    },
    // T1120 - Peripheral Device Discovery
    {
        id: 'T1120',
        name: 'Peripheral Device Discovery',
        description: 'Adversaries may attempt to gather information about attached peripheral devices.',
        mitre_link: 'https://attack.mitre.org/techniques/T1120/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/wmic diskdrive|lsblk/)) {
                    return true;
                }
                if (eid === '1006' && event.DeviceName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('peripheral device');
        }
    },
    // T1135 - Network Share Discovery
    {
        id: 'T1135',
        name: 'Network Share Discovery',
        description: 'Adversaries may look for shared drives and folders on computers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1135/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/net share|net use/)) {
                    return true;
                }
                if (eid === '5145' && event.ShareName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network share');
        }
    },
    // T1201 - Password Policy Discovery
    {
        id: 'T1201',
        name: 'Password Policy Discovery',
        description: 'Adversaries may attempt to access password policy information.',
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
                if (eid === '4670' && event.Privileges) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('password policy');
        }
    },
    // T1482 - Domain Trust Discovery
    {
        id: 'T1482',
        name: 'Domain Trust Discovery',
        description: 'Adversaries may attempt to gather information on domain trust relationships.',
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
                if (eid === '4672' && event.Privileges?.includes('SeEnableDelegationPrivilege')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain trust');
        }
    },
    // T1518 - Software Discovery
    {
        id: 'T1518',
        name: 'Software Discovery',
        description: 'Adversaries may attempt to get a listing of software installed on the system.',
        mitre_link: 'https://attack.mitre.org/techniques/T1518/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/wmic product|dir software/)) {
                    return true;
                }
                if (eid === '1000' && event.ApplicationName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('software discovery');
        }
    },
    {
        id: 'T1518.001',
        name: 'Software Discovery: Security Software Discovery',
        description: 'Adversaries may attempt to get a listing of security software.',
        mitre_link: 'https://attack.mitre.org/techniques/T1518/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/antivirus|firewall/)) {
                    return true;
                }
                if (eid === '1000' && event.ApplicationName?.toLowerCase().match(/av|firewall/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('security software');
        }
    },
    // T1614 - System Location Discovery
    {
        id: 'T1614',
        name: 'System Location Discovery',
        description: 'Adversaries may gather information about the physical location of a victim system.',
        mitre_link: 'https://attack.mitre.org/techniques/T1614/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/ipconfig|geolocation/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().includes('geolocation')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system location');
        }
    },
    // T1615 - Group Policy Discovery
    {
        id: 'T1615',
        name: 'Group Policy Discovery',
        description: 'Adversaries may gather information on Group Policy settings.',
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
        description: 'Adversaries may attempt to enumerate device drivers.',
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
        description: 'Adversaries may enumerate logs to find information.',
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
        description: 'Adversaries may attempt to get a listing of systems in a network.',
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
        description: 'Adversaries may reflectively load code to gather system information.',
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
    // Additional techniques and sub-techniques can be added for full coverage...
];
