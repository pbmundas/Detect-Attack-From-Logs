// Detection rules for Discovery tactic on Linux systems
const rules = [
    // T1087 - Account Discovery
    {
        id: 'T1087',
        name: 'Account Discovery',
        description: 'Adversaries may enumerate accounts and groups on the system.',
        mitre_link: 'https://attack.mitre.org/techniques/T1087/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('whoami') || command.includes('id') || command.includes('getent')) && 
                   description.includes('enumeration of local user accounts');
        }
    },
    {
        id: 'T1087.001',
        name: 'Account Discovery: Local Account',
        description: 'Adversaries may enumerate local accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1087/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('getent passwd') || command.includes('cat /etc/passwd');
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
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('uname -a') || command.includes('lscpu') || command.includes('hostnamectl');
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
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('ls -la') || command.includes('find /');
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
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('nmap -sV') || command.includes('netcat -z');
        }
    },
    // T1135 - Network Share Discovery
    {
        id: 'T1135',
        name: 'Network Share Discovery',
        description: 'Adversaries may search for network shares like SMB/CIFS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1135/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('smbclient') || command.includes('mount -t cifs')) && 
                   description.includes('searching for mounted network shares');
        }
    },
    // T1018 - System Network Configuration Discovery
    {
        id: 'T1018',
        name: 'System Network Configuration Discovery',
        description: 'Adversaries may discover network configuration details.',
        mitre_link: 'https://attack.mitre.org/techniques/T1018/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('ifconfig') || command.includes('ip addr') || command.includes('route')) && 
                   description.includes('network interface listing');
        }
    },
    // T1040 - Network Sniffing
    {
        id: 'T1040',
        name: 'Network Sniffing',
        description: 'Adversaries may sniff network traffic.',
        mitre_link: 'https://attack.mitre.org/techniques/T1040/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('tcpdump') || command.includes('wireshark');
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
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('ps aux') || command.includes('top');
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
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('dpkg -l') || command.includes('rpm -qa');
        }
    },
    {
        id: 'T1518.001',
        name: 'Software Discovery: Security Software Discovery',
        description: 'Adversaries may enumerate security software.',
        mitre_link: 'https://attack.mitre.org/techniques/T1518/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('clamav') || command.includes('auditd');
        }
    },
    // T1016 - System Network Connections Discovery
    {
        id: 'T1016',
        name: 'System Network Connections Discovery',
        description: 'Adversaries may enumerate network connections.',
        mitre_link: 'https://attack.mitre.org/techniques/T1016/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('netstat -an') || command.includes('ss -tuln');
        }
    }
];