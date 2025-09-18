// Discovery Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const discoveryRules = [
    // T1018: System Network Configuration Discovery
    {
        id: 'T1018',
        name: 'System Network Configuration Discovery',
        description: 'Adversaries may discover network configurations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1018/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.match(/nmap|ifconfig|ip addr|netstat|curl|git clone/) && 
                    description.match(/network.*configuration|interface.*listing|routing.*table/i)) ||
                   command.match(/bash \/tmp\//);
        }
    },
    // T1087: Account Discovery
    {
        id: 'T1087',
        name: 'Account Discovery',
        description: 'Adversaries may enumerate accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1087/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.match(/whoami|id|cat.*\/etc\/passwd|nmap/) && 
                    description.match(/account.*enumeration|local.*user/i)) ||
                   command.includes('bash /tmp/');
        }
    },
    // T1135: Network Share Discovery
    {
        id: 'T1135',
        name: 'Network Share Discovery',
        description: 'Adversaries may search for network shares.',
        mitre_link: 'https://attack.mitre.org/techniques/T1135/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.match(/smbclient|mount.*cifs|git clone|python -c|nmap/) && 
                    description.match(/searching.*network.*shares|smb.*cifs/i)) ||
                   command.match(/bash \/tmp\/|python -c/);
        }
    },
    // T1082: System Information Discovery
    {
        id: 'T1082',
        name: 'System Information Discovery',
        description: 'Adversaries may gather system information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1082/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/uname|dmidecode|lscpu|cat.*\/proc\/cpuinfo/);
        }
    }
];

module.exports = discoveryRules;
