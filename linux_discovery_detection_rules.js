// Discovery Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const rules = [
    // T1018: System Network Configuration Discovery
    {
        id: 'T1018',
        name: 'System Network Configuration Discovery',
        description: 'Adversaries may discover network configurations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1018/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return (command.match(/nmap|ifconfig|ip\s*addr|netstat|curl|git\s*clone|python\s*-c/) && 
                    description.match(/network|interface|routing|suspicious/i));
        }
    },
    // T1087: Account Discovery
    {
        id: 'T1087',
        name: 'Account Discovery',
        description: 'Adversaries may enumerate accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1087/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return (command.match(/whoami|id|cat\s*.*\/etc\/passwd|nmap/) && 
                    description.match(/account|user|enumeration|suspicious/i));
        }
    },
    // T1135: Network Share Discovery
    {
        id: 'T1135',
        name: 'Network Share Discovery',
        description: 'Adversaries may search for network shares.',
        mitre_link: 'https://attack.mitre.org/techniques/T1135/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return (command.match(/smbclient|mount\s*.*cifs|git\s*clone|python\s*-c|nmap/) && 
                    description.match(/network\s*share|smb|cifs|suspicious/i));
        }
    },
    // T1082: System Information Discovery
    {
        id: 'T1082',
        name: 'System Information Discovery',
        description: 'Adversaries may gather system information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1082/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/uname|dmidecode|lscpu|cat\s*.*\/proc\/cpuinfo/);
        }
    }
];
