// Defense Evasion Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const rules = [
    // T1070: Indicator Removal on Host
    {
        id: 'T1070',
        name: 'Indicator Removal on Host',
        description: 'Adversaries may delete or modify logs to hide activity.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return (command.match(/rm|truncate|git\s*clone|nmap|bash\s*\/tmp\//) && 
                    description.match(/deletion|truncation|logs|suspicious/i));
        }
    },
    {
        id: 'T1070.004',
        name: 'Indicator Removal on Host: File Deletion',
        description: 'Adversaries may delete files to hide activity.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/004/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/rm\s*.*\/var\/log|truncate\s*.*\/var\/log/);
        }
    },
    // T1562: Impair Defenses
    {
        id: 'T1562',
        name: 'Impair Defenses',
        description: 'Adversaries may impair security tools or monitoring.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const process = (event.process || '').toString().toLowerCase().trim();
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return (process.match(/systemctl|bash|nmap/) || 
                    command.match(/systemctl|bash\s*\/tmp\/|nmap/)) && 
                   description.match(/tampering|disabling|security|av|suspicious/i);
        }
    },
    {
        id: 'T1562.001',
        name: 'Impair Defenses: Disable or Modify Tools',
        description: 'Adversaries may disable security tools.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/001/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/systemctl\s*.*disable|service\s*.*stop|killall\s*.*iptables/);
        }
    },
    // T1027: Obfuscated Files or Information
    {
        id: 'T1027',
        name: 'Obfuscated Files or Information',
        description: 'Adversaries may obfuscate files or commands.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/base64|xxd|obfuscate/);
        }
    },
    // T1222: File and Directory Permissions Modification
    {
        id: 'T1222',
        name: 'File and Directory Permissions Modification',
        description: 'Adversaries may modify permissions to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1222/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/chmod|chown/);
        }
    }
];
