// Credential Access Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const rules = [
    // T1003: OS Credential Dumping
    {
        id: 'T1003',
        name: 'OS Credential Dumping',
        description: 'Adversaries may dump credentials from OS stores.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            const log_type = (event.log_type || '').toString().toLowerCase().trim();
            return log_type.match(/auth|syslog|application|cron|kernel|audit/) && 
                   (description.match(/credential|shadow|password|suspicious/i) || 
                    command.match(/cat\s*.*\/etc\/shadow|wget\s*.*credential|curl\s*.*credential/));
        }
    },
    // T1555: Credentials from Password Stores
    {
        id: 'T1555',
        name: 'Credentials from Password Stores',
        description: 'Adversaries may access password stores.',
        mitre_link: 'https://attack.mitre.org/techniques/T1555/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/\/etc\/passwd|\/etc\/shadow|pass\s*.*store/);
        }
    },
    // T1110: Brute Force
    {
        id: 'T1110',
        name: 'Brute Force',
        description: 'Adversaries may attempt brute force attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1110/',
        detection: (event) => {
            if (!event) return false;
            const description = (event.description || '').toString().toLowerCase().trim();
            const command = (event.command || '').toString().toLowerCase().trim();
            return description.match(/failed\s*password|brute\s*force|suspicious/i) || 
                   command.match(/failed\s*password/);
        }
    }
];
