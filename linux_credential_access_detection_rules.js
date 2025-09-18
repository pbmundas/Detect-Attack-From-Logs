// Credential Access Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const credentialAccessRules = [
    // T1003: OS Credential Dumping
    {
        id: 'T1003',
        name: 'OS Credential Dumping',
        description: 'Adversaries may dump credentials from OS stores.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            const log_type = (event.log_type || '').toString().toLowerCase();
            return (log_type.match(/auth|syslog|audit|kernel/) && 
                    description.match(/credential.*store|\/etc\/shadow/i)) ||
                   command.match(/cat.*\/etc\/shadow|wget.*credential|curl.*credential/);
        }
    },
    // T1555: Credentials from Password Stores
    {
        id: 'T1555',
        name: 'Credentials from Password Stores',
        description: 'Adversaries may access password stores.',
        mitre_link: 'https://attack.mitre.org/techniques/T1555/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/\/etc\/passwd|\/etc\/shadow|pass.*store/);
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
            const description = (event.description || '').toString().toLowerCase();
            return description.match(/failed.*password|brute.*force/i);
        }
    }
];

module.exports = credentialAccessRules;
