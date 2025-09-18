// Command and Control Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const commandAndControlRules = [
    // T1071: Application Layer Protocol
    {
        id: 'T1071',
        name: 'Application Layer Protocol',
        description: 'Adversaries may use application layer protocols for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1071/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.match(/curl|wget|nc|netcat|python -c/) && 
                    description.match(/outbound.*http|possible.*c2/i)) ||
                   command.match(/bash \/tmp\/|python -c/);
        }
    },
    {
        id: 'T1071.001',
        name: 'Application Layer Protocol: Web Protocols',
        description: 'Adversaries may use web protocols for C2.',
        mitre_link: 'https://attack.mitre.org/techniques/T1071/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/curl.*http|wget.*http/);
        }
    }
];

module.exports = commandAndControlRules;
