// Lateral Movement Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const lateralMovementRules = [
    // T1021: Remote Services
    {
        id: 'T1021',
        name: 'Remote Services',
        description: 'Adversaries may use remote services for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1021/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.match(/ssh|rdp|rsync|nc|netcat/) && 
                    description.match(/remote.*ssh|remote.*connection/i)) ||
                   command.includes('bash /tmp/');
        }
    },
    {
        id: 'T1021.001',
        name: 'Remote Services: Remote Desktop Protocol',
        description: 'Adversaries may use RDP for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1021/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/rdp|xfreerdp/);
        }
    },
    {
        id: 'T1021.004',
        name: 'Remote Services: SSH',
        description: 'Adversaries may use SSH for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1021/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/ssh|scp|rsync/);
        }
    },
    // T1570: Lateral Tool Transfer
    {
        id: 'T1570',
        name: 'Lateral Tool Transfer',
        description: 'Adversaries may transfer tools to other systems.',
        mitre_link: 'https://attack.mitre.org/techniques/T1570/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.match(/scp|rsync|wget|curl|git clone|nmap/) && 
                    description.match(/lateral.*tool|transferring.*tools/i)) ||
                   command.match(/bash \/tmp\/|python -c/);
        }
    }
];

module.exports = lateralMovementRules;
