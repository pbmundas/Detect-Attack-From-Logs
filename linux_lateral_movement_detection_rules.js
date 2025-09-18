// Detection rules for Lateral Movement tactic on Linux systems
const rules = [
    // T1021 - Remote Services
    {
        id: 'T1021',
        name: 'Remote Services',
        description: 'Adversaries may use remote services like SSH/RDP for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1021/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (process.includes('ssh') || process.includes('rsync') || command.includes('nc -l')) && 
                   description.includes('remote ssh/rdp connection') && description.includes('lateral movement');
        }
    },
    {
        id: 'T1021.004',
        name: 'Remote Services: SSH',
        description: 'Adversaries may use SSH for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1021/004/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return process.includes('ssh') && command.includes('ssh');
        }
    },
    // T1072 - Software Deployment Tools
    {
        id: 'T1072',
        name: 'Software Deployment Tools',
        description: 'Adversaries may use deployment tools for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1072/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('ansible') || command.includes('puppet');
        }
    },
    // T1570 - Lateral Tool Transfer
    {
        id: 'T1570',
        name: 'Lateral Tool Transfer',
        description: 'Adversaries may transfer tools to remote hosts for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1570/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (process.includes('scp') || process.includes('rsync') || command.includes('git clone')) && 
                   description.includes('transferring lateral tools');
        }
    }
];