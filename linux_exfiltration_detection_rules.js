// Exfiltration Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const rules = [
    // T1041: Exfiltration Over C2 Channel
    {
        id: 'T1041',
        name: 'Exfiltration Over C2 Channel',
        description: 'Adversaries may exfiltrate data over C2 channels.',
        mitre_link: 'https://attack.mitre.org/techniques/T1041/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return (command.match(/rsync|scp|wget|curl|python\s*-c|bash\s*\/tmp\//) && 
                    description.match(/exfiltration|host|port|suspicious/i));
        }
    },
    // T1048: Exfiltration Over Alternative Protocol
    {
        id: 'T1048',
        name: 'Exfiltration Over Alternative Protocol',
        description: 'Adversaries may exfiltrate data over alternative protocols.',
        mitre_link: 'https://attack.mitre.org/techniques/T1048/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/ftp|sftp|scp/);
        }
    }
];
