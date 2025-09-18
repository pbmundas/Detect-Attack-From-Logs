// Detection rules for Exfiltration tactic on Linux systems
const rules = [
    // T1041 - Exfiltration Over C2 Channel
    {
        id: 'T1041',
        name: 'Exfiltration Over C2 Channel',
        description: 'Adversaries may exfiltrate data over a C2 channel.',
        mitre_link: 'https://attack.mitre.org/techniques/T1041/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (process.includes('rsync') || process.includes('scp') || command.includes('python -c')) && 
                   description.includes('exfiltration') && description.includes('uncommon port');
        }
    },
    // T1048 - Exfiltration Over Alternative Protocol
    {
        id: 'T1048',
        name: 'Exfiltration Over Alternative Protocol',
        description: 'Adversaries may exfiltrate data over alternative protocols.',
        mitre_link: 'https://attack.mitre.org/techniques/T1048/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('ftp') || command.includes('sftp');
        }
    },
    {
        id: 'T1048.003',
        name: 'Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol',
        description: 'Adversaries may exfiltrate data over unencrypted non-C2 protocols.',
        mitre_link: 'https://attack.mitre.org/techniques/T1048/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('ftp') && !command.includes('sftp');
        }
    },
    // T1567 - Exfiltration Over Web Service
    {
        id: 'T1567',
        name: 'Exfiltration Over Web Service',
        description: 'Adversaries may exfiltrate data over web services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1567/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('http');
        }
    },
    {
        id: 'T1567.002',
        name: 'Exfiltration Over Web Service: Exfiltration to Cloud Storage',
        description: 'Adversaries may exfiltrate data to cloud storage.',
        mitre_link: 'https://attack.mitre.org/techniques/T1567/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('aws s3 cp') || command.includes('gcloud storage');
        }
    }
];