// Impact Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const rules = [
    // T1486: Data Encrypted for Impact
    {
        id: 'T1486',
        name: 'Data Encrypted for Impact',
        description: 'Adversaries may encrypt data for impact.',
        mitre_link: 'https://attack.mitre.org/techniques/T1486/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return (command.match(/openssl|gpg|tar|nmap|bash\s*\/tmp\/|python\s*-c/) && 
                    description.match(/encryption|ransom|suspicious/i));
        }
    },
    // T1490: Inhibit System Recovery
    {
        id: 'T1490',
        name: 'Inhibit System Recovery',
        description: 'Adversaries may inhibit system recovery.',
        mitre_link: 'https://attack.mitre.org/techniques/T1490/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return (command.match(/rm\s*.*\/backup|tar|bash\s*\/tmp\/|python\s*-c/) && 
                    description.match(/backup|shadow|deletion|suspicious/i));
        }
    },
    // T1485: Data Destruction
    {
        id: 'T1485',
        name: 'Data Destruction',
        description: 'Adversaries may destroy data to impact systems.',
        mitre_link: 'https://attack.mitre.org/techniques/T1485/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/rm\s*-rf|shred/);
        }
    }
];
