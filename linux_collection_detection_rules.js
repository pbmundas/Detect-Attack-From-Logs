// Collection Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const rules = [
    // T1119: Automated Collection
    {
        id: 'T1119',
        name: 'Automated Collection',
        description: 'Adversaries may automate data collection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1119/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return (command.match(/tar|zip|gzip|wget|curl|git\s*clone|bash\s*\/tmp\/|python\s*-c/) && 
                    description.match(/collection|files|directories|suspicious/i));
        }
    },
    // T1005: Data from Local System
    {
        id: 'T1005',
        name: 'Data from Local System',
        description: 'Adversaries may collect data from local systems.',
        mitre_link: 'https://attack.mitre.org/techniques/T1005/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/cat|cp|tar\s*.*\/home|tar\s*.*\/etc/);
        }
    }
];
