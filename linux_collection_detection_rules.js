// Collection Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const rules = [
    // T1119: Automated Collection
    {
        id: 'T1119',
        name: 'Automated Collection',
        description: 'Adversaries may automate data collection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1119/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.match(/tar|zip|gzip|wget|curl|git clone/) && 
                    description.match(/automated.*collection|files.*from.*directories/i)) ||
                   command.match(/bash \/tmp\/|python -c/);
        }
    },
    // T1005: Data from Local System
    {
        id: 'T1005',
        name: 'Data from Local System',
        description: 'Adversaries may collect data from local systems.',
        mitre_link: 'https://attack.mitre.org/techniques/T1005/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/cat|cp|tar.*\/home|tar.*\/etc/);
        }
    }
];

