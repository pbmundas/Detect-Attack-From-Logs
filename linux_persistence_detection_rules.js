// Persistence Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const rules = [
    // T1543: Create or Modify System Process
    {
        id: 'T1543',
        name: 'Create or Modify System Process',
        description: 'Adversaries may create or modify system processes for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const process = (event.process || '').toString().toLowerCase().trim();
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return (process.match(/systemctl|cron|at/) || 
                    command.match(/systemctl|cron|at|bash\s*\/tmp\//)) && 
                   description.match(/service|unit|persistence|suspicious/i);
        }
    },
    {
        id: 'T1543.002',
        name: 'Create or Modify System Process: Systemd Service',
        description: 'Adversaries may create or modify systemd services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/002/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const process = (event.process || '').toString().toLowerCase().trim();
            const command = event.command.toString().toLowerCase().trim();
            return process.includes('systemctl') || command.match(/systemctl\s*.*service/);
        }
    },
    {
        id: 'T1543.003',
        name: 'Create or Modify System Process: Windows Service',
        description: 'Adversaries may create or modify Windows services (not applicable to Linux).',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/003/',
        detection: (event) => {
            return false; // Not applicable to Linux
        }
    },
    // T1037: Boot or Logon Initialization Scripts
    {
        id: 'T1037',
        name: 'Boot or Logon Initialization Scripts',
        description: 'Adversaries may modify boot or logon scripts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/\/etc\/rc\.local|\/etc\/init\.d/);
        }
    },
    {
        id: 'T1037.001',
        name: 'Boot or Logon Initialization Scripts: Logon Script',
        description: 'Adversaries may modify logon scripts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/001/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/\/etc\/profile|\/bash_profile|\/bashrc/);
        }
    },
    // T1547: Boot or Logon Autostart Execution
    {
        id: 'T1547',
        name: 'Boot or Logon Autostart Execution',
        description: 'Adversaries may configure autostart mechanisms.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/\/etc\/rc\.local|\/etc\/init\.d|crontab/);
        }
    },
    {
        id: 'T1547.001',
        name: 'Boot or Logon Autostart Execution: Registry Run Keys',
        description: 'Adversaries may use registry run keys (not applicable to Linux).',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/001/',
        detection: (event) => {
            return false; // Not applicable to Linux
        }
    },
    // T1546: Event Triggered Execution
    {
        id: 'T1546',
        name: 'Event Triggered Execution',
        description: 'Adversaries may establish persistence via event triggers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/inotifywait|fsnotify/);
        }
    },
    // T1098: Account Manipulation
    {
        id: 'T1098',
        name: 'Account Manipulation',
        description: 'Adversaries may manipulate accounts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return command.match(/useradd|usermod|passwd/) && description.match(/account|manipulation|suspicious/i);
        }
    },
    // T1548: Abuse Elevation Control Mechanism (also under Privilege Escalation)
    {
        id: 'T1548',
        name: 'Abuse Elevation Control Mechanism',
        description: 'Adversaries may abuse elevation mechanisms for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const process = (event.process || '').toString().toLowerCase().trim();
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return (process.includes('sudo') || command.includes('sudo')) && 
                   description.match(/sudo|bypass|policy|suspicious/i);
        }
    }
];
