// Detection rules for Persistence tactic on Linux systems
const rules = [
    // T1037 - Boot or Logon Initialization Scripts
    {
        id: 'T1037',
        name: 'Boot or Logon Initialization Scripts',
        description: 'Adversaries may use initialization scripts to establish persistence. On Linux, this includes /etc/rc.local or systemd services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('rc.local') || command.includes('systemctl enable')) && description.includes('persistence');
        }
    },
    {
        id: 'T1037.004',
        name: 'Boot or Logon Initialization Scripts: RC Scripts',
        description: 'Adversaries may modify RC scripts like /etc/rc.local for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('rc.local') || command.includes('init.d');
        }
    },
    // T1098 - Account Manipulation
    {
        id: 'T1098',
        name: 'Account Manipulation',
        description: 'Adversaries may manipulate accounts to maintain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('useradd') || command.includes('passwd')) && description.includes('account manipulation');
        }
    },
    {
        id: 'T1098.001',
        name: 'Account Manipulation: Additional Account Properties',
        description: 'Adversaries may modify account properties for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('usermod') || command.includes('chsh');
        }
    },
    {
        id: 'T1098.003',
        name: 'Account Manipulation: Additional Local Account Properties',
        description: 'Adversaries may modify local account properties for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('usermod -G') || command.includes('adduser');
        }
    },
    // T1136 - Create Account
    {
        id: 'T1136',
        name: 'Create Account',
        description: 'Adversaries may create accounts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1136/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('useradd') || command.includes('adduser');
        }
    },
    {
        id: 'T1136.001',
        name: 'Create Account: Local Account',
        description: 'Adversaries may create local accounts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1136/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('useradd -m') || command.includes('adduser');
        }
    },
    // T1543 - Create or Modify System Process
    {
        id: 'T1543',
        name: 'Create or Modify System Process',
        description: 'Adversaries may create or modify system processes for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (process.includes('systemctl') || process.includes('cron') || process.includes('at')) && 
                   (description.includes('service/unit file') || description.includes('persistence'));
        }
    },
    {
        id: 'T1543.002',
        name: 'Create or Modify System Process: Systemd Service',
        description: 'Adversaries may create or modify systemd services for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('systemctl enable') || command.includes('systemd');
        }
    },
    // T1547 - Boot or Logon Autostart Execution
    {
        id: 'T1547',
        name: 'Boot or Logon Autostart Execution',
        description: 'Adversaries may configure autostart mechanisms. On Linux, this includes cron or /etc/profile.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('crontab') || command.includes('profile.d');
        }
    },
    {
        id: 'T1547.006',
        name: 'Boot or Logon Autostart Execution: Kernel Modules and Extensions',
        description: 'Adversaries may load kernel modules for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/006/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('insmod') || command.includes('modprobe');
        }
    },
    // T1546 - Event Triggered Execution
    {
        id: 'T1546',
        name: 'Event Triggered Execution',
        description: 'Adversaries may establish persistence via event triggers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('inotifywait') || command.includes('trigger');
        }
    },
    {
        id: 'T1546.004',
        name: 'Event Triggered Execution: Unix Shell Configuration Modification',
        description: 'Adversaries may modify shell configuration files for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('bashrc') || command.includes('bash_profile');
        }
    },
    // T1505 - Server Software Component
    {
        id: 'T1505',
        name: 'Server Software Component',
        description: 'Adversaries may abuse server software components for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1505/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('apache2') || command.includes('nginx');
        }
    },
    {
        id: 'T1505.003',
        name: 'Server Software Component: Web Shell',
        description: 'Adversaries may install web shells for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1505/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.includes('php') && description.includes('web shell');
        }
    },
    {
        id: 'T1505.004',
        name: 'Server Software Component: Serverless',
        description: 'Adversaries may abuse serverless components for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1505/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('aws lambda') || command.includes('serverless');
        }
    }
];