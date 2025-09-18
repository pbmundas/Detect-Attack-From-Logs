// Detection rules for Privilege Escalation tactic on Linux systems
const rules = [
    // T1068 - Exploitation for Privilege Escalation
    {
        id: 'T1068',
        name: 'Exploitation for Privilege Escalation',
        description: 'Adversaries may exploit vulnerabilities to escalate privileges.',
        mitre_link: 'https://attack.mitre.org/techniques/T1068/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('bash /tmp/') || command.includes('sudo') || command.includes('USER=root')) && 
                   description.includes('exploit attempt') && description.includes('privilege escalation');
        }
    },
    // T1548 - Abuse Elevation Control Mechanism
    {
        id: 'T1548',
        name: 'Abuse Elevation Control Mechanism',
        description: 'Adversaries may abuse elevation control mechanisms to gain higher privileges.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (process.includes('sudo') || command.includes('sudo')) && 
                   description.includes('sudo bypass') && description.includes('policy abuse');
        }
    },
    {
        id: 'T1548.001',
        name: 'Abuse Elevation Control Mechanism: Setuid and Setgid',
        description: 'Adversaries may abuse setuid/setgid binaries to escalate privileges.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('chmod u+s') || command.includes('chmod g+s');
        }
    },
    {
        id: 'T1548.003',
        name: 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching',
        description: 'Adversaries may abuse sudo or sudo caching for privilege escalation.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('sudo') && command.includes('NOPASSWD');
        }
    },
    // T1543 - Create or Modify System Process
    {
        id: 'T1543',
        name: 'Create or Modify System Process',
        description: 'Adversaries may create or modify system processes to escalate privileges.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return (process.includes('systemctl') || command.includes('systemctl')) && command.includes('root');
        }
    },
    {
        id: 'T1543.002',
        name: 'Create or Modify System Process: Systemd Service',
        description: 'Adversaries may create or modify systemd services to escalate privileges.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('systemctl enable') && command.includes('root');
        }
    },
    // T1547 - Boot or Logon Autostart Execution
    {
        id: 'T1547',
        name: 'Boot or Logon Autostart Execution',
        description: 'Adversaries may configure autostart mechanisms for privilege escalation.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('crontab') && command.includes('root');
        }
    },
    {
        id: 'T1547.006',
        name: 'Boot or Logon Autostart Execution: Kernel Modules and Extensions',
        description: 'Adversaries may load kernel modules to escalate privileges.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/006/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('insmod') || command.includes('modprobe') && command.includes('root');
        }
    },
    // T1098 - Account Manipulation
    {
        id: 'T1098',
        name: 'Account Manipulation',
        description: 'Adversaries may manipulate accounts to escalate privileges.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('usermod -G sudo') || command.includes('adduser root');
        }
    },
    {
        id: 'T1098.001',
        name: 'Account Manipulation: Additional Account Properties',
        description: 'Adversaries may modify account properties for escalation.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('usermod -u 0') || command.includes('chsh');
        }
    },
    {
        id: 'T1098.003',
        name: 'Account Manipulation: Additional Local Account Properties',
        description: 'Adversaries may modify local account properties for escalation.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('usermod -G wheel') || command.includes('adduser sudo');
        }
    }
];