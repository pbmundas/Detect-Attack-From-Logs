// Privilege Escalation Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const rules = [
    // T1068: Exploitation for Privilege Escalation
    {
        id: 'T1068',
        name: 'Exploitation for Privilege Escalation',
        description: 'Adversaries may exploit vulnerabilities to escalate privileges.',
        mitre_link: 'https://attack.mitre.org/techniques/T1068/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const process = (event.process || '').toString().toLowerCase().trim();
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return (process.match(/sudo|bash|python|java|tar/) || 
                    command.match(/bash\s*\/tmp\/|python\s*-c|sudo|tar/)) && 
                   description.match(/exploit|suid|escalation|suspicious/i);
        }
    },
    // T1548: Abuse Elevation Control Mechanism
    {
        id: 'T1548',
        name: 'Abuse Elevation Control Mechanism',
        description: 'Adversaries may abuse elevation mechanisms like sudo.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const process = (event.process || '').toString().toLowerCase().trim();
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return (process.includes('sudo') || command.includes('sudo')) && 
                   description.match(/sudo|bypass|policy|suspicious/i);
        }
    },
    {
        id: 'T1548.001',
        name: 'Abuse Elevation Control Mechanism: Setuid and Setgid',
        description: 'Adversaries may abuse setuid/setgid binaries.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/001/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/chmod\s*.*u\+s|chmod\s*.*g\+s/);
        }
    },
    // T1543: Create or Modify System Process (also under Persistence)
    {
        id: 'T1543',
        name: 'Create or Modify System Process',
        description: 'Adversaries may create or modify system processes for escalation.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const process = (event.process || '').toString().toLowerCase().trim();
            const command = event.command.toString().toLowerCase().trim();
            const description = (event.description || '').toString().toLowerCase().trim();
            return (process.match(/systemctl|cron|at/) || 
                    command.match(/systemctl|cron|at/)) && 
                   description.match(/service|unit|escalation|suspicious/i);
        }
    },
    // T1134: Access Token Manipulation
    {
        id: 'T1134',
        name: 'Access Token Manipulation',
        description: 'Adversaries may manipulate access tokens (less common on Linux).',
        mitre_link: 'https://attack.mitre.org/techniques/T1134/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/sudo\s*.*-u|runuser/);
        }
    },
    // T1574: Hijack Execution Flow
    {
        id: 'T1574',
        name: 'Hijack Execution Flow',
        description: 'Adversaries may hijack execution flow.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/',
        detection: (event) => {
            if (!event || !event.command) return false;
            const command = event.command.toString().toLowerCase().trim();
            return command.match(/ld_preload|ld_library_path/);
        }
    }
];
