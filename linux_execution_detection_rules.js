// Execution Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const rules = [
    // T1059: Command and Scripting Interpreter
    {
        id: 'T1059',
        name: 'Command and Scripting Interpreter',
        description: 'Adversaries may use interpreters like bash or python for execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (process.match(/bash|sh|python|perl|java|node/) || 
                    command.match(/bash \/tmp\/|sh \/tmp\/|python -c|perl|java|node/)) && 
                   description.match(/suspicious.*command|execution.*interpreter/i);
        }
    },
    {
        id: 'T1059.004',
        name: 'Command and Scripting Interpreter: Unix Shell',
        description: 'Adversaries may use Unix shell for execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/004/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return process.match(/bash|sh/) || command.match(/bash \/tmp\/|sh \/tmp\//);
        }
    },
    {
        id: 'T1059.006',
        name: 'Command and Scripting Interpreter: Python',
        description: 'Adversaries may use Python for execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/006/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return process.includes('python') || command.includes('python -c');
        }
    },
    {
        id: 'T1059.007',
        name: 'Command and Scripting Interpreter: JavaScript',
        description: 'Adversaries may use JavaScript for execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/007/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return process.includes('node') || command.match(/node|javascript/);
        }
    },
    // T1204: User Execution
    {
        id: 'T1204',
        name: 'User Execution',
        description: 'Adversaries may rely on user execution of malicious files.',
        mitre_link: 'https://attack.mitre.org/techniques/T1204/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.match(/nmap|wget|curl|git clone|bash \/tmp\/|python -c/) && 
                    description.match(/user.*executed|downloaded.*binary/i)) ||
                   command.match(/bash \/tmp\/|python -c/);
        }
    },
    {
        id: 'T1204.001',
        name: 'User Execution: Malicious Link',
        description: 'Adversaries may trick users into clicking malicious links.',
        mitre_link: 'https://attack.mitre.org/techniques/T1204/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/wget.*http|curl.*http|git clone.*http/);
        }
    },
    {
        id: 'T1204.002',
        name: 'User Execution: Malicious File',
        description: 'Adversaries may trick users into executing malicious files.',
        mitre_link: 'https://attack.mitre.org/techniques/T1204/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/bash \/tmp\/|python -c|wget.*http|curl.*http|git clone.*http/);
        }
    },
    // T1053: Scheduled Task/Job
    {
        id: 'T1053',
        name: 'Scheduled Task/Job',
        description: 'Adversaries may abuse task scheduling for execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return process.match(/cron|at/) || command.match(/crontab|at|systemctl/);
        }
    },
    {
        id: 'T1053.002',
        name: 'Scheduled Task/Job: At',
        description: 'Adversaries may use at for scheduling execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/002/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return process.includes('at') || command.includes('at');
        }
    },
    {
        id: 'T1053.003',
        name: 'Scheduled Task/Job: Cron',
        description: 'Adversaries may use cron for scheduling execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/003/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return process.includes('cron') || command.includes('crontab');
        }
    },
    {
        id: 'T1053.005',
        name: 'Scheduled Task/Job: Scheduled Task',
        description: 'Adversaries may use scheduled tasks for execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/005/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return process.includes('systemctl') || command.includes('systemctl');
        }
    },
    // T1648: Serverless Execution
    {
        id: 'T1648',
        name: 'Serverless Execution',
        description: 'Adversaries may abuse serverless computing for execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1648/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.match(/aws|lambda|serverless/) && description.match(/serverless|cloud.*execution/i);
        }
    },
    // T1129: Shared Modules
    {
        id: 'T1129',
        name: 'Shared Modules',
        description: 'Adversaries may execute code via shared modules.',
        mitre_link: 'https://attack.mitre.org/techniques/T1129/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/insmod|modprobe/);
        }
    },
    // T1203: Exploitation for Client Execution
    {
        id: 'T1203',
        name: 'Exploitation for Client Execution',
        description: 'Adversaries may exploit software vulnerabilities for execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1203/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.match(/wget|curl|bash \/tmp\//) && description.match(/exploit.*attempt|vulnerability/i);
        }
    },
    // T1609: Container Administration Command
    {
        id: 'T1609',
        name: 'Container Administration Command',
        description: 'Adversaries may execute commands in containers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1609/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return process.match(/docker|kubectl/) || command.match(/docker|kubectl/);
        }
    },
    // T1611: Escape to Host
    {
        id: 'T1611',
        name: 'Escape to Host',
        description: 'Adversaries may break out of containers to the host.',
        mitre_link: 'https://attack.mitre.org/techniques/T1611/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.match(/docker|kubectl|nsenter/) && description.match(/container.*escape|host.*access/i);
        }
    }
];

