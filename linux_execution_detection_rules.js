// Detection rules for Execution tactic on Linux systems
const rules = [
    // T1059 - Command and Scripting Interpreter
    {
        id: 'T1059',
        name: 'Command and Scripting Interpreter',
        description: 'Adversaries may abuse command and scripting interpreters to execute commands.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (process.includes('bash') || process.includes('python') || process.includes('perl') || process.includes('sh')) && 
                   (command.includes('bash /tmp/') || command.includes('python -c') || description.includes('suspicious command execution'));
        }
    },
    {
        id: 'T1059.004',
        name: 'Command and Scripting Interpreter: Unix Shell',
        description: 'Adversaries may abuse Unix shell to execute commands.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/004/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return (process.includes('bash') || process.includes('sh') || process.includes('zsh')) && 
                   command.includes('/bin/') && command.includes('/tmp/');
        }
    },
    {
        id: 'T1059.006',
        name: 'Command and Scripting Interpreter: Python',
        description: 'Adversaries may abuse Python to execute commands.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/006/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return process.includes('python') && command.includes('python -c');
        }
    },
    {
        id: 'T1059.007',
        name: 'Command and Scripting Interpreter: JavaScript',
        description: 'Adversaries may abuse JavaScript to execute commands.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/007/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return process.includes('node') && command.includes('node');
        }
    },
    // T1204 - User Execution
    {
        id: 'T1204',
        name: 'User Execution',
        description: 'Adversaries may rely on user execution to run malicious code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1204/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('bash /tmp/') || command.includes('wget') || command.includes('curl')) && 
                   description.includes('user executed');
        }
    },
    {
        id: 'T1204.001',
        name: 'User Execution: Malicious Link',
        description: 'Adversaries may rely on user clicking malicious links.',
        mitre_link: 'https://attack.mitre.org/techniques/T1204/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('http');
        }
    },
    {
        id: 'T1204.002',
        name: 'User Execution: Malicious File',
        description: 'Adversaries may rely on user executing malicious files.',
        mitre_link: 'https://attack.mitre.org/techniques/T1204/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('bash /tmp/') || command.includes('chmod +x');
        }
    },
    // T1053 - Scheduled Task/Job
    {
        id: 'T1053',
        name: 'Scheduled Task/Job',
        description: 'Adversaries may abuse scheduled tasks to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return (process.includes('cron') || process.includes('at')) && command.includes('schedule');
        }
    },
    {
        id: 'T1053.002',
        name: 'Scheduled Task/Job: At',
        description: 'Adversaries may abuse at to execute scheduled tasks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/002/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return process.includes('at') && command.includes('at');
        }
    },
    {
        id: 'T1053.003',
        name: 'Scheduled Task/Job: Cron',
        description: 'Adversaries may abuse cron to execute scheduled tasks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/003/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return process.includes('cron') && command.includes('crontab');
        }
    },
    {
        id: 'T1053.005',
        name: 'Scheduled Task/Job: Scheduled Task',
        description: 'Adversaries may abuse systemd timers to execute scheduled tasks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/005/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return process.includes('systemctl') && command.includes('timer');
        }
    },
    // T1648 - Serverless Execution
    {
        id: 'T1648',
        name: 'Serverless Execution',
        description: 'Adversaries may abuse serverless platforms to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1648/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('aws lambda') || command.includes('serverless');
        }
    },
    // T1129 - Shared Modules
    {
        id: 'T1129',
        name: 'Shared Modules',
        description: 'Adversaries may execute code via shared modules.',
        mitre_link: 'https://attack.mitre.org/techniques/T1129/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('insmod') || command.includes('modprobe');
        }
    },
    // T1203 - Exploitation for Client Execution
    {
        id: 'T1203',
        name: 'Exploitation for Client Execution',
        description: 'Adversaries may exploit software vulnerabilities to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1203/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.includes('exploit') && description.includes('client execution');
        }
    },
    // T1609 - Container Administration Command
    {
        id: 'T1609',
        name: 'Container Administration Command',
        description: 'Adversaries may abuse container administration commands to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1609/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('docker') || command.includes('kubectl') || command.includes('container');
        }
    },
    // T1611 - Escape to Host
    {
        id: 'T1611',
        name: 'Escape to Host',
        description: 'Adversaries may break out of containers to execute code on the host.',
        mitre_link: 'https://attack.mitre.org/techniques/T1611/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.includes('docker') && description.includes('container escape');
        }
    }
];