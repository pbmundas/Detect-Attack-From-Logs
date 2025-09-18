// Detection rules for Initial Access tactic on Linux systems
const rules = [
    // T1078 - Valid Accounts
    {
        id: 'T1078',
        name: 'Valid Accounts',
        description: 'Adversaries may obtain and abuse valid accounts to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/',
        detection: (event) => {
            if (!event) return false;
            const log_type = (event.log_type || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return log_type.includes('auth') && 
                   (command.includes('password') || description.includes('valid account') || description.includes('compromised credentials'));
        }
    },
    {
        id: 'T1078.001',
        name: 'Valid Accounts: Default Accounts',
        description: 'Adversaries may use default accounts to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/001/',
        detection: (event) => {
            if (!event) return false;
            const log_type = (event.log_type || '').toString().toLowerCase();
            const user = (event.user || '').toString().toLowerCase();
            return log_type.includes('auth') && 
                   (user.includes('admin') || user.includes('root') || user.includes('guest'));
        }
    },
    {
        id: 'T1078.002',
        name: 'Valid Accounts: Domain Accounts',
        description: 'Adversaries may use domain accounts to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/002/',
        detection: (event) => {
            if (!event) return false;
            const log_type = (event.log_type || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return log_type.includes('auth') && description.includes('domain account');
        }
    },
    {
        id: 'T1078.003',
        name: 'Valid Accounts: Local Accounts',
        description: 'Adversaries may use local accounts to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/003/',
        detection: (event) => {
            if (!event) return false;
            const log_type = (event.log_type || '').toString().toLowerCase();
            const user = (event.user || '').toString().toLowerCase();
            return log_type.includes('auth') && 
                   (user.includes('ubuntu') || user.includes('svc_') || user.includes('postgres'));
        }
    },
    {
        id: 'T1078.004',
        name: 'Valid Accounts: Cloud Accounts',
        description: 'Adversaries may use cloud accounts to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/004/',
        detection: (event) => {
            if (!event) return false;
            const log_type = (event.log_type || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return log_type.includes('auth') && command.includes('cloud');
        }
    },
    // T1190 - Exploit Public-Facing Application
    {
        id: 'T1190',
        name: 'Exploit Public-Facing Application',
        description: 'Adversaries may exploit public-facing applications to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1190/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('wget') || command.includes('curl') || command.includes('git clone')) && 
                   description.includes('exploit attempt') && description.includes('public-facing');
        }
    },
    // T1133 - External Remote Services
    {
        id: 'T1133',
        name: 'External Remote Services',
        description: 'Adversaries may leverage external remote services to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1133/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return (process.includes('ssh') || process.includes('rdp')) && command.includes('remote');
        }
    },
    // T1189 - Drive-by Compromise
    {
        id: 'T1189',
        name: 'Drive-by Compromise',
        description: 'Adversaries may gain access through drive-by compromise.',
        mitre_link: 'https://attack.mitre.org/techniques/T1189/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('http') && command.includes('exploit');
        }
    },
    // T1195 - Supply Chain Compromise
    {
        id: 'T1195',
        name: 'Supply Chain Compromise',
        description: 'Adversaries may manipulate supply chain to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1195/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('apt-get install') || command.includes('yum install') || command.includes('supply chain');
        }
    },
    {
        id: 'T1195.001',
        name: 'Supply Chain Compromise: Compromise Software Dependencies and Development Tools',
        description: 'Adversaries may compromise software dependencies and tools.',
        mitre_link: 'https://attack.mitre.org/techniques/T1195/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('pip install') || command.includes('npm install');
        }
    },
    {
        id: 'T1195.002',
        name: 'Supply Chain Compromise: Compromise Software Supply Chain',
        description: 'Adversaries may compromise software supply chains.',
        mitre_link: 'https://attack.mitre.org/techniques/T1195/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('apt-get install') && command.includes('http');
        }
    },
    {
        id: 'T1195.003',
        name: 'Supply Chain Compromise: Compromise Hardware Supply Chain',
        description: 'Adversaries may compromise hardware supply chains.',
        mitre_link: 'https://attack.mitre.org/techniques/T1195/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('dmidecode') && command.includes('hardware');
        }
    },
    // T1199 - Trusted Relationship
    {
        id: 'T1199',
        name: 'Trusted Relationship',
        description: 'Adversaries may breach trusted relationships to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1199/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('ssh') && command.includes('trusted');
        }
    },
    // T1566 - Phishing
    {
        id: 'T1566',
        name: 'Phishing',
        description: 'Adversaries may use phishing to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1566/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.includes('wget') && description.includes('phishing');
        }
    },
    {
        id: 'T1566.001',
        name: 'Phishing: Spearphishing Attachment',
        description: 'Adversaries may use spearphishing attachments to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1566/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('wget') && command.includes('.pdf');
        }
    },
    {
        id: 'T1566.002',
        name: 'Phishing: Spearphishing Link',
        description: 'Adversaries may use spearphishing links to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1566/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('http');
        }
    },
    {
        id: 'T1566.003',
        name: 'Phishing: Spearphishing via Service',
        description: 'Adversaries may use services for spearphishing to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1566/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('phish');
        }
    }
];