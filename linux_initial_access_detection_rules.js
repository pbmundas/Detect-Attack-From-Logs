// Initial Access Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const initialAccessRules = [
    // T1078: Valid Accounts
    {
        id: 'T1078',
        name: 'Valid Accounts',
        description: 'Adversaries may use valid accounts for initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/',
        detection: (event) => {
            if (!event) return false;
            const log_type = (event.log_type || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return (log_type.match(/auth|syslog|audit|application|cron|kernel/) && 
                    description.match(/valid.*account|unusual.*ip|compromised.*credentials/i)) ||
                   command.match(/accepted.*password|failed.*password/);
        }
    },
    {
        id: 'T1078.001',
        name: 'Valid Accounts: Default Accounts',
        description: 'Adversaries may use default accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/001/',
        detection: (event) => {
            if (!event) return false;
            const user = (event.user || '').toString().toLowerCase();
            const log_type = (event.log_type || '').toString().toLowerCase();
            return log_type.match(/auth|syslog|audit/) && user.match(/root|admin|guest/);
        }
    },
    {
        id: 'T1078.002',
        name: 'Valid Accounts: Domain Accounts',
        description: 'Adversaries may use domain accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/002/',
        detection: (event) => {
            if (!event) return false;
            const user = (event.user || '').toString().toLowerCase();
            const log_type = (event.log_type || '').toString().toLowerCase();
            return log_type.match(/auth|syslog|audit/) && user.includes('domain');
        }
    },
    {
        id: 'T1078.003',
        name: 'Valid Accounts: Local Accounts',
        description: 'Adversaries may use local accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/003/',
        detection: (event) => {
            if (!event) return false;
            const user = (event.user || '').toString().toLowerCase();
            const log_type = (event.log_type || '').toString().toLowerCase();
            return log_type.match(/auth|syslog|audit/) && user.match(/alice|bob|ubuntu|svc_monitor|svc_backup|postgres|oracle|www-data|syslog/);
        }
    },
    {
        id: 'T1078.004',
        name: 'Valid Accounts: Cloud Accounts',
        description: 'Adversaries may use cloud accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/004/',
        detection: (event) => {
            if (!event) return false;
            const user = (event.user || '').toString().toLowerCase();
            const log_type = (event.log_type || '').toString().toLowerCase();
            return log_type.match(/auth|syslog|audit/) && user.match(/aws|azure|gcp/);
        }
    },
    // T1190: Exploit Public-Facing Application
    {
        id: 'T1190',
        name: 'Exploit Public-Facing Application',
        description: 'Adversaries may exploit public-facing applications.',
        mitre_link: 'https://attack.mitre.org/techniques/T1190/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.match(/wget.*http|curl.*http|git clone.*http/) && 
                    description.match(/exploit.*attempt|web.*payload/i)) ||
                   command.match(/bash \/tmp\/|python -c/);
        }
    },
    // T1133: External Remote Services
    {
        id: 'T1133',
        name: 'External Remote Services',
        description: 'Adversaries may use external remote services for access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1133/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.match(/ssh|rdp|vpn/) && description.match(/remote.*access|external.*service/i);
        }
    },
    // T1189: Drive-by Compromise
    {
        id: 'T1189',
        name: 'Drive-by Compromise',
        description: 'Adversaries may compromise systems via web browser exploits.',
        mitre_link: 'https://attack.mitre.org/techniques/T1189/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.match(/wget|curl/) && description.match(/drive-by|browser.*exploit/i);
        }
    },
    // T1195: Supply Chain Compromise
    {
        id: 'T1195',
        name: 'Supply Chain Compromise',
        description: 'Adversaries may compromise software supply chains.',
        mitre_link: 'https://attack.mitre.org/techniques/T1195/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.match(/pip install|npm install|apt-get|yum/) && 
                   description.match(/supply.*chain|dependency.*compromise/i);
        }
    },
    {
        id: 'T1195.001',
        name: 'Supply Chain Compromise: Software Dependencies',
        description: 'Adversaries may compromise software dependencies.',
        mitre_link: 'https://attack.mitre.org/techniques/T1195/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/pip install|npm install/);
        }
    },
    {
        id: 'T1195.002',
        name: 'Supply Chain Compromise: Software Supply Chain',
        description: 'Adversaries may compromise software supply chains.',
        mitre_link: 'https://attack.mitre.org/techniques/T1195/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/apt-get|yum|dpkg/);
        }
    },
    {
        id: 'T1195.003',
        name: 'Supply Chain Compromise: Hardware Supply Chain',
        description: 'Adversaries may compromise hardware supply chains.',
        mitre_link: 'https://attack.mitre.org/techniques/T1195/003/',
        detection: (event) => {
            if (!event) return false;
            const description = (event.description || '').toString().toLowerCase();
            return description.match(/hardware.*compromise|supply.*chain/i);
        }
    },
    // T1199: Trusted Relationship
    {
        id: 'T1199',
        name: 'Trusted Relationship',
        description: 'Adversaries may exploit trusted relationships.',
        mitre_link: 'https://attack.mitre.org/techniques/T1199/',
        detection: (event) => {
            if (!event) return false;
            const description = (event.description || '').toString().toLowerCase();
            return description.match(/trusted.*relationship|third.*party.*access/i);
        }
    },
    // T1566: Phishing
    {
        id: 'T1566',
        name: 'Phishing',
        description: 'Adversaries may use phishing for initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1566/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.match(/wget|curl/) && description.match(/phishing|spearphishing/i);
        }
    },
    {
        id: 'T1566.001',
        name: 'Phishing: Spearphishing Attachment',
        description: 'Adversaries may use spearphishing attachments.',
        mitre_link: 'https://attack.mitre.org/techniques/T1566/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/wget.*\.pdf|curl.*\.pdf|wget.*\.doc|curl.*\.doc/);
        }
    },
    {
        id: 'T1566.002',
        name: 'Phishing: Spearphishing Link',
        description: 'Adversaries may use spearphishing links.',
        mitre_link: 'https://attack.mitre.org/techniques/T1566/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/wget.*http|curl.*http/);
        }
    },
    {
        id: 'T1566.003',
        name: 'Phishing: Spearphishing via Service',
        description: 'Adversaries may use services for spearphishing.',
        mitre_link: 'https://attack.mitre.org/techniques/T1566/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.match(/wget|curl/) && description.match(/spearphishing.*service/i);
        }
    }
];

module.exports = initialAccessRules;
