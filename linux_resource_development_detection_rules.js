// Detection rules for Resource Development tactic on Linux systems
const rules = [
    // T1583 - Acquire Infrastructure
    {
        id: 'T1583',
        name: 'Acquire Infrastructure',
        description: 'Adversaries may acquire infrastructure for their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('cloud') && command.includes('register');
        }
    },
    {
        id: 'T1583.001',
        name: 'Acquire Infrastructure: Domains',
        description: 'Adversaries may acquire domains for their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('whois') && command.includes('register');
        }
    },
    {
        id: 'T1583.002',
        name: 'Acquire Infrastructure: DNS Server',
        description: 'Adversaries may acquire DNS servers for their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('bind') || command.includes('dns server');
        }
    },
    {
        id: 'T1583.003',
        name: 'Acquire Infrastructure: Virtual Private Server',
        description: 'Adversaries may acquire VPS for their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('vps');
        }
    },
    {
        id: 'T1583.004',
        name: 'Acquire Infrastructure: Server',
        description: 'Adversaries may acquire servers for their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('server lease');
        }
    },
    {
        id: 'T1583.005',
        name: 'Acquire Infrastructure: Botnet',
        description: 'Adversaries may acquire botnets for their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/005/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('botnet') || command.includes('ddos');
        }
    },
    {
        id: 'T1583.006',
        name: 'Acquire Infrastructure: Web Services',
        description: 'Adversaries may acquire web services for their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/006/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('web service');
        }
    },
    // T1584 - Compromise Infrastructure
    {
        id: 'T1584',
        name: 'Compromise Infrastructure',
        description: 'Adversaries may compromise third-party infrastructure.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.includes('exploit') && description.includes('compromise');
        }
    },
    {
        id: 'T1584.001',
        name: 'Compromise Infrastructure: Domains',
        description: 'Adversaries may compromise domains.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('whois') && command.includes('compromise');
        }
    },
    {
        id: 'T1584.002',
        name: 'Compromise Infrastructure: DNS Server',
        description: 'Adversaries may compromise DNS servers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('bind') && command.includes('exploit');
        }
    },
    {
        id: 'T1584.003',
        name: 'Compromise Infrastructure: Virtual Private Server',
        description: 'Adversaries may compromise VPS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('vps') && command.includes('exploit');
        }
    },
    {
        id: 'T1584.004',
        name: 'Compromise Infrastructure: Server',
        description: 'Adversaries may compromise servers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('server') && command.includes('exploit');
        }
    },
    {
        id: 'T1584.005',
        name: 'Compromise Infrastructure: Botnet',
        description: 'Adversaries may compromise botnets.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/005/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('botnet') && command.includes('exploit');
        }
    },
    {
        id: 'T1584.006',
        name: 'Compromise Infrastructure: Web Services',
        description: 'Adversaries may compromise web services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/006/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('web service') && command.includes('exploit');
        }
    },
    // T1587 - Develop Capabilities
    {
        id: 'T1587',
        name: 'Develop Capabilities',
        description: 'Adversaries may develop capabilities for their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('gcc') || command.includes('make') || command.includes('compile');
        }
    },
    {
        id: 'T1587.001',
        name: 'Develop Capabilities: Malware',
        description: 'Adversaries may develop malware.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('gcc') && command.includes('malware');
        }
    },
    {
        id: 'T1587.002',
        name: 'Develop Capabilities: Code Signing Certificates',
        description: 'Adversaries may develop code signing certificates.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('openssl req') && command.includes('certificate');
        }
    },
    {
        id: 'T1587.003',
        name: 'Develop Capabilities: Digital Certificates',
        description: 'Adversaries may develop digital certificates.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('openssl x509') && command.includes('certificate');
        }
    },
    {
        id: 'T1587.004',
        name: 'Develop Capabilities: Exploits',
        description: 'Adversaries may develop exploits.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('gcc') && command.includes('exploit');
        }
    },
    // T1588 - Obtain Capabilities
    {
        id: 'T1588',
        name: 'Obtain Capabilities',
        description: 'Adversaries may obtain capabilities for their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('wget') && command.includes('exploit');
        }
    },
    {
        id: 'T1588.001',
        name: 'Obtain Capabilities: Malware',
        description: 'Adversaries may obtain malware.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('wget') && command.includes('malware');
        }
    },
    {
        id: 'T1588.002',
        name: 'Obtain Capabilities: Tools',
        description: 'Adversaries may obtain tools.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('wget') && command.includes('tool');
        }
    },
    {
        id: 'T1588.003',
        name: 'Obtain Capabilities: Code Signing Certificates',
        description: 'Adversaries may obtain code signing certificates.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('certificate');
        }
    },
    {
        id: 'T1588.004',
        name: 'Obtain Capabilities: Digital Certificates',
        description: 'Adversaries may obtain digital certificates.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('certificate');
        }
    },
    {
        id: 'T1588.005',
        name: 'Obtain Capabilities: Exploits',
        description: 'Adversaries may obtain exploits.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/005/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('wget') && command.includes('exploit');
        }
    },
    {
        id: 'T1588.006',
        name: 'Obtain Capabilities: Vulnerabilities',
        description: 'Adversaries may obtain information on vulnerabilities.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/006/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('cve');
        }
    },
    // T1608 - Stage Capabilities
    {
        id: 'T1608',
        name: 'Stage Capabilities',
        description: 'Adversaries may stage capabilities for their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('wget') && command.includes('/tmp/');
        }
    },
    {
        id: 'T1608.001',
        name: 'Stage Capabilities: Upload Malware',
        description: 'Adversaries may upload malware to a system.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('wget') && command.includes('/tmp/') && command.includes('malware');
        }
    },
    {
        id: 'T1608.002',
        name: 'Stage Capabilities: Upload Tool',
        description: 'Adversaries may upload tools to a system.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('scp') && command.includes('/tmp/') && command.includes('tool');
        }
    },
    {
        id: 'T1608.003',
        name: 'Stage Capabilities: Install Digital Certificate',
        description: 'Adversaries may install digital certificates.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('openssl') && command.includes('certificate');
        }
    },
    {
        id: 'T1608.004',
        name: 'Stage Capabilities: Drive-by Compromise',
        description: 'Adversaries may stage capabilities for drive-by compromise.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('http') && command.includes('exploit');
        }
    },
    {
        id: 'T1608.005',
        name: 'Stage Capabilities: Link Target',
        description: 'Adversaries may stage capabilities via malicious links.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/005/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('http');
        }
    },
    {
        id: 'T1608.006',
        name: 'Stage Capabilities: SEO Poisoning',
        description: 'Adversaries may use SEO poisoning to stage capabilities.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/006/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('curl') && command.includes('seo');
        }
    }
];