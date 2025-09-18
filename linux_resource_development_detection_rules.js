// Resource Development Detection Rules for MITRE ATT&CK Enterprise (Linux-focused)
const rules = [
    // T1583: Acquire Infrastructure
    {
        id: 'T1583',
        name: 'Acquire Infrastructure',
        description: 'Adversaries may acquire infrastructure for attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.match(/aws|azure|gcp|curl|wget/) && description.match(/infrastructure.*acquisition/i);
        }
    },
    {
        id: 'T1583.001',
        name: 'Acquire Infrastructure: Domains',
        description: 'Adversaries may acquire domains.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/whois|godaddy|namecheap/);
        }
    },
    {
        id: 'T1583.002',
        name: 'Acquire Infrastructure: DNS Server',
        description: 'Adversaries may acquire DNS servers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/bind|named|dnsmasq/);
        }
    },
    {
        id: 'T1583.003',
        name: 'Acquire Infrastructure: Virtual Private Server',
        description: 'Adversaries may acquire VPS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/aws.*ec2|azure.*vm|linode|digitalocean/);
        }
    },
    {
        id: 'T1583.004',
        name: 'Acquire Infrastructure: Server',
        description: 'Adversaries may acquire servers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/ssh.*setup|apache2|nginx/);
        }
    },
    {
        id: 'T1583.005',
        name: 'Acquire Infrastructure: Botnet',
        description: 'Adversaries may acquire botnets.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/005/',
        detection: (event) => {
            if (!event) return false;
            const description = (event.description || '').toString().toLowerCase();
            return description.match(/botnet|command.*control/i);
        }
    },
    {
        id: 'T1583.006',
        name: 'Acquire Infrastructure: Web Services',
        description: 'Adversaries may acquire web services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/006/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/curl.*github|wget.*github/);
        }
    },
    // T1584: Compromise Infrastructure
    {
        id: 'T1584',
        name: 'Compromise Infrastructure',
        description: 'Adversaries may compromise infrastructure.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return command.match(/nmap|metasploit|sqlmap/) && description.match(/compromise.*infrastructure/i);
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
            return command.match(/dns.*spoof|dig.*spoof/);
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
            return command.match(/bind.*exploit|dnsmasq.*exploit/);
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
            return command.match(/aws.*exploit|azure.*exploit/);
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
            return command.match(/apache2.*exploit|nginx.*exploit/);
        }
    },
    {
        id: 'T1584.005',
        name: 'Compromise Infrastructure: Botnet',
        description: 'Adversaries may compromise botnets.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/005/',
        detection: (event) => {
            if (!event) return false;
            const description = (event.description || '').toString().toLowerCase();
            return description.match(/botnet.*compromise/i);
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
            return command.match(/curl.*exploit|wget.*exploit/);
        }
    },
    // T1587: Develop Capabilities
    {
        id: 'T1587',
        name: 'Develop Capabilities',
        description: 'Adversaries may develop malicious capabilities.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/gcc|make|python.*malware/);
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
            return command.match(/gcc.*malware|python.*malware/);
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
            return command.match(/openssl.*req|certutil/);
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
            return command.match(/openssl.*x509/);
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
            return command.match(/metasploit|exploit-db/);
        }
    },
    // T1588: Obtain Capabilities
    {
        id: 'T1588',
        name: 'Obtain Capabilities',
        description: 'Adversaries may obtain malicious capabilities.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/wget.*exploit|curl.*exploit/);
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
            return command.match(/wget.*malware|curl.*malware/);
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
            return command.match(/wget.*tool|curl.*tool|nmap|metasploit/);
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
            return command.match(/openssl.*req|certutil/);
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
            return command.match(/openssl.*x509/);
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
            return command.match(/wget.*exploit|curl.*exploit|exploit-db/);
        }
    },
    {
        id: 'T1588.006',
        name: 'Obtain Capabilities: Vulnerabilities',
        description: 'Adversaries may obtain vulnerability information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/006/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/nmap.*-sV|openvas/);
        }
    },
    // T1608: Stage Capabilities
    {
        id: 'T1608',
        name: 'Stage Capabilities',
        description: 'Adversaries may stage capabilities for attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/wget.*payload|curl.*payload|git clone.*payload/);
        }
    },
    {
        id: 'T1608.001',
        name: 'Stage Capabilities: Upload Malware',
        description: 'Adversaries may upload malware.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/wget.*malware|curl.*malware/);
        }
    },
    {
        id: 'T1608.002',
        name: 'Stage Capabilities: Upload Tool',
        description: 'Adversaries may upload tools.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/wget.*tool|curl.*tool/);
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
            return command.match(/openssl.*install/);
        }
    },
    {
        id: 'T1608.004',
        name: 'Stage Capabilities: Drive-by Target',
        description: 'Adversaries may stage drive-by targets.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/curl.*exploit|wget.*exploit/);
        }
    },
    {
        id: 'T1608.005',
        name: 'Stage Capabilities: Link Target',
        description: 'Adversaries may stage link targets.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/005/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.match(/curl.*link|wget.*link/);
        }
    }
];
