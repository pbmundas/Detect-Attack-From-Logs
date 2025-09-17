const rules = [
    // T1583 - Acquire Infrastructure
    {
        id: 'T1583',
        name: 'Acquire Infrastructure',
        description: 'Adversaries may acquire infrastructure to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('whois') || 
                    commandLine.toLowerCase().includes('domain registration')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('registrar')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain registration');
        }
    },
    {
        id: 'T1583.001',
        name: 'Acquire Infrastructure: Domains',
        description: 'Adversaries may acquire domains to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('whois') || 
                    commandLine.toLowerCase().includes('register domain')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/godaddy\.com|namecheap\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('register domain');
        }
    },
    {
        id: 'T1583.002',
        name: 'Acquire Infrastructure: DNS Server',
        description: 'Adversaries may acquire DNS servers to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('dns server') || 
                    commandLine.toLowerCase().includes('bind')) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().includes('53')) {
                    return true; // DNS traffic
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dns server');
        }
    },
    {
        id: 'T1583.003',
        name: 'Acquire Infrastructure: Virtual Private Server',
        description: 'Adversaries may acquire VPS to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('vps') || 
                    commandLine.toLowerCase().includes('aws ec2')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/amazonaws\.com|digitalocean\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('vps');
        }
    },
    {
        id: 'T1583.004',
        name: 'Acquire Infrastructure: Server',
        description: 'Adversaries may acquire servers to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('server setup') || 
                    commandLine.toLowerCase().includes('dedicated server')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('server')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('server setup');
        }
    },
    {
        id: 'T1583.005',
        name: 'Acquire Infrastructure: Botnet',
        description: 'Adversaries may acquire botnets to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('botnet') || 
                    commandLine.toLowerCase().includes('c2')) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp?.toString().includes('.')) {
                    return true; // Suspicious network connections
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('botnet');
        }
    },
    {
        id: 'T1583.006',
        name: 'Acquire Infrastructure: Web Services',
        description: 'Adversaries may acquire web services to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1583/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('web service') || 
                    commandLine.toLowerCase().includes('cloudflare')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/cloudflare\.com|heroku\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('web service');
        }
    },
    // T1584 - Compromise Infrastructure
    {
        id: 'T1584',
        name: 'Compromise Infrastructure',
        description: 'Adversaries may compromise infrastructure to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('compromise') || 
                    commandLine.toLowerCase().includes('hijack')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('compromise');
        }
    },
    {
        id: 'T1584.001',
        name: 'Compromise Infrastructure: Domains',
        description: 'Adversaries may compromise domains to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('domain compromise') || 
                    commandLine.toLowerCase().includes('dns hijack')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dns hijack');
        }
    },
    {
        id: 'T1584.002',
        name: 'Compromise Infrastructure: DNS Server',
        description: 'Adversaries may compromise DNS servers to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('dns compromise') || 
                    commandLine.toLowerCase().includes('dns server')) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().includes('53')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dns compromise');
        }
    },
    {
        id: 'T1584.003',
        name: 'Compromise Infrastructure: Virtual Private Server',
        description: 'Adversaries may compromise VPS to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('vps compromise') || 
                    commandLine.toLowerCase().includes('aws ec2')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/amazonaws\.com|digitalocean\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('vps compromise');
        }
    },
    {
        id: 'T1584.004',
        name: 'Compromise Infrastructure: Server',
        description: 'Adversaries may compromise servers to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('server compromise') || 
                    commandLine.toLowerCase().includes('server hack')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('server')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('server compromise');
        }
    },
    {
        id: 'T1584.005',
        name: 'Compromise Infrastructure: Botnet',
        description: 'Adversaries may compromise botnets to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('botnet compromise') || 
                    commandLine.toLowerCase().includes('c2')) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('botnet compromise');
        }
    },
    {
        id: 'T1584.006',
        name: 'Compromise Infrastructure: Web Services',
        description: 'Adversaries may compromise web services to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1584/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('web service compromise') || 
                    commandLine.toLowerCase().includes('cloudflare')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/cloudflare\.com|heroku\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('web service compromise');
        }
    },
    // T1650 - Acquire Access
    {
        id: 'T1650',
        name: 'Acquire Access',
        description: 'Adversaries may purchase or acquire access to compromised systems.',
        mitre_link: 'https://attack.mitre.org/techniques/T1650/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('acquire access') || 
                    commandLine.toLowerCase().includes('dark web')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('tor')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('acquire access');
        }
    },
    // T1586 - Compromise Accounts
    {
        id: 'T1586',
        name: 'Compromise Accounts',
        description: 'Adversaries may compromise accounts to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1586/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4625' && event.TargetUserName) {
                    return true; // Failed logon attempts
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('account compromise')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('account compromise');
        }
    },
    {
        id: 'T1586.001',
        name: 'Compromise Accounts: Social Media Accounts',
        description: 'Adversaries may compromise social media accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1586/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4625' && event.TargetUserName?.toLowerCase().match(/twitter|facebook|linkedin/)) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('social media')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('social media');
        }
    },
    {
        id: 'T1586.002',
        name: 'Compromise Accounts: Email Accounts',
        description: 'Adversaries may compromise email accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1586/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4625' && event.TargetUserName?.toLowerCase().match(/gmail\.com|outlook\.com/)) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('email compromise')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('email compromise');
        }
    },
    // T1585 - Establish Accounts
    {
        id: 'T1585',
        name: 'Establish Accounts',
        description: 'Adversaries may create accounts to support their operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1585/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net user /add') || 
                    commandLine.toLowerCase().includes('account creation')) {
                    return true;
                }
                if (eid === '4720' && event.TargetUserName) {
                    return true; // User account creation
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('account creation');
        }
    },
    {
        id: 'T1585.001',
        name: 'Establish Accounts: Social Media Accounts',
        description: 'Adversaries may create social media accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1585/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('social media account') || 
                    commandLine.toLowerCase().includes('twitter')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/twitter\.com|facebook\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('social media account');
        }
    },
    {
        id: 'T1585.002',
        name: 'Establish Accounts: Email Accounts',
        description: 'Adversaries may create email accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1585/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('email account') || 
                    commandLine.toLowerCase().includes('gmail')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/gmail\.com|outlook\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('email account');
        }
    },
    // T1587 - Develop Capabilities
    {
        id: 'T1587',
        name: 'Develop Capabilities',
        description: 'Adversaries may develop capabilities like malware or exploits.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('malware') || 
                    commandLine.toLowerCase().includes('exploit')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('malware');
        }
    },
    {
        id: 'T1587.001',
        name: 'Develop Capabilities: Malware',
        description: 'Adversaries may develop malware.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('malware development')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('malware development');
        }
    },
    {
        id: 'T1587.002',
        name: 'Develop Capabilities: Code Signing Certificates',
        description: 'Adversaries may develop or acquire code signing certificates.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('code signing') || 
                    commandLine.toLowerCase().includes('certificate')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.cer')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('code signing');
        }
    },
    {
        id: 'T1587.003',
        name: 'Develop Capabilities: Digital Certificates',
        description: 'Adversaries may develop or acquire digital certificates.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('digital certificate') || 
                    commandLine.toLowerCase().includes('openssl')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.cer')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('digital certificate');
        }
    },
    {
        id: 'T1587.004',
        name: 'Develop Capabilities: Exploits',
        description: 'Adversaries may develop exploits.',
        mitre_link: 'https://attack.mitre.org/techniques/T1587/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('exploit development') || 
                    commandLine.toLowerCase().includes('metasploit')) {
                    return true;
                }
                if (eid === '1116' && event.Message?.toLowerCase().includes('exploit')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('exploit development');
        }
    },
    // T1588 - Obtain Capabilities
    {
        id: 'T1588',
        name: 'Obtain Capabilities',
        description: 'Adversaries may obtain capabilities like malware or tools.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('obtain malware') || 
                    commandLine.toLowerCase().includes('tool download')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('obtain malware');
        }
    },
    {
        id: 'T1588.001',
        name: 'Obtain Capabilities: Malware',
        description: 'Adversaries may obtain malware.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('malware download')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('malware download');
        }
    },
    {
        id: 'T1588.002',
        name: 'Obtain Capabilities: Tool',
        description: 'Adversaries may obtain tools.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('tool download') || 
                    commandLine.toLowerCase().includes('nmap')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.py/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('tool download');
        }
    },
    {
        id: 'T1588.003',
        name: 'Obtain Capabilities: Code Signing Certificates',
        description: 'Adversaries may obtain code signing certificates.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('code signing certificate')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.cer')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('code signing certificate');
        }
    },
    {
        id: 'T1588.004',
        name: 'Obtain Capabilities: Digital Certificates',
        description: 'Adversaries may obtain digital certificates.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('digital certificate') || 
                     commandLine.toLowerCase().includes('certutil') || 
                     commandLine.toLowerCase().includes('openssl'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.cer|\.crt|\.pem/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('digital certificate');
        }
    },
    {
        id: 'T1588.005',
        name: 'Obtain Capabilities: Exploits',
        description: 'Adversaries may obtain exploits.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('exploit download') || 
                     commandLine.toLowerCase().includes('metasploit'))) {
                    return true;
                }
                if (eid === '1116' && event.Message?.toLowerCase().includes('exploit')) {
                    return true; // Antivirus detection of exploits
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('exploit download');
        }
    },
    {
        id: 'T1588.006',
        name: 'Obtain Capabilities: Vulnerabilities',
        description: 'Adversaries may obtain information about vulnerabilities.',
        mitre_link: 'https://attack.mitre.org/techniques/T1588/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('vulnerability scan') || 
                     commandLine.toLowerCase().includes('nessus') || 
                     commandLine.toLowerCase().includes('nmap'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/cve\.mitre\.org|nvd\.nist\.gov/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('vulnerability scan');
        }
    },
    // T1608 - Stage Capabilities
    {
        id: 'T1608',
        name: 'Stage Capabilities',
        description: 'Adversaries may stage capabilities for use in attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('stage malware') || 
                     commandLine.toLowerCase().includes('upload'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll|\.py/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('stage malware');
        }
    },
    {
        id: 'T1608.001',
        name: 'Stage Capabilities: Upload Malware',
        description: 'Adversaries may upload malware to stage it for attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('upload malware') || 
                     commandLine.toLowerCase().includes('ftp') || 
                     commandLine.toLowerCase().includes('scp'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('upload malware');
        }
    },
    {
        id: 'T1608.002',
        name: 'Stage Capabilities: Upload Tool',
        description: 'Adversaries may upload tools to stage them for attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('upload tool') || 
                     commandLine.toLowerCase().includes('nmap') || 
                     commandLine.toLowerCase().includes('wget'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.py/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('upload tool');
        }
    },
    {
        id: 'T1608.003',
        name: 'Stage Capabilities: Install Digital Certificate',
        description: 'Adversaries may install digital certificates to stage capabilities.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('install certificate') || 
                     commandLine.toLowerCase().includes('certutil'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.cer|\.crt|\.pem/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('install certificate');
        }
    },
    {
        id: 'T1608.004',
        name: 'Stage Capabilities: Drive-by Target',
        description: 'Adversaries may stage capabilities for drive-by attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('drive-by') || 
                     commandLine.toLowerCase().includes('exploit kit'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.')) {
                    return true; // Suspicious network connections
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('drive-by');
        }
    },
    {
        id: 'T1608.005',
        name: 'Stage Capabilities: Link Target',
        description: 'Adversaries may stage capabilities via malicious links.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('malicious link') || 
                     commandLine.toLowerCase().includes('url'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('malicious link');
        }
    },
    {
        id: 'T1608.006',
        name: 'Stage Capabilities: SEO Poisoning',
        description: 'Adversaries may use SEO poisoning to stage capabilities.',
        mitre_link: 'https://attack.mitre.org/techniques/T1608/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('seo poisoning') || 
                     commandLine.toLowerCase().includes('search engine'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/google\.com|bing\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('seo poisoning');
        }
    }
];