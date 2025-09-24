const rules = [
    // T1078 - Valid Accounts
    {
        id: 'T1078',
        name: 'Valid Accounts',
        description: 'Adversaries may obtain and abuse valid accounts to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4672') && 
                    event.TargetUserName && !event.TargetUserName.toLowerCase().includes('system')) {
                    return true; // Successful logon with non-system account
                }
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('net.exe') && 
                    commandLine.toLowerCase().includes('user')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && 
                (event.toLowerCase().includes('net user') || event.toLowerCase().includes('logon'));
        }
    },
    {
        id: 'T1078.001',
        name: 'Valid Accounts: Default Accounts',
        description: 'Adversaries may use default accounts to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4624' && 
                    event.TargetUserName?.toLowerCase().match(/admin|guest|administrator/)) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net user') && 
                    commandLine.toLowerCase().includes('admin') || commandLine.toLowerCase().includes('guest')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && 
                (event.toLowerCase().includes('net user admin') || event.toLowerCase().includes('net user guest'));
        }
    },
    {
        id: 'T1078.002',
        name: 'Valid Accounts: Domain Accounts',
        description: 'Adversaries may use domain accounts to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4624' && event.TargetDomainName && 
                    !event.TargetDomainName.toLowerCase().includes('system')) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net user') && 
                    commandLine.toLowerCase().includes('/domain')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('net user /domain');
        }
    },
    {
        id: 'T1078.003',
        name: 'Valid Accounts: Local Accounts',
        description: 'Adversaries may use local accounts to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4624' && event.TargetUserName && 
                    !event.TargetDomainName && !event.TargetUserName.toLowerCase().includes('system')) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('net.exe') && 
                    commandLine.toLowerCase().includes('user /add')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('net user /add');
        }
    },
    {
        id: 'T1078.004',
        name: 'Valid Accounts: Cloud Accounts',
        description: 'Adversaries may use cloud accounts to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4624' && event.TargetUserName?.toLowerCase().match(/aws|azure/)) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('aws login') || 
                    commandLine.toLowerCase().includes('az login')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && 
                (event.toLowerCase().includes('aws login') || event.toLowerCase().includes('az login'));
        }
    },
    // T1091 - Replication Through Removable Media
    {
        id: 'T1091',
        name: 'Replication Through Removable Media',
        description: 'Adversaries may use removable media to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1091/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('autorun') || 
                    commandLine.toLowerCase().includes('usb')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('autorun.inf')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('autorun');
        }
    },
    // T1190 - Exploit Public-Facing Application
    {
        id: 'T1190',
        name: 'Exploit Public-Facing Application',
        description: 'Adversaries may exploit vulnerabilities in public-facing applications.',
        mitre_link: 'https://attack.mitre.org/techniques/T1190/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('sqlmap.exe') || 
                     commandLine.toLowerCase().includes('sqlmap') || 
                     commandLine.toLowerCase().includes('exploit'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/80|443/)) {
                    return true; // HTTP/HTTPS connections
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('sqlmap');
        }
    },
    // T1133 - External Remote Services
    {
        id: 'T1133',
        name: 'External Remote Services',
        description: 'Adversaries may use external remote services like VPN or RDP to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1133/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4624' && event.LogonType === '10') {
                    return true; // Remote interactive logon (RDP)
                }
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('mstsc.exe') || 
                     commandLine.toLowerCase().includes('rdp') || 
                     commandLine.toLowerCase().includes('vpn'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && 
                (event.toLowerCase().includes('rdp') || event.toLowerCase().includes('vpn'));
        }
    },
    // T1195 - Supply Chain Compromise
    {
        id: 'T1195',
        name: 'Supply Chain Compromise',
        description: 'Adversaries may manipulate supply chains to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1195/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('supply chain') || 
                    commandLine.toLowerCase().includes('software update')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.exe')) {
                    return true; // Suspicious executable creation
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('supply chain');
        }
    },
    {
        id: 'T1195.001',
        name: 'Supply Chain Compromise: Compromise Software Dependencies and Development Tools',
        description: 'Adversaries may compromise software dependencies or development tools.',
        mitre_link: 'https://attack.mitre.org/techniques/T1195/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('npm install') || 
                     commandLine.toLowerCase().includes('pip install'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/package\.json|requirements\.txt/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('npm install');
        }
    },
    {
        id: 'T1195.002',
        name: 'Supply Chain Compromise: Compromise Software Supply Chain',
        description: 'Adversaries may compromise software supply chains.',
        mitre_link: 'https://attack.mitre.org/techniques/T1195/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('software update') || 
                    commandLine.toLowerCase().includes('install')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.msi')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('software update');
        }
    },
    {
        id: 'T1195.003',
        name: 'Supply Chain Compromise: Compromise Hardware Supply Chain',
        description: 'Adversaries may compromise hardware supply chains.',
        mitre_link: 'https://attack.mitre.org/techniques/T1195/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('firmware') || 
                    commandLine.toLowerCase().includes('hardware update')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.bin')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('firmware');
        }
    },
    // T1199 - Trusted Relationship
    {
        id: 'T1199',
        name: 'Trusted Relationship',
        description: 'Adversaries may breach or abuse trusted relationships to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1199/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4624' && event.TargetDomainName?.toLowerCase().includes('partner')) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('trusted domain') || 
                    commandLine.toLowerCase().includes('partner network')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('trusted domain');
        }
    },
    // T1566 - Phishing
    {
        id: 'T1566',
        name: 'Phishing',
        description: 'Adversaries may use phishing to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1566/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('phish') || 
                    commandLine.toLowerCase().includes('email')) {
                    return true;
                }
                if (eid === '1116' && event.Message?.toLowerCase().includes('phishing')) {
                    return true; // Microsoft Defender phishing detection
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('phish');
        }
    },
    {
        id: 'T1566.001',
        name: 'Phishing: Spearphishing Attachment',
        description: 'Adversaries may use spearphishing attachments to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1566/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('attachment') && 
                    commandLine.toLowerCase().includes('email')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.docx|\.pdf|\.exe/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('email attachment');
        }
    },
    {
        id: 'T1566.002',
        name: 'Phishing: Spearphishing Link',
        description: 'Adversaries may use spearphishing links to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1566/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('url') && 
                    commandLine.toLowerCase().includes('email')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('email url');
        }
    },
    {
        id: 'T1566.003',
        name: 'Phishing: Spearphishing via Service',
        description: 'Adversaries may use third-party services for spearphishing.',
        mitre_link: 'https://attack.mitre.org/techniques/T1566/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('smtp') || 
                    commandLine.toLowerCase().includes('email service')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/gmail\.com|outlook\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('smtp');
        }
    },
    // T1189 - Drive-by Compromise
    {
        id: 'T1189',
        name: 'Drive-by Compromise',
        description: 'Adversaries may gain access through drive-by compromises on websites.',
        mitre_link: 'https://attack.mitre.org/techniques/T1189/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('drive-by') || 
                    commandLine.toLowerCase().includes('exploit kit')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('drive-by');
        }
    },
    // T1200 - Hardware Additions
    {
        id: 'T1200',
        name: 'Hardware Additions',
        description: 'Adversaries may introduce hardware to gain initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1200/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('hardware') || 
                    commandLine.toLowerCase().includes('usb device')) {
                    return true;
                }
                if (eid === '6416' && event.DeviceDescription?.toLowerCase().includes('usb')) {
                    return true; // USB device installation
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('usb device');
        }
    }
];
