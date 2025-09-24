const rules = [
    // T1078 - Valid Accounts
    {
        id: 'T1078',
        name: 'Valid Accounts',
        description: 'Adversaries may obtain and abuse valid accounts for initial access.',
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
        description: 'Adversaries may use default accounts for initial access.',
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
                    (commandLine.toLowerCase().includes('admin') || commandLine.toLowerCase().includes('guest'))) {
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
        description: 'Adversaries may use domain accounts for initial access.',
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
            return typeof event === 'string' && event && event.toLowerCase().includes('domain accounts');
        }
    },
    {
        id: 'T1078.003',
        name: 'Valid Accounts: Local Accounts',
        description: 'Adversaries may use local accounts for initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4624' && event.TargetDomainName?.toLowerCase().includes('local')) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net user') && 
                    !commandLine.toLowerCase().includes('/domain')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('local accounts');
        }
    },
    // T1091 - Replication Through Removable Media
    {
        id: 'T1091',
        name: 'Replication Through Removable Media',
        description: 'Adversaries may spread through removable media.',
        mitre_link: 'https://attack.mitre.org/techniques/T1091/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('autorun') || 
                    commandLine.toLowerCase().includes('removable media')) {
                    return true;
                }
                if (eid === '1006' && event.DeviceName?.toLowerCase().includes('usb')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('removable media');
        }
    },
    // T1133 - External Remote Services
    {
        id: 'T1133',
        name: 'External Remote Services',
        description: 'Adversaries may leverage external remote services for access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1133/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('rdp') || 
                    commandLine.toLowerCase().includes('ssh')) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/3389|22/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('remote services');
        }
    },
    // T1187 - Forced Authentication
    {
        id: 'T1187',
        name: 'Forced Authentication',
        description: 'Adversaries may force users to authenticate for initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1187/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('ntlm') || 
                    commandLine.toLowerCase().includes('kerberos')) {
                    return true;
                }
                if (eid === '4672' && event.TargetUserName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('forced authentication');
        }
    },
    // T1190 - Exploit Public-Facing Application
    {
        id: 'T1190',
        name: 'Exploit Public-Facing Application',
        description: 'Adversaries may exploit public-facing applications for access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1190/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cve') || 
                    commandLine.toLowerCase().includes('exploit')) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/80|443/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('exploit');
        }
    },
    // T1195 - Supply Chain Compromise
    {
        id: 'T1195',
        name: 'Supply Chain Compromise',
        description: 'Adversaries may compromise the supply chain for initial access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1195/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('supply chain') || 
                    commandLine.toLowerCase().includes('third-party')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('update')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('supply chain');
        }
    },
    // T1199 - Trusted Relationship
    {
        id: 'T1199',
        name: 'Trusted Relationship',
        description: 'Adversaries may leverage trusted relationships for access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1199/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('trust') || 
                    commandLine.toLowerCase().includes('kerberos')) {
                    return true;
                }
                if (eid === '4672' && event.Privileges?.includes('SeEnableDelegationPrivilege')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('trusted relationship');
        }
    },
    // T1203 - Exploitation for Client Execution
    {
        id: 'T1203',
        name: 'Exploitation for Client Execution',
        description: 'Adversaries may exploit client applications for access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1203/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('exploit') || 
                    commandLine.toLowerCase().includes('client')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('client execution');
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
                if (eid === '3' && event.DestinationHostname?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('phishing');
        }
    },
    {
        id: 'T1566.001',
        name: 'Phishing: Spearphishing Attachment',
        description: 'Adversaries may use spearphishing with attachments to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1566/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('phish') || 
                    commandLine.toLowerCase().includes('attachment')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.docx|\.pdf/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('spearphishing attachment');
        }
    },
    {
        id: 'T1566.002',
        name: 'Phishing: Spearphishing Link',
        description: 'Adversaries may use spearphishing with links to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1566/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('phish') || 
                    commandLine.toLowerCase().includes('link')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('spearphishing link');
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
        description: 'Adversaries may gain access via drive-by compromises.',
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
        description: 'Adversaries may introduce hardware for initial access.',
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
    // Additional techniques can be added for full coverage...
];
