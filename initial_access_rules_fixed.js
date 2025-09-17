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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            const parentImage = (event.ParentImage || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4672' || eid === '4625') && // Added failed logons
                    event.TargetUserName && !event.TargetUserName.toLowerCase().includes('system') && event.LogonType?.match(/2|3|10/)) { // Interactive, network, remote logons
                    return true;
                }
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (image.includes('net.exe') || commandLine.includes('net user') || commandLine.includes('net group') || parentImage.includes('powershell.exe'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('net user') || event.toLowerCase().includes('logon');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && 
                    event.TargetUserName?.toLowerCase().match(/admin|guest|administrator|default|root/)) {
                    return true;
                }
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('net user') && (commandLine.includes('admin') || commandLine.includes('guest') || commandLine.includes('default')))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('net user admin') || event.toLowerCase().includes('net user guest');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && event.TargetDomainName && 
                    !event.TargetDomainName.toLowerCase().includes('system') && event.LogonType === '3') { // Network logon
                    return true;
                }
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('net user') && commandLine.includes('/domain') || commandLine.includes('get-aduser'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('net user /domain');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && event.TargetUserName && 
                    !event.TargetDomainName && !event.TargetUserName.toLowerCase().includes('system') && event.LogonType === '2') { // Interactive logon
                    return true;
                }
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (image.includes('net.exe') && commandLine.includes('user /add') || commandLine.includes('new-localuser'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('net user /add');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && event.TargetUserName?.toLowerCase().match(/aws|azure|gcp|cloud/)) {
                    return true;
                }
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('aws login') || commandLine.includes('az login') || commandLine.includes('gcloud auth') || commandLine.includes('aws configure'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/amazonaws\.com|azure\.com|googleapis\.com/)) { // Cloud API connections
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('aws login') || event.toLowerCase().includes('az login');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('autorun') || commandLine.includes('usb') || commandLine.includes('removable') || commandLine.includes('diskpart'))) {
                    return true;
                }
                if ((eid === '11' || eid === '15') && event.TargetFilename?.toLowerCase().match(/autorun\.inf|desktop\.ini/)) { // Added file creation monitoring
                    return true;
                }
                if (eid === '6416' && event.DeviceDescription?.toLowerCase().includes('usb') || event.DeviceDescription?.toLowerCase().includes('removable')) { // Device installation
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('autorun');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (image.includes('sqlmap.exe') || commandLine.includes('sqlmap') || commandLine.includes('exploit') || commandLine.includes('nikto') || commandLine.includes('dirbuster'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/80|443|8080/) && event.Protocol?.toLowerCase() === 'tcp') { // Web ports with protocol
                    return true;
                }
                if (eid === '1116' && event.Message?.includes('exploit')) { // AV exploit detection
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('sqlmap');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && event.LogonType === '10' && event.SourceIp?.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)) { // RDP with external IP
                    return true;
                }
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (image.includes('mstsc.exe') || commandLine.includes('rdp') || commandLine.includes('vpn') || commandLine.includes('openvpn') || commandLine.includes('citrix'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/3389|1194/) && event.Protocol?.toLowerCase() === 'tcp') { // RDP/VPN ports
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('rdp') || event.toLowerCase().includes('vpn');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('supply chain') || commandLine.includes('software update') || commandLine.includes('apt-get') || commandLine.includes('yum install'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.msi|\.deb|\.rpm/)) {
                    return true;
                }
                if (eid === '1116' && event.Message?.includes('trojan')) { // AV trojan detection
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('supply chain');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('npm install') || commandLine.includes('pip install') || commandLine.includes('maven') || commandLine.includes('gradle') || commandLine.includes('composer'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/package\.json|requirements\.txt|pom\.xml|build\.gradle|composer\.json/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/npmjs\.com|pypi\.org|mvnrepository\.com/)) { // Package repos
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('npm install');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('software update') || commandLine.includes('install') || commandLine.includes('winget') || commandLine.includes('choco install') || commandLine.includes('msiexec'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.msi|\.pkg|\.dmg/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('software update');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('firmware') || commandLine.includes('hardware update') || commandLine.includes('bios update') || commandLine.includes('uefi'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.bin|\.rom|\.fw/)) {
                    return true;
                }
                if (eid === '6416' && event.DeviceDescription?.includes('firmware')) { // Device/firmware installation
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('firmware');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && event.TargetDomainName?.toLowerCase().match(/partner|trusted|vendor/)) {
                    return true;
                }
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('trusted domain') || commandLine.includes('partner network') || commandLine.includes('add-adtrust') || commandLine.includes('nltest /add_trust'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('trusted domain');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('phish') || commandLine.includes('email') || commandLine.includes('gophish') || commandLine.includes('spearphish'))) {
                    return true;
                }
                if (eid === '1116' && event.Message?.toLowerCase().includes('phishing')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.eml|\.msg/)) { // Email files
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('phish');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('attachment') && commandLine.includes('email') || commandLine.includes('malicious doc') || commandLine.includes('outlook /safe'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.docx|\.pdf|\.exe|\.zip|\.rtf/)) {
                    return true;
                }
                if (eid === '1116' && event.Message?.includes('attachment')) { // AV attachment scan
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('email attachment');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('url') && commandLine.includes('email') || commandLine.includes('malicious link') || commandLine.includes('bit.ly'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.') && event.Referer?.includes('mail')) { // Email referers
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('email url');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('smtp') || commandLine.includes('email service') || commandLine.includes('sendgrid') || commandLine.includes('mailchimp'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/gmail\.com|outlook\.com|sendgrid\.net|mailchimp\.com/) && event.Port === '587') { // SMTP ports
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('smtp');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('drive-by') || commandLine.includes('exploit kit') || commandLine.includes('ek') || commandLine.includes('malvertising') || commandLine.includes('watering hole'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.') && event.UserAgent?.match(/bot|crawler/)) { // Suspicious agents
                    return true;
                }
                if (eid === '1116' && event.Message?.includes('drive-by')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('drive-by');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('hardware') || commandLine.includes('usb device') || commandLine.includes('keyboard') || commandLine.includes('mouse') || commandLine.includes('hid'))) {
                    return true;
                }
                if ((eid === '6416' || eid === '7045') && (event.DeviceDescription?.toLowerCase().includes('usb') || event.ServiceName?.includes('hid'))) { // Device/service install
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('usb device');
        }
    }
];
