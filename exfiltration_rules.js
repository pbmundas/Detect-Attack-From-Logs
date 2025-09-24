const rules = [
    // T1020 - Automated Exfiltration
    {
        id: 'T1020',
        name: 'Automated Exfiltration',
        description: 'Adversaries may exfiltrate data automatically using scripts or tools.',
        mitre_link: 'https://attack.mitre.org/techniques/T1020/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/powershell.*upload|python.*exfil|curl.*post/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/80|443|21/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('automated exfiltration');
        }
    },
    // T1030 - Data Transfer Size Limits
    {
        id: 'T1030',
        name: 'Data Transfer Size Limits',
        description: 'Adversaries may limit data transfer sizes to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1030/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/split.*file|chunk.*data/)) {
                    return true;
                }
                if (eid === '3' && event.BytesSent && parseInt(event.BytesSent) < 1000000) { // Less than 1MB
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('data transfer size limits');
        }
    },
    // T1041 - Exfiltration Over C2 Channel
    {
        id: 'T1041',
        name: 'Exfiltration Over C2 Channel',
        description: 'Adversaries may exfiltrate data over a command and control channel.',
        mitre_link: 'https://attack.mitre.org/techniques/T1041/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/c2|callback.*data/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/443|8443/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('c2 channel');
        }
    },
    // T1048 - Exfiltration Over Alternative Protocol
    {
        id: 'T1048',
        name: 'Exfiltration Over Alternative Protocol',
        description: 'Adversaries may exfiltrate data using alternative protocols.',
        mitre_link: 'https://attack.mitre.org/techniques/T1048/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/ftp|sftp|scp|rsync/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/21|22|873/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('alternative protocol');
        }
    },
    {
        id: 'T1048.001',
        name: 'Exfiltration Over Symmetric Encrypted Non-C2 Protocol',
        description: 'Adversaries may exfiltrate data over encrypted non-C2 protocols.',
        mitre_link: 'https://attack.mitre.org/techniques/T1048/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/openssl|ssh.*-e/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/22|443/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('symmetric encrypted');
        }
    },
    // T1052 - Exfiltration Over Physical Medium
    {
        id: 'T1052',
        name: 'Exfiltration Over Physical Medium',
        description: 'Adversaries may exfiltrate data via removable media.',
        mitre_link: 'https://attack.mitre.org/techniques/T1052/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/copy.*usb|xcopy.*removable/)) {
                    return true;
                }
                if (eid === '1006' && event.DeviceName?.toLowerCase().includes('usb')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('physical medium');
        }
    },
    // T1567 - Exfiltration Over Web Service
    {
        id: 'T1567',
        name: 'Exfiltration Over Web Service',
        description: 'Adversaries may exfiltrate data to web services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1567/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/curl.*upload|wget.*post/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/dropbox\.com|google\.com|onedrive\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('web service');
        }
    },
    {
        id: 'T1567.001',
        name: 'Exfiltration Over Web Service: Exfiltration to Code Repository',
        description: 'Adversaries may exfiltrate data to code repositories.',
        mitre_link: 'https://attack.mitre.org/techniques/T1567/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/git.*push|github.*upload/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/github\.com|gitlab\.com|bitbucket\.org/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('code repository');
        }
    },
    {
        id: 'T1567.002',
        name: 'Exfiltration Over Web Service: Exfiltration to Cloud Storage',
        description: 'Adversaries may exfiltrate data to cloud storage services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1567/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/dropbox.*upload|onedrive.*sync/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/dropbox\.com|onedrive\.com|drive\.google\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud storage');
        }
    },
    {
        id: 'T1567.003',
        name: 'Exfiltration Over Web Service: Exfiltration to Text Storage Sites',
        description: 'Adversaries may exfiltrate data to text storage sites.',
        mitre_link: 'https://attack.mitre.org/techniques/T1567/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/pastebin|gist/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/pastebin\.com|gist\.github/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('text storage');
        }
    },
    {
        id: 'T1567.004',
        name: 'Exfiltration Over Webhook',
        description: 'Adversaries may exfiltrate data over webhooks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1567/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/webhook|api.*post/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/webhook|discord\.com|slack\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('webhook');
        }
    },
    // T1029 - Scheduled Transfer
    {
        id: 'T1029',
        name: 'Scheduled Transfer',
        description: 'Adversaries may schedule data exfiltration at specific times.',
        mitre_link: 'https://attack.mitre.org/techniques/T1029/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/schtasks|at|cron.*transfer/)) {
                    return true;
                }
                if (eid === '7045' && event.ServiceName?.toLowerCase().includes('transfer')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('scheduled transfer');
        }
    },
    // T1537 - Transfer Data to Cloud Account
    {
        id: 'T1537',
        name: 'Transfer Data to Cloud Account',
        description: 'Adversaries may exfiltrate data to a cloud account.',
        mitre_link: 'https://attack.mitre.org/techniques/T1537/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws s3 sync|gcloud storage cp|az storage blob/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/s3\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud account');
        }
    }
    // Additional techniques can be added for full coverage...
];
