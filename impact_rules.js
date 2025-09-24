const rules = [
    // T1485 - Data Destruction
    {
        id: 'T1485',
        name: 'Data Destruction',
        description: 'Adversaries may destroy data to disrupt operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1485/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/del.*\\|rm.*-rf|shred/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.doc|\.pdf|\.txt/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('data destruction');
        }
    },
    // T1486 - Data Encrypted for Impact
    {
        id: 'T1486',
        name: 'Data Encrypted for Impact',
        description: 'Adversaries may encrypt data to demand ransom or disrupt operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1486/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/ransomware|encrypt.*file|gpg.*encrypt/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.encrypted|\.locked/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('data encrypted');
        }
    },
    // T1491 - Defacement
    {
        id: 'T1491',
        name: 'Defacement',
        description: 'Adversaries may deface systems or websites to disrupt operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1491/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/deface|modify.*web/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.html|\.css|\.js/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('defacement');
        }
    },
    {
        id: 'T1491.001',
        name: 'Defacement: Internal Defacement',
        description: 'Adversaries may deface internal systems.',
        mitre_link: 'https://attack.mitre.org/techniques/T1491/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/deface.*internal|modify.*desktop/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/desktop.*\.txt|config.*\.conf/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('internal defacement');
        }
    },
    {
        id: 'T1491.002',
        name: 'Defacement: External Defacement',
        description: 'Adversaries may deface external websites.',
        mitre_link: 'https://attack.mitre.org/techniques/T1491/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/deface.*web|modify.*site/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/web|http/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('external defacement');
        }
    },
    // T1490 - Inhibit System Recovery
    {
        id: 'T1490',
        name: 'Inhibit System Recovery',
        description: 'Adversaries may inhibit system recovery mechanisms.',
        mitre_link: 'https://attack.mitre.org/techniques/T1490/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/vssadmin.*delete|bcdedit.*recovery/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().match(/shadowcopy|recovery/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('inhibit system recovery');
        }
    },
    // T1489 - Service Stop
    {
        id: 'T1489',
        name: 'Service Stop',
        description: 'Adversaries may stop services to disrupt operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1489/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/net stop|sc stop|systemctl stop/)) {
                    return true;
                }
                if (eid === '7045' && event.ServiceName?.toLowerCase().includes('stop')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('service stop');
        }
    },
    // T1498 - Network Denial of Service
    {
        id: 'T1498',
        name: 'Network Denial of Service',
        description: 'Adversaries may perform network denial of service attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1498/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/hping|slowloris|dos/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp && event.PacketsSent && parseInt(event.PacketsSent) > 1000) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('denial of service');
        }
    },
    {
        id: 'T1498.001',
        name: 'Network Denial of Service: Direct Network Flood',
        description: 'Adversaries may perform direct network flood DoS attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1498/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/flood|syn.*flood|udp.*flood/)) {
                    return true;
                }
                if (eid === '3' && event.Protocol?.toLowerCase().match(/tcp|udp/) && event.PacketsSent && parseInt(event.PacketsSent) > 1000) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('direct network flood');
        }
    },
    {
        id: 'T1498.002',
        name: 'Network Denial of Service: Reflection Amplification',
        description: 'Adversaries may use reflection amplification for DoS attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1498/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/ntp.*amplification|dns.*amplification/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/123|53/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('reflection amplification');
        }
    },
    // T1499 - Endpoint Denial of Service
    {
        id: 'T1499',
        name: 'Endpoint Denial of Service',
        description: 'Adversaries may perform endpoint denial of service attacks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1499/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/forkbomb|crash.*system/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('system')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('endpoint denial');
        }
    },
    {
        id: 'T1499.001',
        name: 'Endpoint Denial of Service: OS Exhaustion Flood',
        description: 'Adversaries may exhaust OS resources for DoS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1499/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/forkbomb|consume.*cpu/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('memory')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('os exhaustion');
        }
    },
    {
        id: 'T1499.002',
        name: 'Endpoint Denial of Service: Service Exhaustion Flood',
        description: 'Adversaries may exhaust services for DoS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1499/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/service.*flood|overload.*service/)) {
                    return true;
                }
                if (eid === '7045' && event.ServiceName?.toLowerCase().includes('flood')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('service exhaustion');
        }
    },
    {
        id: 'T1499.003',
        name: 'Endpoint Denial of Service: Application Exhaustion Flood',
        description: 'Adversaries may exhaust applications for DoS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1499/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/application.*flood|overload.*app/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('application')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('application exhaustion');
        }
    },
    {
        id: 'T1499.004',
        name: 'Endpoint Denial of Service: Application or System Exploitation',
        description: 'Adversaries may exploit applications or systems for DoS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1499/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/exploit.*crash|vuln.*dos/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('exploit')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('application exploitation');
        }
    },
    // T1565 - Data Manipulation
    {
        id: 'T1565',
        name: 'Data Manipulation',
        description: 'Adversaries may manipulate data to disrupt operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1565/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/modify.*data|alter.*file/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.db|\.sql/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('data manipulation');
        }
    },
    {
        id: 'T1565.001',
        name: 'Data Manipulation: Stored Data Manipulation',
        description: 'Adversaries may manipulate stored data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1565/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/sql.*update|modify.*database/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.db|\.sql/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('stored data manipulation');
        }
    },
    {
        id: 'T1565.002',
        name: 'Data Manipulation: Transmitted Data Manipulation',
        description: 'Adversaries may manipulate transmitted data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1565/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/mitm|intercept.*data/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp && event.Data?.toLowerCase().includes('modify')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('transmitted data manipulation');
        }
    },
    {
        id: 'T1565.003',
        name: 'Data Manipulation: Runtime Data Manipulation',
        description: 'Adversaries may manipulate data at runtime.',
        mitre_link: 'https://attack.mitre.org/techniques/T1565/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/hook.*data|runtime.*modify/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('runtime')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('runtime data manipulation');
        }
    },
    // T1495 - Firmware Corruption
    {
        id: 'T1495',
        name: 'Firmware Corruption',
        description: 'Adversaries may corrupt firmware to disrupt operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1495/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/firmware.*update|bios.*corrupt/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('firmware')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('firmware corruption');
        }
    },
    // T1496 - Resource Hijacking
    {
        id: 'T1496',
        name: 'Resource Hijacking',
        description: 'Adversaries may hijack resources for unauthorized use.',
        mitre_link: 'https://attack.mitre.org/techniques/T1496/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/miner|cryptojack/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/mining|pool/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('resource hijacking');
        }
    },
    // T1561 - Disk Wipe
    {
        id: 'T1561',
        name: 'Disk Wipe',
        description: 'Adversaries may wipe disks to disrupt operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1561/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/dd.*if=|wipe.*disk/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('disk')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('disk wipe');
        }
    },
    {
        id: 'T1561.001',
        name: 'Disk Wipe: Disk Content Wipe',
        description: 'Adversaries may wipe disk content to disrupt operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1561/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/dd.*if=/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('wipe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('disk content wipe');
        }
    },
    {
        id: 'T1561.002',
        name: 'Disk Wipe: Disk Structure Wipe',
        description: 'Adversaries may wipe disk structures to disrupt operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1561/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/format.*disk|fdisk/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('partition')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('disk structure wipe');
        }
    },
    // T1529 - System Shutdown/Reboot
    {
        id: 'T1529',
        name: 'System Shutdown/Reboot',
        description: 'Adversaries may shut down or reboot systems to disrupt operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1529/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/shutdown|reboot/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('shutdown')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system shutdown');
        }
    },
    // T1531 - Account Access Removal
    {
        id: 'T1531',
        name: 'Account Access Removal',
        description: 'Adversaries may remove account access to disrupt operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1531/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/net user.*delete|userdel/)) {
                    return true;
                }
                if ((eid === '4720' || eid === '4738') && event.TargetUserName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('account access removal');
        }
    },
    // T1657 - Financial Theft
    {
        id: 'T1657',
        name: 'Financial Theft',
        description: 'Adversaries may steal financial data or resources.',
        mitre_link: 'https://attack.mitre.org/techniques/T1657/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/bank|financial.*transfer|crypto.*wallet/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/bank|payment|crypto/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('financial theft');
        }
    }
];
