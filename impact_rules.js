const rules = [
    // T1485 - Data Destruction
    {
        id: 'T1485',
        name: 'Data Destruction',
        description: 'Adversaries may destroy data to disrupt availability.',
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
        description: 'Adversaries may encrypt data for ransom or disruption.',
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
    // T1490 - Inhibit System Recovery
    {
        id: 'T1490',
        name: 'Inhibit System Recovery',
        description: 'Adversaries may inhibit system recovery to prevent data restoration.',
        mitre_link: 'https://attack.mitre.org/techniques/T1490/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/vssadmin delete|bcdedit.*bootstatuspolicy/)) {
                    return true;
                }
                if (eid === '7045' && event.ServiceName?.toLowerCase().includes('shadow')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system recovery');
        }
    },
    // T1491 - Defacement
    {
        id: 'T1491',
        name: 'Defacement',
        description: 'Adversaries may deface systems or websites for impact.',
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
        description: 'Adversaries may deface internal systems for impact.',
        mitre_link: 'https://attack.mitre.org/techniques/T1491/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/deface.*internal|modify.*intranet/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.html|\.asp/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('internal defacement');
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
                    commandLine.toLowerCase().match(/flash.*corrupt|bios.*update/)) {
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
        description: 'Adversaries may hijack system resources for cryptocurrency mining.',
        mitre_link: 'https://attack.mitre.org/techniques/T1496/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/minerd|xmrig|crypto.*mine/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.sh/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('resource hijacking');
        }
    },
    // T1498 - Network Denial of Service
    {
        id: 'T1498',
        name: 'Network Denial of Service',
        description: 'Adversaries may perform DoS attacks to disrupt network availability.',
        mitre_link: 'https://attack.mitre.org/techniques/T1498/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/ddos|hping|synflood/)) {
                    return true;
                }
                if (eid === '5152' && event.SourcePort && event.DestinationPort) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network denial');
        }
    },
    // T1499 - Endpoint Denial of Service
    {
        id: 'T1499',
        name: 'Endpoint Denial of Service',
        description: 'Adversaries may perform DoS attacks on endpoints.',
        mitre_link: 'https://attack.mitre.org/techniques/T1499/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/slowloris|endpoint.*flood/)) {
                    return true;
                }
                if (eid === '5156' && event.Application) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('endpoint denial');
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
                    commandLine.toLowerCase().match(/sed.*replace|modify.*data/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.csv|\.json/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('data manipulation');
        }
    },
    // T1650 - Endpoint Data Deletion
    {
        id: 'T1650',
        name: 'Endpoint Data Deletion',
        description: 'Adversaries may delete data on endpoints to disrupt operations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1650/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/del.*endpoint|rm.*-r/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('endpoint data deletion');
        }
    },
    // T1651 - Distributed Component Object Model
    {
        id: 'T1651',
        name: 'Distributed Component Object Model',
        description: 'Adversaries may use DCOM for remote impact.',
        mitre_link: 'https://attack.mitre.org/techniques/T1651/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/dcom|ole.*remote/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '135') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dcom');
        }
    },
    // T1656 - Trusted Relationship Abuse
    {
        id: 'T1656',
        name: 'Trusted Relationship Abuse',
        description: 'Adversaries may abuse trusted relationships for impact.',
        mitre_link: 'https://attack.mitre.org/techniques/T1656/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/trust.*abuse|kerberos.*delegate/)) {
                    return true;
                }
                if (eid === '4672' && event.Privileges?.includes('SeEnableDelegationPrivilege')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('trusted relationship');
        }
    },
    // T1529 - System Shutdown/Reboot
    {
        id: 'T1529',
        name: 'System Shutdown/Reboot',
        description: 'Adversaries may shut down or reboot systems for impact.',
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
        description: 'Adversaries may remove account access for impact.',
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
        description: 'Adversaries may steal financial assets or data.',
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
    // Additional techniques can be added for full coverage...
];
