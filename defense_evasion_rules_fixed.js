const rules = [
    // T1134 - Access Token Manipulation
    {
        id: 'T1134',
        name: 'Access Token Manipulation',
        description: 'Adversaries may manipulate access tokens to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1134/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('setoken') || 
                    commandLine.toLowerCase().includes('duplicate token')) {
                    return true;
                }
                if (eid === '4672' && event.Privileges?.toLowerCase().includes('sedebugprivilege')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('token manipulation');
        }
    },
    {
        id: 'T1134.001',
        name: 'Access Token Manipulation: Token Impersonation/Theft',
        description: 'Adversaries may impersonate or steal tokens to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1134/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('impersonate token')) {
                    return true;
                }
                if (eid === '4672' && event.Privileges?.toLowerCase().includes('seimpersonateprivilege')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('token impersonation');
        }
    },
    {
        id: 'T1134.002',
        name: 'Access Token Manipulation: Create Process with Token',
        description: 'Adversaries may create processes with stolen tokens to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1134/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('createprocesswithtoken')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('create process with token');
        }
    },
    {
        id: 'T1134.003',
        name: 'Access Token Manipulation: Make and Impersonate Token',
        description: 'Adversaries may create and impersonate tokens to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1134/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('make token')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('make token');
        }
    },
    {
        id: 'T1134.004',
        name: 'Access Token Manipulation: Parent PID Spoofing',
        description: 'Adversaries may spoof parent PIDs to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1134/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('parent pid')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('parent pid spoofing');
        }
    },
    {
        id: 'T1134.005',
        name: 'Access Token Manipulation: SID-History Injection',
        description: 'Adversaries may inject SID history to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1134/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sid history')) {
                    return true;
                }
                if (eid === '4738' && event.SidHistory) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('sid history');
        }
    },
    // T1548 - Abuse Elevation Control Mechanism
    {
        id: 'T1548',
        name: 'Abuse Elevation Control Mechanism',
        description: 'Adversaries may abuse elevation control mechanisms to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('uac bypass')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('uac bypass');
        }
    },
    {
        id: 'T1548.001',
        name: 'Abuse Elevation Control Mechanism: Setuid and Setgid',
        description: 'Adversaries may use setuid/setgid to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('chmod +s')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('setuid');
        }
    },
    {
        id: 'T1548.002',
        name: 'Abuse Elevation Control Mechanism: Bypass User Account Control',
        description: 'Adversaries may bypass UAC to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('uac bypass') || 
                    commandLine.toLowerCase().includes('cmstp.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('uac bypass');
        }
    },
    {
        id: 'T1548.003',
        name: 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching',
        description: 'Adversaries may abuse sudo to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sudo')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/sudoers/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('sudo');
        }
    },
    {
        id: 'T1548.004',
        name: 'Abuse Elevation Control Mechanism: Elevated Execution with Prompt',
        description: 'Adversaries may use elevated execution with prompt to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('runas')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('elevated execution');
        }
    },
    {
        id: 'T1548.005',
        name: 'Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access',
        description: 'Adversaries may use temporary elevated cloud access to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cloud access')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud access');
        }
    },
    {
        id: 'T1548.006',
        name: 'Abuse Elevation Control Mechanism: Sudoers File Modification',
        description: 'Adversaries may modify sudoers file to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sudoers')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/sudoers/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('sudoers');
        }
    },
    // T1222 - File and Directory Permissions Modification
    {
        id: 'T1222',
        name: 'File and Directory Permissions Modification',
        description: 'Adversaries may modify file or directory permissions to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1222/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('cacls') || 
                     commandLine.toLowerCase().includes('icacls') || 
                     commandLine.toLowerCase().includes('chmod'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('permissions modification');
        }
    },
    {
        id: 'T1222.001',
        name: 'File and Directory Permissions Modification: Windows File and Directory Permissions Modification',
        description: 'Adversaries may modify Windows file or directory permissions to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1222/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('cacls') || 
                     commandLine.toLowerCase().includes('icacls'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('windows permissions modification');
        }
    },
    {
        id: 'T1222.002',
        name: 'File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification',
        description: 'Adversaries may modify Linux or Mac file permissions to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1222/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('chmod')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('chmod');
        }
    },
    // T1564 - Hide Artifacts
    {
        id: 'T1564',
        name: 'Hide Artifacts',
        description: 'Adversaries may hide artifacts to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1564/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('attrib +h')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('hidden')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('hide artifacts');
        }
    },
    {
        id: 'T1564.001',
        name: 'Hide Artifacts: Hidden Files and Directories',
        description: 'Adversaries may hide files or directories to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1564/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('attrib +h')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/^\./)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('hidden file');
        }
    },
    {
        id: 'T1564.002',
        name: 'Hide Artifacts: Hidden Users',
        description: 'Adversaries may hide user accounts to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1564/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net user') && 
                    commandLine.toLowerCase().includes('hidden')) {
                    return true;
                }
                if (eid === '4720' && event.AccountName?.toLowerCase().includes('$')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('hidden user');
        }
    },
    {
        id: 'T1564.003',
        name: 'Hide Artifacts: Hidden Window',
        description: 'Adversaries may hide windows to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1564/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('hidden window')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('hidden window');
        }
    },
    {
        id: 'T1564.004',
        name: 'Hide Artifacts: NTFS File Attributes',
        description: 'Adversaries may use NTFS attributes to hide files.',
        mitre_link: 'https://attack.mitre.org/techniques/T1564/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('alternate data stream')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes(':')) {
                    return true; // ADS detection
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('ntfs alternate data stream');
        }
    },
    {
        id: 'T1564.005',
        name: 'Hide Artifacts: Hidden File System',
        description: 'Adversaries may use hidden file systems to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1564/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('hidden file system')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('hidden file system');
        }
    },
    {
        id: 'T1564.006',
        name: 'Hide Artifacts: Run Virtual Instance',
        description: 'Adversaries may run virtual instances to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1564/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('virtual instance')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('virtual instance');
        }
    },
    {
        id: 'T1564.008',
        name: 'Hide Artifacts: Email Hiding Rules',
        description: 'Adversaries may use email hiding rules to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1564/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('email rule')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('email hiding rule');
        }
    },
    {
        id: 'T1564.009',
        name: 'Hide Artifacts: Resource Forking',
        description: 'Adversaries may use resource forking to hide artifacts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1564/009/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('resource fork')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('resource fork');
        }
    },
    {
        id: 'T1564.010',
        name: 'Hide Artifacts: Process Argument Spoofing',
        description: 'Adversaries may spoof process arguments to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1564/010/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('argument spoofing')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('argument spoofing');
        }
    },
    {
        id: 'T1564.011',
        name: 'Hide Artifacts: File System Logical Offsets',
        description: 'Adversaries may use file system logical offsets to hide artifacts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1564/011/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('logical offset')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('logical offset');
        }
    },
    {
        id: 'T1564.012',
        name: 'Hide Artifacts: File/Path Exclusions',
        description: 'Adversaries may use file or path exclusions to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1564/012/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('exclusion')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('file exclusion');
        }
    },
    // T1574 - Hijack Execution Flow
    {
        id: 'T1574',
        name: 'Hijack Execution Flow',
        description: 'Adversaries may hijack execution flow to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('dll hijacking')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dll hijacking');
        }
    },
    {
        id: 'T1574.001',
        name: 'Hijack Execution Flow: DLL Search Order Hijacking',
        description: 'Adversaries may use DLL search order hijacking to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('dll hijacking')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dll search order hijacking');
        }
    },
    {
        id: 'T1574.002',
        name: 'Hijack Execution Flow: DLL Side-Loading',
        description: 'Adversaries may use DLL side-loading to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('dll side-loading')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dll side-loading');
        }
    },
    {
        id: 'T1574.004',
        name: 'Hijack Execution Flow: Dylib Hijacking',
        description: 'Adversaries may use dylib hijacking to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('dylib')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dylib/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dylib hijacking');
        }
    },
    {
        id: 'T1574.005',
        name: 'Hijack Execution Flow: Executable Installer',
        description: 'Adversaries may use executable installers to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('executable installer')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('executable installer');
        }
    },
    {
        id: 'T1574.006',
        name: 'Hijack Execution Flow: Dynamic Linker Hijacking',
        description: 'Adversaries may use dynamic linker hijacking to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('ld_preload')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.so/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dynamic linker');
        }
    },
    {
        id: 'T1574.007',
        name: 'Hijack Execution Flow: Path Interception by PATH Environment Variable',
        description: 'Adversaries may manipulate PATH environment variable to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('set path')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('environment\\path')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('path environment');
        }
    },
    {
        id: 'T1574.008',
        name: 'Hijack Execution Flow: Path Interception by Search Order Hijacking',
        description: 'Adversaries may use search order hijacking to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('search order hijacking')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('search order hijacking');
        }
    },
    {
        id: 'T1574.009',
        name: 'Hijack Execution Flow: Path Interception by Unquoted Path',
        description: 'Adversaries may exploit unquoted paths to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/009/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.match(/[^"]\s+\S*\.exe/)) {
                    return true; // Detect unquoted paths
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('unquoted path');
        }
    },
    {
        id: 'T1574.010',
        name: 'Hijack Execution Flow: Services File Permissions Weakness',
        description: 'Adversaries may exploit service file permissions to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/010/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('cacls') || 
                     commandLine.toLowerCase().includes('icacls'))) {
                    return true;
                }
                if (eid === '7045' && event.ServiceName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('service permission');
        }
    },
    {
        id: 'T1574.011',
        name: 'Hijack Execution Flow: Services Registry Permissions Weakness',
        description: 'Adversaries may exploit service registry permissions to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/011/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('reg add') && 
                    commandLine.toLowerCase().includes('services')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('services')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('service registry permission');
        }
    },
    {
        id: 'T1574.012',
        name: 'Hijack Execution Flow: COR_PROFILER',
        description: 'Adversaries may use COR_PROFILER to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/012/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cor_profiler')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('cor_profiler')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cor_profiler');
        }
    },
    {
        id: 'T1574.013',
        name: 'Hijack Execution Flow: KernelCallbackTable',
        description: 'Adversaries may use KernelCallbackTable to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/013/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('kernelcallbacktable')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.sys/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('kernelcallbacktable');
        }
    },
    {
        id: 'T1574.014',
        name: 'Hijack Execution Flow: AppDomainManager',
        description: 'Adversaries may use AppDomainManager to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/014/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('appdomainmanager')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('appdomainmanager')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('appdomainmanager');
        }
    },
    // T1562 - Impair Defenses
    {
        id: 'T1562',
        name: 'Impair Defenses',
        description: 'Adversaries may impair security defenses to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('disable defender')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('impair defenses');
        }
    },
    {
        id: 'T1562.001',
        name: 'Impair Defenses: Disable or Modify Tools',
        description: 'Adversaries may disable or modify security tools to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sc stop') && 
                    commandLine.toLowerCase().includes('defender')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('disable security tool');
        }
    },
    {
        id: 'T1562.002',
        name: 'Impair Defenses: Disable Windows Event Logging',
        description: 'Adversaries may disable Windows event logging to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('wevtutil cl')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('disable event logging');
        }
    },
    {
        id: 'T1562.003',
        name: 'Impair Defenses: Impair Command History Logging',
        description: 'Adversaries may impair command history logging to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('history -c')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('history -c');
        }
    },
    {
        id: 'T1562.004',
        name: 'Impair Defenses: Disable or Modify System Firewall',
        description: 'Adversaries may disable or modify system firewall to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('netsh advfirewall')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('disable firewall');
        }
    },
    {
        id: 'T1562.006',
        name: 'Impair Defenses: Indicator Blocking',
        description: 'Adversaries may block indicators to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('indicator blocking')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('indicator blocking');
        }
    },
    {
        id: 'T1562.007',
        name: 'Impair Defenses: Disable or Modify Cloud Firewall',
        description: 'Adversaries may disable or modify cloud firewalls to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cloud firewall')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud firewall');
        }
    },
    {
        id: 'T1562.008',
        name: 'Impair Defenses: Disable or Modify Cloud Logs',
        description: 'Adversaries may disable or modify cloud logs to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cloud logs')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud logs');
        }
    },
    {
        id: 'T1562.009',
        name: 'Impair Defenses: Safe Mode',
        description: 'Adversaries may use safe mode to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/009/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('bcdedit /set safeboot')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('safe mode');
        }
    },
    {
        id: 'T1562.010',
        name: 'Impair Defenses: Downgrade Attack',
        description: 'Adversaries may downgrade systems to evade defenses.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/010/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('downgrade')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('downgrade attack');
        }
    },
    {
        id: 'T1562.011',
        name: 'Impair Defenses: Spoof Security Alerting',
        description: 'Adversaries may spoof security alerts to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/011/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('spoof alert')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('spoof security alert');
        }
    },
    {
        id: 'T1562.012',
        name: 'Impair Defenses: Disable or Modify Linux Audit System',
        description: 'Adversaries may disable or modify Linux audit systems to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/012/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('auditctl')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('auditctl');
        }
    },
    // T1070 - Indicator Removal
    {
        id: 'T1070',
        name: 'Indicator Removal',
        description: 'Adversaries may remove indicators to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('wevtutil cl')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('indicator removal');
        }
    },
    {
        id: 'T1070.001',
        name: 'Indicator Removal: Clear Windows Event Logs',
        description: 'Adversaries may clear Windows event logs to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('wevtutil cl')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('clear event logs');
        }
    },
    {
        id: 'T1070.002',
        name: 'Indicator Removal: Clear Linux or Mac System Logs',
        description: 'Adversaries may clear Linux or Mac system logs to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('rm /var/log')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('clear system logs');
        }
    },
    {
        id: 'T1070.003',
        name: 'Indicator Removal: Clear Command History',
        description: 'Adversaries may clear command history to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('history -c')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('clear command history');
        }
    },
    {
        id: 'T1070.004',
        name: 'Indicator Removal: File Deletion',
        description: 'Adversaries may delete files to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('del ') || 
                    commandLine.toLowerCase().includes('rm ')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('file deletion');
        }
    },
    {
        id: 'T1070.005',
        name: 'Indicator Removal: Network Share Connection Removal',
        description: 'Adversaries may remove network share connections to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net use * /delete')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network share removal');
        }
    },
    {
        id: 'T1070.006',
        name: 'Indicator Removal: Timestomp',
        description: 'Adversaries may modify timestamps to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('timestomp')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('timestomp');
        }
    },
    {
        id: 'T1070.007',
        name: 'Indicator Removal: Clear Network Connection History and Configurations',
        description: 'Adversaries may clear network connection history to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('netsh wlan delete')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('clear network history');
        }
    },
    {
        id: 'T1070.008',
        name: 'Indicator Removal: Clear Mailbox Data',
        description: 'Adversaries may clear mailbox data to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('clear mailbox')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('clear mailbox');
        }
    },
   {
        id: 'T1070.009',
        name: 'Indicator Removal: Clear Persistence',
        description: 'Adversaries may clear persistence mechanisms to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/009/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('reg delete') && 
                    commandLine.toLowerCase().includes('run')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('run')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('clear persistence');
        }
    },
    // T1036 - Masquerading
    {
        id: 'T1036',
        name: 'Masquerading',
        description: 'Adversaries may masquerade processes or files to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1036/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('notepad.exe') && 
                    commandLine.toLowerCase().includes('malicious')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/notepad\.exe/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('masquerading');
        }
    },
    {
        id: 'T1036.001',
        name: 'Masquerading: Invalid Code Signature',
        description: 'Adversaries may use invalid code signatures to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1036/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('invalid signature')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('invalid code signature');
        }
    },
    {
        id: 'T1036.002',
        name: 'Masquerading: Right-to-Left Override',
        description: 'Adversaries may use right-to-left override to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1036/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.match(/[\u202E]/)) {
                    return true; // Right-to-left override character
                }
                if (eid === '11' && event.TargetFilename?.match(/[\u202E]/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('right-to-left override');
        }
    },
    {
        id: 'T1036.003',
        name: 'Masquerading: Rename System Utilities',
        description: 'Adversaries may rename system utilities to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1036/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('rename') && 
                    commandLine.toLowerCase().match(/cmd\.exe|powershell\.exe/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('rename system utility');
        }
    },
    {
        id: 'T1036.004',
        name: 'Masquerading: Masquerade Task or Service',
        description: 'Adversaries may masquerade tasks or services to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1036/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4698' && event.TaskName?.toLowerCase().includes('svchost')) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('masquerade task')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('masquerade task');
        }
    },
    {
        id: 'T1036.005',
        name: 'Masquerading: Match Legitimate Name or Location',
        description: 'Adversaries may match legitimate names or locations to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1036/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().match(/svchost\.exe|explorer\.exe/) && 
                    commandLine.toLowerCase().includes('malicious')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('match legitimate name');
        }
    },
    {
        id: 'T1036.006',
        name: 'Masquerading: Space after Filename',
        description: 'Adversaries may add spaces after filenames to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1036/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.match(/\.exe\s+$/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('space after filename');
        }
    },
    {
        id: 'T1036.007',
        name: 'Masquerading: Double File Extension',
        description: 'Adversaries may use double file extensions to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1036/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.match(/\.\w+\.exe$/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.match(/\.\w+\.exe$/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('double file extension');
        }
    },
    {
        id: 'T1036.008',
        name: 'Masquerading: Masquerade File Type',
        description: 'Adversaries may masquerade file types to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1036/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.match(/\.txt\.exe$/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('masquerade file type');
        }
    },
    {
        id: 'T1036.009',
        name: 'Masquerading: Binary Padding',
        description: 'Adversaries may use binary padding to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1036/009/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('binary padding')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('binary padding');
        }
    },
    // T1556 - Modify Authentication Process
    {
        id: 'T1556',
        name: 'Modify Authentication Process',
        description: 'Adversaries may modify authentication processes to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('authentication process')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('sam')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('modify authentication');
        }
    },
    {
        id: 'T1556.001',
        name: 'Modify Authentication Process: Domain Controller Authentication',
        description: 'Adversaries may modify domain controller authentication to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('domain controller')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain controller authentication');
        }
    },
    {
        id: 'T1556.002',
        name: 'Modify Authentication Process: Password Filter DLL',
        description: 'Adversaries may use password filter DLLs to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('password filter')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('passwordfilter')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('password filter dll');
        }
    },
    {
        id: 'T1556.003',
        name: 'Modify Authentication Process: Pluggable Authentication Modules',
        description: 'Adversaries may modify PAM to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('pam.d')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/pam\.d/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('pluggable authentication');
        }
    },
    {
        id: 'T1556.004',
        name: 'Modify Authentication Process: Network Device Authentication',
        description: 'Adversaries may modify network device authentication to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('network device auth')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network device authentication');
        }
    },
    {
        id: 'T1556.005',
        name: 'Modify Authentication Process: Reversible Encryption',
        description: 'Adversaries may enable reversible encryption to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('reversible encryption')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('reversible encryption');
        }
    },
    {
        id: 'T1556.006',
        name: 'Modify Authentication Process: Multi-Factor Authentication',
        description: 'Adversaries may modify MFA to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('mfa')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('multi-factor authentication');
        }
    },
    {
        id: 'T1556.007',
        name: 'Modify Authentication Process: Hybrid Identity',
        description: 'Adversaries may modify hybrid identity to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('hybrid identity')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('hybrid identity');
        }
    },
    {
        id: 'T1556.008',
        name: 'Modify Authentication Process: Cloud Authentication Modification',
        description: 'Adversaries may modify cloud authentication to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cloud authentication')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud authentication');
        }
    },
    // T1578 - Modify Cloud Compute Infrastructure
    {
        id: 'T1578',
        name: 'Modify Cloud Compute Infrastructure',
        description: 'Adversaries may modify cloud compute infrastructure to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1578/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cloud compute')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud compute');
        }
    },
    {
        id: 'T1578.001',
        name: 'Modify Cloud Compute Infrastructure: Create Snapshot',
        description: 'Adversaries may create cloud snapshots to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1578/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('create snapshot')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('create snapshot');
        }
    },
    {
        id: 'T1578.002',
        name: 'Modify Cloud Compute Infrastructure: Create Cloud Instance',
        description: 'Adversaries may create cloud instances to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1578/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('create instance')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('create cloud instance');
        }
    },
    {
        id: 'T1578.003',
        name: 'Modify Cloud Compute Infrastructure: Delete Cloud Instance',
        description: 'Adversaries may delete cloud instances to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1578/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('delete instance')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('delete cloud instance');
        }
    },
    {
        id: 'T1578.004',
        name: 'Modify Cloud Compute Infrastructure: Revert Cloud Instance',
        description: 'Adversaries may revert cloud instances to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1578/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('revert instance')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('revert cloud instance');
        }
    },
    {
        id: 'T1578.005',
        name: 'Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations',
        description: 'Adversaries may modify cloud compute configurations to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1578/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('modify cloud config')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('modify cloud config');
        }
    },
    // T1600 - Weaken Encryption
    {
        id: 'T1600',
        name: 'Weaken Encryption',
        description: 'Adversaries may weaken encryption to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1600/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('weaken encryption')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('weaken encryption');
        }
    },
    {
        id: 'T1600.001',
        name: 'Weaken Encryption: Reduce Key Space',
        description: 'Adversaries may reduce encryption key space to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1600/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('reduce key space')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('reduce key space');
        }
    },
    {
        id: 'T1600.002',
        name: 'Weaken Encryption: Disable Crypto Hardware',
        description: 'Adversaries may disable crypto hardware to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1600/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('disable crypto hardware')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('disable crypto hardware');
        }
    },
    // T1027 - Obfuscated Files or Information
    {
        id: 'T1027',
        name: 'Obfuscated Files or Information',
        description: 'Adversaries may obfuscate files or information to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('base64') || 
                    commandLine.toLowerCase().includes('obfuscate')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('obfuscated file');
        }
    },
    {
        id: 'T1027.001',
        name: 'Obfuscated Files or Information: Binary Padding',
        description: 'Adversaries may use binary padding to obfuscate files and evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('binary padding')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('binary padding');
        }
    },
    {
        id: 'T1027.002',
        name: 'Obfuscated Files or Information: Software Packing',
        description: 'Adversaries may use software packing to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('upx') || 
                    commandLine.toLowerCase().includes('packer')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('software packing');
        }
    },
    {
        id: 'T1027.003',
        name: 'Obfuscated Files or Information: Steganography',
        description: 'Adversaries may use steganography to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('steganography')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('steganography');
        }
    },
    {
        id: 'T1027.004',
        name: 'Obfuscated Files or Information: Compile After Delivery',
        description: 'Adversaries may compile code after delivery to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('gcc') || 
                    commandLine.toLowerCase().includes('compile')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('compile after delivery');
        }
    },
    {
        id: 'T1027.005',
        name: 'Obfuscated Files or Information: Indicator Removal from Tools',
        description: 'Adversaries may remove indicators from tools to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('indicator removal')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('indicator removal from tools');
        }
    },
    {
        id: 'T1027.006',
        name: 'Obfuscated Files or Information: HTML Smuggling',
        description: 'Adversaries may use HTML smuggling to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('html smuggling')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('html smuggling');
        }
    },
    {
        id: 'T1027.007',
        name: 'Obfuscated Files or Information: Dynamic API Resolution',
        description: 'Adversaries may use dynamic API resolution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('dynamic api')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dynamic api resolution');
        }
    },
    {
        id: 'T1027.008',
        name: 'Obfuscated Files or Information: Stripped Payloads',
        description: 'Adversaries may use stripped payloads to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('stripped payload')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('stripped payload');
        }
    },
    {
        id: 'T1027.009',
        name: 'Obfuscated Files or Information: Embedded Payloads',
        description: 'Adversaries may use embedded payloads to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/009/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('embedded payload')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('embedded payload');
        }
    },
    {
        id: 'T1027.010',
        name: 'Obfuscated Files or Information: Command Obfuscation',
        description: 'Adversaries may use command obfuscation to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/010/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.match(/cmd\s*\/c\s*".*?"/)) {
                    return true; // Obfuscated command line
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('command obfuscation');
        }
    },
    {
        id: 'T1027.011',
        name: 'Obfuscated Files or Information: Fileless Storage',
        description: 'Adversaries may use fileless storage to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/011/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('fileless')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('fileless storage');
        }
    },
    {
        id: 'T1027.012',
        name: 'Obfuscated Files or Information: LNK Icon Smuggling',
        description: 'Adversaries may use LNK icon smuggling to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/012/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('lnk icon')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.lnk/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('lnk icon smuggling');
        }
    },
    {
        id: 'T1027.013',
        name: 'Obfuscated Files or Information: Encrypted/Encoded File',
        description: 'Adversaries may use encrypted or encoded files to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1027/013/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('base64') || 
                    commandLine.toLowerCase().includes('encoded file')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('encoded file');
        }
    },
    // T1055 - Process Injection
    {
        id: 'T1055',
        name: 'Process Injection',
        description: 'Adversaries may inject code into processes to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1055/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('writeprocessmemory')) {
                    return true;
                }
                if (eid === '8' && event.TargetProcessName) {
                    return true; // CreateRemoteThread
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('process injection');
        }
    },
    {
        id: 'T1055.001',
        name: 'Process Injection: Dynamic-link Library Injection',
        description: 'Adversaries may inject DLLs into processes to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1055/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('loaddll')) {
                    return true;
                }
                if (eid === '8' && event.TargetProcessName && event.CallTrace?.toLowerCase().includes('loaddll')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dll injection');
        }
    },
    {
        id: 'T1055.002',
        name: 'Process Injection: Portable Executable Injection',
        description: 'Adversaries may inject PEs into processes to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1055/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('pe injection')) {
                    return true;
                }
                if (eid === '8' && event.TargetProcessName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('pe injection');
        }
    },
    {
        id: 'T1055.003',
        name: 'Process Injection: Thread Execution Hijacking',
        description: 'Adversaries may hijack thread execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1055/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('thread hijacking')) {
                    return true;
                }
                if (eid === '8' && event.TargetProcessName && event.CallTrace?.toLowerCase().includes('setthreadcontext')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('thread hijacking');
        }
    },
    {
        id: 'T1055.004',
        name: 'Process Injection: Asynchronous Procedure Call',
        description: 'Adversaries may use APC injection to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1055/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('queueuserapc')) {
                    return true;
                }
                if (eid === '8' && event.TargetProcessName && event.CallTrace?.toLowerCase().includes('queueuserapc')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('apc injection');
        }
    },
    {
        id: 'T1055.005',
        name: 'Process Injection: Thread Local Storage',
        description: 'Adversaries may use TLS callbacks to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1055/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('tls callback')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('tls callback');
        }
    },
    {
        id: 'T1055.008',
        name: 'Process Injection: Ptrace System Calls',
        description: 'Adversaries may use ptrace to inject code and evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1055/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('ptrace')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('ptrace');
        }
    },
    {
        id: 'T1055.009',
        name: 'Process Injection: Proc Memory',
        description: 'Adversaries may inject code via /proc memory to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1055/009/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('/proc')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('proc memory');
        }
    },
    {
        id: 'T1055.011',
        name: 'Process Injection: Extra Window Memory Injection',
        description: 'Adversaries may use extra window memory injection to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1055/011/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('setwindowlong')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('extra window memory');
        }
    },
    {
        id: 'T1055.012',
        name: 'Process Injection: Process Hollowing',
        description: 'Adversaries may use process hollowing to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1055/012/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('process hollowing')) {
                    return true;
                }
                if (eid === '8' && event.TargetProcessName && event.CallTrace?.toLowerCase().includes('createremotethread')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('process hollowing');
        }
    },
    {
        id: 'T1055.013',
        name: 'Process Injection: Process Doppelgänging',
        description: 'Adversaries may use process doppelgänging to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1055/013/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('doppelganging')) {
                    return true;
                }
                if (eid === '8' && event.TargetProcessName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('doppelganging');
        }
    },
    {
        id: 'T1055.014',
        name: 'Process Injection: VDSO Hijacking',
        description: 'Adversaries may use VDSO hijacking to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1055/014/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('vdso')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('vdso hijacking');
        }
    },
    {
        id: 'T1055.015',
        name: 'Process Injection: ListPlanting',
        description: 'Adversaries may use ListPlanting to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1055/015/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('listplanting')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('listplanting');
        }
    },
    // T1620 - Reflective Code Loading
    {
        id: 'T1620',
        name: 'Reflective Code Loading',
        description: 'Adversaries may use reflective code loading to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1620/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('reflective code')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('reflective code loading');
        }
    },
    // T1014 - Rootkit
    {
        id: 'T1014',
        name: 'Rootkit',
        description: 'Adversaries may use rootkits to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1014/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('rootkit')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.sys/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('rootkit');
        }
    },
    // T1218 - System Binary Proxy Execution
    {
        id: 'T1218',
        name: 'System Binary Proxy Execution',
        description: 'Adversaries may abuse system binaries for proxy execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1218/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().match(/rundll32\.exe|msiexec\.exe|regsvr32\.exe/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system binary proxy');
        }
    },
    {
        id: 'T1218.001',
        name: 'System Binary Proxy Execution: Compiled HTML File',
        description: 'Adversaries may use compiled HTML files for proxy execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1218/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('hh.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('compiled html');
        }
    },
    {
        id: 'T1218.002',
        name: 'System Binary Proxy Execution: Control Panel',
        description: 'Adversaries may use control panel items for proxy execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1218/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('control.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('control panel');
        }
    },
    {
        id: 'T1218.003',
        name: 'System Binary Proxy Execution: CMSTP',
        description: 'Adversaries may use CMSTP for proxy execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1218/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('cmstp.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cmstp');
        }
    },
    {
        id: 'T1218.004',
        name: 'System Binary Proxy Execution: InstallUtil',
        description: 'Adversaries may use InstallUtil for proxy execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1218/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('installutil.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('installutil');
        }
    },
    {
        id: 'T1218.005',
        name: 'System Binary Proxy Execution: Mshta',
        description: 'Adversaries may use Mshta for proxy execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1218/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('mshta.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('mshta');
        }
    },
    {
        id: 'T1218.007',
        name: 'System Binary Proxy Execution: Msiexec',
        description: 'Adversaries may use Msiexec for proxy execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1218/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('msiexec.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('msiexec');
        }
    },
    {
        id: 'T1218.008',
        name: 'System Binary Proxy Execution: Odbcconf',
        description: 'Adversaries may use Odbcconf for proxy execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1218/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('odbcconf.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('odbcconf');
        }
    },
    {
        id: 'T1218.009',
        name: 'System Binary Proxy Execution: Regsvcs/Regasm',
        description: 'Adversaries may use Regsvcs or Regasm for proxy execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1218/009/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().match(/regsvcs\.exe|regasm\.exe/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('regsvcs');
        }
    },
    {
        id: 'T1218.010',
        name: 'System Binary Proxy Execution: Regsvr32',
        description: 'Adversaries may use Regsvr32 for proxy execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1218/010/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('regsvr32.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('regsvr32');
        }
    },
	{
        id: 'T1218.011',
        name: 'System Binary Proxy Execution: Rundll32',
        description: 'Adversaries may use Rundll32 for proxy execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1218/011/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('rundll32.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('rundll32');
        }
    },
    {
        id: 'T1218.012',
        name: 'System Binary Proxy Execution: Verclsid',
        description: 'Adversaries may use Verclsid for proxy execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1218/012/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('verclsid.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('verclsid');
        }
    },
    {
        id: 'T1218.013',
        name: 'System Binary Proxy Execution: Mavinject',
        description: 'Adversaries may use Mavinject for proxy execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1218/013/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('mavinject.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('mavinject');
        }
    },
    {
        id: 'T1218.014',
        name: 'System Binary Proxy Execution: MMC',
        description: 'Adversaries may use MMC for proxy execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1218/014/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('mmc.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('mmc');
        }
    },
    // T1216 - System Script Proxy Execution
    {
        id: 'T1216',
        name: 'System Script Proxy Execution',
        description: 'Adversaries may use scripts for proxy execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1216/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().match(/pubprn\.vbs|syncappvpublishingserver\.vbs/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('script proxy');
        }
    },
    {
        id: 'T1216.001',
        name: 'System Script Proxy Execution: PubPrn',
        description: 'Adversaries may use PubPrn for script proxy execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1216/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('pubprn.vbs')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('pubprn');
        }
    },
    {
        id: 'T1216.002',
        name: 'System Script Proxy Execution: SyncAppvPublishingServer',
        description: 'Adversaries may use SyncAppvPublishingServer for script proxy execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1216/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('syncappvpublishingserver.vbs')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('syncappvpublishingserver');
        }
    },
    // T1553 - Subvert Trust Controls
    {
        id: 'T1553',
        name: 'Subvert Trust Controls',
        description: 'Adversaries may subvert trust controls to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1553/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('codesign')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('certificates')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('subvert trust');
        }
    },
    {
        id: 'T1553.001',
        name: 'Subvert Trust Controls: Gatekeeper Bypass',
        description: 'Adversaries may bypass Gatekeeper to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1553/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('spctl') && 
                    commandLine.toLowerCase().includes('disable')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('gatekeeper bypass');
        }
    },
    {
        id: 'T1553.002',
        name: 'Subvert Trust Controls: Code Signing',
        description: 'Adversaries may abuse code signing to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1553/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('codesign')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('code signing');
        }
    },
    {
        id: 'T1553.003',
        name: 'Subvert Trust Controls: SIP and Trust Provider Hijacking',
        description: 'Adversaries may hijack SIP or trust providers to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1553/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sip hijack')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('sip hijacking');
        }
    },
    {
        id: 'T1553.004',
        name: 'Subvert Trust Controls: Install Root Certificate',
        description: 'Adversaries may install root certificates to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1553/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('certutil') && 
                    commandLine.toLowerCase().includes('addstore')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('certificates')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('install root certificate');
        }
    },
    {
        id: 'T1553.005',
        name: 'Subvert Trust Controls: Mark-of-the-Web Bypass',
        description: 'Adversaries may bypass Mark-of-the-Web to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1553/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('mark-of-the-web')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('zone.identifier')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('mark-of-the-web');
        }
    },
    {
        id: 'T1553.006',
        name: 'Subvert Trust Controls: Code Signing Policy Modification',
        description: 'Adversaries may modify code signing policies to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1553/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('code signing policy')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('code signing policy');
        }
    },
    // T1497 - Virtualization/Sandbox Evasion
    {
        id: 'T1497',
        name: 'Virtualization/Sandbox Evasion',
        description: 'Adversaries may evade virtualization or sandbox environments.',
        mitre_link: 'https://attack.mitre.org/techniques/T1497/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('virtualization') || 
                    commandLine.toLowerCase().includes('sandbox')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('virtualization evasion');
        }
    },
    {
        id: 'T1497.001',
        name: 'Virtualization/Sandbox Evasion: System Checks',
        description: 'Adversaries may use system checks to evade virtualization detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1497/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cpuid') || 
                    commandLine.toLowerCase().includes('vmware')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system checks');
        }
    },
    {
        id: 'T1497.002',
        name: 'Virtualization/Sandbox Evasion: User Activity Based Checks',
        description: 'Adversaries may use user activity checks to evade virtualization detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1497/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('user activity')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('user activity based checks');
        }
    },
    {
        id: 'T1497.003',
        name: 'Virtualization/Sandbox Evasion: Time Based Evasion',
        description: 'Adversaries may use time-based evasion to avoid detection in virtualized environments.',
        mitre_link: 'https://attack.mitre.org/techniques/T1497/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sleep') || 
                    commandLine.toLowerCase().includes('delay')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('time based evasion');
        }
    },
    // T1220 - XSL Script Processing
    {
        id: 'T1220',
        name: 'XSL Script Processing',
        description: 'Adversaries may use XSL scripts to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1220/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('xsl')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.xsl$/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('xsl script');
        }
    },
    // T1078 - Valid Accounts
    {
        id: 'T1078',
        name: 'Valid Accounts',
        description: 'Adversaries may use valid accounts to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && 
                    event.TargetUserName?.toLowerCase().includes('administrator')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('valid account');
        }
    },
    {
        id: 'T1078.001',
        name: 'Valid Accounts: Default Accounts',
        description: 'Adversaries may use default accounts to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && 
                    event.TargetUserName?.toLowerCase().includes('guest')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('default account');
        }
    },
    {
        id: 'T1078.002',
        name: 'Valid Accounts: Domain Accounts',
        description: 'Adversaries may use domain accounts to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && 
                    event.TargetDomainName && !event.TargetDomainName.toLowerCase().includes('local')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain account');
        }
    },
    {
        id: 'T1078.003',
        name: 'Valid Accounts: Local Accounts',
        description: 'Adversaries may use local accounts to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && 
                    event.TargetDomainName?.toLowerCase().includes('local')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('local account');
        }
    },
    {
        id: 'T1078.004',
        name: 'Valid Accounts: Cloud Accounts',
        description: 'Adversaries may use cloud accounts to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud account');
        }
    },
    // T1601 - Modify System Image
    {
        id: 'T1601',
        name: 'Modify System Image',
        description: 'Adversaries may modify system images to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1601/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('system image')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('modify system image');
        }
    },
    {
        id: 'T1601.001',
        name: 'Modify System Image: Patch System Image',
        description: 'Adversaries may patch system images to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1601/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('patch system')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('patch system image');
        }
    },
    {
        id: 'T1601.002',
        name: 'Modify System Image: Downgrade System Image',
        description: 'Adversaries may downgrade system images to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1601/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('downgrade system')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('downgrade system image');
        }
    },
    // T1599 - Network Boundary Bridging
    {
        id: 'T1599',
        name: 'Network Boundary Bridging',
        description: 'Adversaries may bridge network boundaries to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1599/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('network bridge')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().includes('proxy')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network boundary');
        }
    },
    {
        id: 'T1599.001',
        name: 'Network Boundary Bridging: Network Address Translation Traversal',
        description: 'Adversaries may use NAT traversal to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1599/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('nat traversal')) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/3478|5060/)) { // Common NAT traversal ports
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('nat traversal');
        }
    },
    // T1610 - Deploy Container
    {
        id: 'T1610',
        name: 'Deploy Container',
        description: 'Adversaries may deploy containers to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1610/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('docker') || 
                    commandLine.toLowerCase().includes('kubectl')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('deploy container');
        }
    },
    // T1202 - Indirect Command Execution
    {
        id: 'T1202',
        name: 'Indirect Command Execution',
        description: 'Adversaries may use indirect command execution to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1202/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('pcalua') || 
                    commandLine.toLowerCase().includes('forfiles')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('indirect command');
        }
    },
    // T1647 - Plist File Modification
    {
        id: 'T1647',
        name: 'Plist File Modification',
        description: 'Adversaries may modify plist files to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1647/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('defaults write') && 
                    commandLine.toLowerCase().includes('.plist')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.plist$/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('plist modification');
        }
    },
    // T1221 - Template Injection
    {
        id: 'T1221',
        name: 'Template Injection',
        description: 'Adversaries may use template injection to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1221/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('template injection')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dotm|\.xltm/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('template injection');
        }
    },
    // T1535 - Unused/Unsupported Cloud Regions
    {
        id: 'T1535',
        name: 'Unused/Unsupported Cloud Regions',
        description: 'Adversaries may use unused or unsupported cloud regions to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1535/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws\.amazon\.com|azure\.com/) && 
                    commandLine.toLowerCase().includes('region')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('unused cloud region');
        }
    }
];
