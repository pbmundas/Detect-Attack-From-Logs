const rules = [
            {
                id: 'T1059',
                name: 'Command and Scripting Interpreter',
                description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
                mitre_link: 'https://attack.mitre.org/techniques/T1059/',
                detection: (event) => {
                    const eid = event.EventID || event.EventId || '';
                    const image = event.Image || event.NewProcessName || event.TargetUserName || '';
                    const commandLine = event.CommandLine || event.Message || '';
                    if (eid === '4688' || eid === '1') {
                        return image.toLowerCase().includes('cmd.exe') ||
                               image.toLowerCase().includes('powershell.exe') ||
                               commandLine.toLowerCase().includes('cmd.exe') ||
                               commandLine.toLowerCase().includes('powershell.exe');
                    }
                    return typeof event === 'string' && 
                        (event.toLowerCase().includes('cmd') || event.toLowerCase().includes('powershell'));
                }
            },
            {
                id: 'T1078',
                name: 'Valid Accounts',
                description: 'Adversaries may obtain and abuse credentials of existing accounts.',
                mitre_link: 'https://attack.mitre.org/techniques/T1078/',
                detection: (event) => {
                    const eid = event.EventID || event.EventId || '';
                    const logonType = event.LogonType || '';
                    const message = event.Message || '';
                    if (typeof event === 'object') {
                        return (eid === '4624' && (logonType === '3' || message?.includes('Logon Type: 3'))) ||
                               (eid === '4625' && message?.toLowerCase().includes('failed'));
                    }
                    return typeof event === 'string' && 
                        event.toLowerCase().includes('logon') && event.toLowerCase().includes('failed');
                }
            },
            {
                id: 'T1566',
                name: 'Phishing',
                description: 'Adversaries may send phishing messages to gain access to systems.',
                mitre_link: 'https://attack.mitre.org/techniques/T1566/',
                detection: (event) => {
                    const eid = event.EventID || event.EventId || '';
                    const message = event.Message || '';
                    if (typeof event === 'object') {
                        return eid === '1116' && message?.toLowerCase().includes('trojan');
                    }
                    return typeof event === 'string' && event.toLowerCase().includes('trojan');
                }
            },
            {
                id: 'T1053',
                name: 'Scheduled Task/Job',
                description: 'Adversaries may abuse task scheduling to execute malicious code.',
                mitre_link: 'https://attack.mitre.org/techniques/T1053/',
                detection: (event) => {
                    const eid = event.EventID || event.EventId || '';
                    const message = event.Message || '';
                    if (typeof event === 'object') {
                        return eid === '4698' && message?.toLowerCase().includes('scheduled task');
                    }
                    return typeof event === 'string' && event.toLowerCase().includes('scheduled task');
                }
            },
            {
                id: 'T1074',
                name: 'Data Staged',
                description: 'Adversaries may clear logs to hide their activities.',
                mitre_link: 'https://attack.mitre.org/techniques/T1074/',
                detection: (event) => {
                    const eid = event.EventID || event.EventId || '';
                    const message = event.Message || '';
                    if (typeof event === 'object') {
                        return eid === '1102' && message?.toLowerCase().includes('audit log');
                    }
                    return typeof event === 'string' && event.toLowerCase().includes('audit log');
                }
            },
            {
                id: 'T1071',
                name: 'Application Layer Protocol',
                description: 'Adversaries may communicate using application layer protocols to avoid detection.',
                mitre_link: 'https://attack.mitre.org/techniques/T1071/',
                detection: (event) => {
                    const eid = event.EventID || event.EventId || '';
                    const message = event.Message || '';
                    if (typeof event === 'object') {
                        return eid === '3' && message?.toLowerCase().includes('network connection');
                    }
                    return typeof event === 'string' && event.toLowerCase().includes('network connection');
                }
            },
            {
                id: 'T1068',
                name: 'Exploitation for Privilege Escalation',
                description: 'Adversaries may exploit software vulnerabilities to escalate privileges.',
                mitre_link: 'https://attack.mitre.org/techniques/T1068/',
                detection: (event) => {
                    const eid = event.EventID || event.EventId || '';
                    const message = event.Message || '';
                    if (typeof event === 'object') {
                        return eid === '4672' && message?.toLowerCase().includes('privilege');
                    }
                    return typeof event === 'string' && event.toLowerCase().includes('privilege');
                }
            },
            // New rules added based on analysis of PanacheSysmon_vs_AtomicRedTeam01.xml
            {
                id: 'T1543.003',
                name: 'Create or Modify System Process: Windows Service',
                description: 'Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence.',
                mitre_link: 'https://attack.mitre.org/techniques/T1543/003/',
                detection: (event) => {
                    const eid = event.EventID || event.EventId || '';
                    const image = event.Image || event.NewProcessName || event.TargetUserName || '';
                    const commandLine = event.CommandLine || event.Message || '';
                    const targetObject = event.TargetObject || '';
                    if (typeof event === 'object') {
                        if ((eid === '1' || eid === '4688') && image.toLowerCase().includes('sc.exe') && commandLine.toLowerCase().includes('create') && commandLine.toLowerCase().includes('binpath')) {
                            return true;
                        }
                        if (eid === '13' && targetObject?.toLowerCase().includes('\\services\\') && (targetObject?.toLowerCase().includes('\\start') || targetObject?.toLowerCase().includes('\\imagepath'))) {
                            return true;
                        }
                    }
                    return typeof event === 'string' && event.toLowerCase().includes('sc create') && event.toLowerCase().includes('binpath');
                }
            },
            {
                id: 'T1003.003',
                name: 'OS Credential Dumping: NTDS',
                description: 'Adversaries may attempt to access or create a copy of the Active Directory domain database to steal credential information.',
                mitre_link: 'https://attack.mitre.org/techniques/T1003/003/',
                detection: (event) => {
                    const eid = event.EventID || event.EventId || '';
                    const image = event.Image || event.NewProcessName || event.TargetUserName || '';
                    const commandLine = event.CommandLine || event.Message || '';
                    if (typeof event === 'object') {
                        if ((eid === '1' || eid === '4688') && image.toLowerCase().includes('vssadmin.exe') && commandLine.toLowerCase().includes('create shadow')) {
                            return true;
                        }
                        if ((eid === '1' || eid === '4688') && commandLine.toLowerCase().includes('copy') && commandLine.toLowerCase().includes('harddiskvolumeshadowcopy') && commandLine.toLowerCase().includes('ntds.dit')) {
                            return true;
                        }
                    }
                    return typeof event === 'string' && (event.toLowerCase().includes('vssadmin create shadow') || event.toLowerCase().includes('copy ntds.dit'));
                }
            },
            {
                id: 'T1003.002',
                name: 'OS Credential Dumping: Security Account Manager',
                description: 'Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored.',
                mitre_link: 'https://attack.mitre.org/techniques/T1003/002/',
                detection: (event) => {
                    const eid = event.EventID || event.EventId || '';
                    const image = event.Image || event.NewProcessName || event.TargetUserName || '';
                    const commandLine = event.CommandLine || event.Message || '';
                    if (typeof event === 'object') {
                        if ((eid === '1' || eid === '4688') && image.toLowerCase().includes('reg.exe') && commandLine.toLowerCase().includes('save hklm\\system')) {
                            return true;
                        }
                        if ((eid === '1' || eid === '4688') && commandLine.toLowerCase().includes('copy') && commandLine.toLowerCase().includes('harddiskvolumeshadowcopy') && commandLine.toLowerCase().includes('config\\system')) {
                            return true;
                        }
                    }
                    return typeof event === 'string' && event.toLowerCase().includes('reg save hklm\\system');
                }
            }
            // Add custom rules here for additional MITRE techniques
            // For example:
            // {
            //     id: 'TXXXX',
            //     name: 'Technique Name',
            //     description: 'Description of the technique.',
            //     mitre_link: 'https://attack.mitre.org/techniques/TXXXX/',
            //     detection: (event) => {
            //         // Custom detection logic based on event fields like EventID, Image, CommandLine, TargetObject, etc.
            //         const eid = event.EventID || event.EventId || '';
            //         if (typeof event === 'object') {
            //             // Structured log detection for both Sysmon (EventID '1') and Security (e.g., '4688')
            //             if (eid === '1' || eid === '4688') {
            //                 const image = event.Image || event.NewProcessName || event.TargetUserName || '';
            //                 return image.toLowerCase().includes('keyword');
            //             }
            //         }
            //         // Plain text log detection
            //         return typeof event === 'string' && event.toLowerCase().includes('keyword');
            //     }
            // }
        ];