const rules = [
    // T1210 - Exploitation of Remote Services
    {
        id: 'T1210',
        name: 'Exploitation of Remote Services',
        description: 'Adversaries may exploit remote services to move laterally.',
        mitre_link: 'https://attack.mitre.org/techniques/T1210/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/psexec|msfvenom|exploit/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/445|3389|5985/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('remote service exploitation');
        }
    },
    // T1563 - Remote Service Session Hijacking
    {
        id: 'T1563',
        name: 'Remote Service Session Hijacking',
        description: 'Adversaries may hijack remote service sessions for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1563/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('session hijacking')) {
                    return true;
                }
                if (eid === '4624' && event.LogonType?.toString() === '10') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('session hijacking');
        }
    },
    {
        id: 'T1563.001',
        name: 'Remote Service Session Hijacking: SSH Hijacking',
        description: 'Adversaries may hijack SSH sessions for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1563/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/ssh.*-R/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '22') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('ssh hijacking');
        }
    },
    {
        id: 'T1563.002',
        name: 'Remote Service Session Hijacking: RDP Hijacking',
        description: 'Adversaries may hijack RDP sessions for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1563/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/tscon|mstsc/)) {
                    return true;
                }
                if (eid === '4624' && event.LogonType?.toString() === '10' && 
                    event.AuthenticationPackageName?.toLowerCase().includes('rdp')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('rdp hijacking');
        }
    },
    // T1021 - Remote Services
    {
        id: 'T1021',
        name: 'Remote Services',
        description: 'Adversaries may use remote services for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1021/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/psexec|mstsc|winrm/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/3389|445|5985/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('remote services');
        }
    },
    {
        id: 'T1021.001',
        name: 'Remote Services: Remote Desktop Protocol',
        description: 'Adversaries may use RDP for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1021/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/mstsc|rdp/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '3389') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('remote desktop protocol');
        }
    },
    {
        id: 'T1021.002',
        name: 'Remote Services: SMB/Windows Admin Shares',
        description: 'Adversaries may use SMB or Windows Admin Shares for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1021/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/net use|smbclient/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '445') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('smb share');
        }
    },
    {
        id: 'T1021.003',
        name: 'Remote Services: Distributed Component Object Model',
        description: 'Adversaries may use DCOM for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1021/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('dcom')) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '135') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dcom');
        }
    },
    {
        id: 'T1021.004',
        name: 'Remote Services: SSH',
        description: 'Adversaries may use SSH for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1021/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('ssh ')) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '22') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('ssh');
        }
    },
    {
        id: 'T1021.005',
        name: 'Remote Services: VNC',
        description: 'Adversaries may use VNC for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1021/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/vncviewer|tightvnc/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '5900') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('vnc');
        }
    },
    {
        id: 'T1021.006',
        name: 'Remote Services: Windows Remote Management',
        description: 'Adversaries may use WinRM for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1021/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/winrm|wsmprovhost/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '5985') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('winrm');
        }
    },
    // T1550 - Use Alternate Authentication Material
    {
        id: 'T1550',
        name: 'Use Alternate Authentication Material',
        description: 'Adversaries may use alternate authentication material for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1550/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/mimikatz|pth-winexe/)) {
                    return true;
                }
                if (eid === '4624' && event.AuthenticationPackageName?.toLowerCase().includes('ntlm')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('alternate authentication');
        }
    },
    {
        id: 'T1550.001',
        name: 'Use Alternate Authentication Material: Application Access Token',
        description: 'Adversaries may use application access tokens for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1550/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws sts|az login/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('application access token');
        }
    },
    {
        id: 'T1550.002',
        name: 'Use Alternate Authentication Material: Pass the Hash',
        description: 'Adversaries may use pass-the-hash techniques for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1550/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/mimikatz.*sekurlsa::pth|pth-winexe/)) {
                    return true;
                }
                if (eid === '4624' && event.AuthenticationPackageName?.toLowerCase().includes('ntlm') && 
                    event.LogonType?.toString() === '3') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('pass the hash');
        }
    },
    {
        id: 'T1550.003',
        name: 'Use Alternate Authentication Material: Pass the Ticket',
        description: 'Adversaries may use pass-the-ticket techniques for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1550/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/mimikatz.*kerberos::ptt/)) {
                    return true;
                }
                if (eid === '4769' && event.ServiceName?.toLowerCase().includes('krbtgt')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('pass the ticket');
        }
    },
    {
        id: 'T1550.004',
        name: 'Use Alternate Authentication Material: Web Session Cookie',
        description: 'Adversaries may use web session cookies for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1550/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cookie')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/cookies\.sqlite/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('web session cookie');
        }
    },
    // T1534 - Internal Spearphishing
    {
        id: 'T1534',
        name: 'Internal Spearphishing',
        description: 'Adversaries may use internal spearphishing for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1534/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/outlook|email.*phish/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/outlook\.office|exchange/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('spearphishing');
        }
    },
    // T1570 - Lateral Tool Transfer
    {
        id: 'T1570',
        name: 'Lateral Tool Transfer',
        description: 'Adversaries may transfer tools to other systems for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1570/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/copy.*\\\\|scp/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.ps1/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('lateral tool transfer');
        }
    },
    // T1080 - Taint Shared Content
    {
        id: 'T1080',
        name: 'Taint Shared Content',
        description: 'Adversaries may taint shared content for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1080/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('\\\\')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('\\\\')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('taint shared content');
        }
    },
    // T1072 - Software Deployment Tools
    {
        id: 'T1072',
        name: 'Software Deployment Tools',
        description: 'Adversaries may use software deployment tools for lateral movement.',
        mitre_link: 'https://attack.mitre.org/techniques/T1072/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/sccm|ansible|chef|puppet/)) {
                    return true;
                }
                if (eid === '7045' && event.ServiceName?.toLowerCase().match(/sccm|ansible/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('software deployment');
        }
    }
];