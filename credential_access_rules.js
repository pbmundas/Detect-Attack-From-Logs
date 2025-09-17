const rules = [
    // T1555 - Credentials from Password Stores
    {
        id: 'T1555',
        name: 'Credentials from Password Stores',
        description: 'Adversaries may search for credentials in password stores.',
        mitre_link: 'https://attack.mitre.org/techniques/T1555/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('password store')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/keychain|credential/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('password store');
        }
    },
    {
        id: 'T1555.001',
        name: 'Credentials from Password Stores: Keychain',
        description: 'Adversaries may steal credentials from macOS Keychain.',
        mitre_link: 'https://attack.mitre.org/techniques/T1555/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('security dump-keychain')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('keychain')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('keychain');
        }
    },
    {
        id: 'T1555.002',
        name: 'Credentials from Password Stores: Securityd Memory',
        description: 'Adversaries may steal credentials from securityd memory.',
        mitre_link: 'https://attack.mitre.org/techniques/T1555/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('securityd')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('securityd memory');
        }
    },
    {
        id: 'T1555.003',
        name: 'Credentials from Password Stores: Credentials from Web Browsers',
        description: 'Adversaries may steal credentials from web browsers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1555/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/chrome|firefox|edge/) && 
                    commandLine.toLowerCase().includes('password')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/passwords\.sqlite|login\.json/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('browser credential');
        }
    },
    {
        id: 'T1555.004',
        name: 'Credentials from Password Stores: Windows Credential Manager',
        description: 'Adversaries may steal credentials from Windows Credential Manager.',
        mitre_link: 'https://attack.mitre.org/techniques/T1555/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('vaultcmd') || 
                    commandLine.toLowerCase().includes('credential manager')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('credentialmanager')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('credential manager');
        }
    },
    {
        id: 'T1555.005',
        name: 'Credentials from Password Stores: Password Managers',
        description: 'Adversaries may steal credentials from password managers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1555/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/lastpass|keepass|1password/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/keepass\.kdbx/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('password manager');
        }
    },
    // T1110 - Brute Force
    {
        id: 'T1110',
        name: 'Brute Force',
        description: 'Adversaries may use brute force to gain access to accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1110/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4625' && event.FailureReason?.toLowerCase().includes('bad password')) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('hydra') || 
                    commandLine.toLowerCase().includes('brute force')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('brute force');
        }
    },
    {
        id: 'T1110.001',
        name: 'Brute Force: Password Guessing',
        description: 'Adversaries may guess passwords to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1110/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4625' && event.FailureReason?.toLowerCase().includes('bad password')) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('password guessing')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('password guessing');
        }
    },
    {
        id: 'T1110.002',
        name: 'Brute Force: Password Cracking',
        description: 'Adversaries may crack passwords to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1110/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/hashcat|john/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('password cracking');
        }
    },
    {
        id: 'T1110.003',
        name: 'Brute Force: Password Spraying',
        description: 'Adversaries may use password spraying to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1110/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4625' && event.TargetUserName?.toString().match(/admin|user|test/)) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('password spraying')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('password spraying');
        }
    },
    {
        id: 'T1110.004',
        name: 'Brute Force: Credential Stuffing',
        description: 'Adversaries may use credential stuffing to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1110/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4625' && event.IpAddress?.toString().match(/\d+\.\d+\.\d+\.\d+/)) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('credential stuffing')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('credential stuffing');
        }
    },
    // T1558 - Steal or Forge Kerberos Tickets
    {
        id: 'T1558',
        name: 'Steal or Forge Kerberos Tickets',
        description: 'Adversaries may steal or forge Kerberos tickets to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1558/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('kerberos')) {
                    return true;
                }
                if (eid === '4769' && event.ServiceName?.toLowerCase().includes('krbtgt')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('kerberos ticket');
        }
    },
    {
        id: 'T1558.001',
        name: 'Steal or Forge Kerberos Tickets: Golden Ticket',
        description: 'Adversaries may forge Golden Tickets to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1558/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('golden ticket')) {
                    return true;
                }
                if (eid === '4769' && event.ServiceName?.toLowerCase().includes('krbtgt')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('golden ticket');
        }
    },
    {
        id: 'T1558.002',
        name: 'Steal or Forge Kerberos Tickets: Silver Ticket',
        description: 'Adversaries may forge Silver Tickets to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1558/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('silver ticket')) {
                    return true;
                }
                if (eid === '4769' && event.ServiceName?.toLowerCase().match(/http|cifs/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('silver ticket');
        }
    },
    {
        id: 'T1558.003',
        name: 'Steal or Forge Kerberos Tickets: Kerberoasting',
        description: 'Adversaries may perform Kerberoasting to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1558/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('kerberoasting')) {
                    return true;
                }
                if (eid === '4769' && event.ServiceName?.toLowerCase().includes('$')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('kerberoasting');
        }
    },
    {
        id: 'T1558.004',
        name: 'Steal or Forge Kerberos Tickets: AS-REP Roasting',
        description: 'Adversaries may perform AS-REP Roasting to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1558/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('as-rep')) {
                    return true;
                }
                if (eid === '4768' && event.TicketOptions?.toLowerCase().includes('preauth')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('as-rep roasting');
        }
    },
    // T1003 - OS Credential Dumping
    {
        id: 'T1003',
        name: 'OS Credential Dumping',
        description: 'Adversaries may dump credentials from the operating system.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('mimikatz') || 
                    commandLine.toLowerCase().includes('sekurlsa')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('credential dumping');
        }
    },
    {
        id: 'T1003.001',
        name: 'OS Credential Dumping: LSASS Memory',
        description: 'Adversaries may dump credentials from LSASS memory.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('lsass') && 
                    commandLine.toLowerCase().includes('dump')) {
                    return true;
                }
                if (eid === '10' && event.TargetImage?.toLowerCase().includes('lsass.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('lsass memory');
        }
    },
    {
        id: 'T1003.002',
        name: 'OS Credential Dumping: Security Account Manager',
        description: 'Adversaries may dump credentials from SAM.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sam dump')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('sam')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('security account manager');
        }
    },
    {
        id: 'T1003.003',
        name: 'OS Credential Dumping: NTDS',
        description: 'Adversaries may dump credentials from NTDS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('ntdsutil') || 
                    commandLine.toLowerCase().includes('ntds.dit')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('ntds.dit')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('ntds');
        }
    },
    {
        id: 'T1003.004',
        name: 'OS Credential Dumping: LSA Secrets',
        description: 'Adversaries may dump LSA secrets to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('lsa secrets')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('lsa')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('lsa secrets');
        }
    },
    {
        id: 'T1003.005',
        name: 'OS Credential Dumping: Cached Domain Credentials',
        description: 'Adversaries may dump cached domain credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cached credentials')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('cachedlogonscount')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cached domain credentials');
        }
    },
    {
        id: 'T1003.006',
        name: 'OS Credential Dumping: DCSync',
        description: 'Adversaries may use DCSync to dump credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('dcsync')) {
                    return true;
                }
                if (eid === '4662' && event.ObjectName?.toLowerCase().includes('directory service')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dcsync');
        }
    },
    {
        id: 'T1003.007',
        name: 'OS Credential Dumping: Proc Filesystem',
        description: 'Adversaries may dump credentials from /proc filesystem.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/007/',
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
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('/proc')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('proc filesystem');
        }
    },
    {
        id: 'T1003.008',
        name: 'OS Credential Dumping: /etc/passwd and /etc/shadow',
        description: 'Adversaries may dump credentials from /etc/passwd or /etc/shadow.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/\/etc\/passwd|\/etc\/shadow/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\/etc\/passwd|\/etc\/shadow/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('/etc/passwd');
        }
    },
    // T1552 - Unsecured Credentials
    {
        id: 'T1552',
        name: 'Unsecured Credentials',
        description: 'Adversaries may search for unsecured credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('unsecured credentials')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.txt|\.config/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('unsecured credentials');
        }
    },
    {
        id: 'T1552.001',
        name: 'Unsecured Credentials: Credentials In Files',
        description: 'Adversaries may search for credentials in files.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('findstr password') || 
                    commandLine.toLowerCase().includes('grep password')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/password\.txt|config\.ini/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('credentials in files');
        }
    },
    {
        id: 'T1552.002',
        name: 'Unsecured Credentials: Credentials in Registry',
        description: 'Adversaries may search for credentials in the Windows Registry.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('reg query') && 
                    commandLine.toLowerCase().includes('password')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('password')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('credentials in registry');
        }
    },
    {
        id: 'T1552.003',
        name: 'Unsecured Credentials: Bash History',
        description: 'Adversaries may search for credentials in bash history.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('.bash_history')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.bash_history')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('bash history');
        }
    },
    {
        id: 'T1552.004',
        name: 'Unsecured Credentials: Private Keys',
        description: 'Adversaries may steal private keys to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('.pem') || 
                    commandLine.toLowerCase().includes('private key')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.pem|\.key/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('private key');
        }
    },
    {
        id: 'T1552.005',
        name: 'Unsecured Credentials: Cloud Instance Metadata API',
        description: 'Adversaries may access cloud instance metadata to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('169.254.169.254')) {
                    return true;
                }
                if (eid === '3' && event.DestinationIp?.toString().includes('169.254.169.254')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud metadata');
        }
    },
    {
        id: 'T1552.006',
        name: 'Unsecured Credentials: Group Policy Preferences',
        description: 'Adversaries may steal credentials from Group Policy Preferences.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('groups.xml')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('groups.xml')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('group policy preferences');
        }
    },
    {
        id: 'T1552.007',
        name: 'Unsecured Credentials: Container API',
        description: 'Adversaries may access container APIs to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('docker') && 
                    commandLine.toLowerCase().includes('secret')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('container api');
        }
    },
    {
        id: 'T1552.008',
        name: 'Unsecured Credentials: Chat Messages',
        description: 'Adversaries may steal credentials from chat messages.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/slack|teams|discord/) && 
                    commandLine.toLowerCase().includes('password')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('chat messages');
        }
    },
    // T1056 - Input Capture
    {
        id: 'T1056',
        name: 'Input Capture',
        description: 'Adversaries may capture user input to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('keylogger')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('input capture');
        }
    },
    {
        id: 'T1056.001',
        name: 'Input Capture: Keylogging',
        description: 'Adversaries may use keylogging to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('keylogger') || 
                    commandLine.toLowerCase().includes('getkeystate')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('keylogging');
        }
    },
    {
        id: 'T1056.002',
        name: 'Input Capture: GUI Input Capture',
        description: 'Adversaries may use GUI input capture to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('gui capture')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('gui input capture');
        }
    },
    {
        id: 'T1056.003',
        name: 'Input Capture: Web Portal Capture',
        description: 'Adversaries may use web portal capture to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('web portal') && 
                    commandLine.toLowerCase().includes('password')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().includes('login')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('web portal capture');
        }
    },
    {
        id: 'T1056.004',
        name: 'Input Capture: Credential API Hooking',
        description: 'Adversaries may hook credential APIs to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('credential api')) {
                    return true;
                }
                if (eid === '8' && event.CallTrace?.toLowerCase().includes('setwindowshook')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('credential api hooking');
        }
    },
    // T1539 - Steal Web Session Cookie
    {
        id: 'T1539',
        name: 'Steal Web Session Cookie',
        description: 'Adversaries may steal web session cookies to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1539/',
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
    // T1649 - Steal or Forge Authentication Certificates
    {
        id: 'T1649',
        name: 'Steal or Forge Authentication Certificates',
        description: 'Adversaries may steal or forge authentication certificates.',
        mitre_link: 'https://attack.mitre.org/techniques/T1649/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('certificate')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.cer|\.pfx/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('authentication certificate');
        }
    },
    // T1557 - Adversary-in-the-Middle
    {
        id: 'T1557',
        name: 'Adversary-in-the-Middle',
        description: 'Adversaries may perform MitM attacks to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1557/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/responder|ettercap/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/445|137|138/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('adversary-in-the-middle');
        }
    },
    {
        id: 'T1557.001',
        name: 'Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay',
        description: 'Adversaries may use LLMNR/NBT-NS poisoning and SMB relay to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1557/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('responder')) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/137|138|445/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('llmnr poisoning');
        }
    },
    {
        id: 'T1557.002',
        name: 'Adversary-in-the-Middle: ARP Cache Poisoning',
        description: 'Adversaries may use ARP cache poisoning to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1557/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('arp poisoning') || 
                    commandLine.toLowerCase().includes('ettercap')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('arp cache poisoning');
        }
    },
    {
        id: 'T1557.003',
        name: 'Adversary-in-the-Middle: DHCP Spoofing',
        description: 'Adversaries may use DHCP spoofing to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1557/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('dhcp spoofing')) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().includes('67')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dhcp spoofing');
        }
    },
    // T1040 - Network Sniffing
    {
        id: 'T1040',
        name: 'Network Sniffing',
        description: 'Adversaries may sniff network traffic to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1040/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/wireshark|tcpdump/)) {
                    return true;
                }
                if (eid === '3' && event.Protocol?.toLowerCase().includes('tcp') && 
                    event.DestinationPort?.toString().match(/80|443/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network sniffing');
        }
    },
    // T1621 - Multi-Factor Authentication Request Generation
    {
        id: 'T1621',
        name: 'Multi-Factor Authentication Request Generation',
        description: 'Adversaries may generate MFA requests to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1621/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('mfa request')) {
                    return true;
                }
                if (eid === '4624' && event.AuthenticationPackageName?.toLowerCase().includes('mfa')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('mfa request');
        }
    },
    // T1528 - Steal Application Access Token
    {
        id: 'T1528',
        name: 'Steal Application Access Token',
        description: 'Adversaries may steal application access tokens.',
        mitre_link: 'https://attack.mitre.org/techniques/T1528/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('access token')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('application access token');
        }
    },
    // T1542 - Pre-OS Boot
    {
        id: 'T1542',
        name: 'Pre-OS Boot',
        description: 'Adversaries may manipulate pre-OS boot components to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1542/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('bootloader')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/boot|grub/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('pre-os boot');
        }
    },
    {
        id: 'T1542.001',
        name: 'Pre-OS Boot: System Firmware',
        description: 'Adversaries may manipulate system firmware to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1542/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('firmware')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system firmware');
        }
    },
    {
        id: 'T1542.002',
        name: 'Pre-OS Boot: Component Firmware',
        description: 'Adversaries may manipulate component firmware to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1542/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('component firmware')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('component firmware');
        }
    },
    {
        id: 'T1542.003',
        name: 'Pre-OS Boot: Bootkit',
        description: 'Adversaries may use bootkits to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1542/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('bootkit')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/bootmgr|bcd/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('bootkit');
        }
    },
    {
        id: 'T1542.004',
        name: 'Pre-OS Boot: ROMMONkit',
        description: 'Adversaries may use ROMMONkit to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1542/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('rommon')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('rommonkit');
        }
    },
    {
        id: 'T1542.005',
        name: 'Pre-OS Boot: TFTP Boot',
        description: 'Adversaries may use TFTP boot to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1542/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('tftp')) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().includes('69')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('tftp boot');
        }
    },
    // T1187 - Forced Authentication
    {
        id: 'T1187',
        name: 'Forced Authentication',
        description: 'Adversaries may force authentication to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1187/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('forced authentication')) {
                    return true;
                }
                if (eid === '4624' && event.AuthenticationPackageName?.toLowerCase().includes('ntlm')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('forced authentication');
        }
    },
    // T1606 - Forge Web Credentials
    {
        id: 'T1606',
        name: 'Forge Web Credentials',
        description: 'Adversaries may forge web credentials to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1606/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('forge credential')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('forge web credentials');
        }
    },
    {
        id: 'T1606.001',
        name: 'Forge Web Credentials: Web Cookies',
        description: 'Adversaries may forge web cookies to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1606/001/',
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
            return typeof event === 'string' && event && event.toLowerCase().includes('web cookies');
        }
    },
    {
        id: 'T1606.002',
        name: 'Forge Web Credentials: SAML Tokens',
        description: 'Adversaries may forge SAML tokens to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1606/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('saml token')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().includes('saml')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('saml token');
        }
    },
    // T1212 - Exploitation for Credential Access
    {
        id: 'T1212',
        name: 'Exploitation for Credential Access',
        description: 'Adversaries may exploit vulnerabilities to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1212/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('exploit credential')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('exploitation for credential');
        }
    },
    // T1651 - Cloud Administration Command
    {
        id: 'T1651',
        name: 'Cloud Administration Command',
        description: 'Adversaries may use cloud administration commands to steal credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1651/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws|azure/) && 
                    commandLine.toLowerCase().includes('credential')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud administration command');
        }
    }
];