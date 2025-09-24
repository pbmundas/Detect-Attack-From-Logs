const rules = [
    // T1003 - OS Credential Dumping
    {
        id: 'T1003',
        name: 'OS Credential Dumping',
        description: 'Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password, from operating systems and software.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/lsadump|mimikatz|procdump/)) {
                    return true;
                }
                if (eid === '10' && event.TargetProcessName?.toLowerCase().includes('lsass.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('credential dumping');
        }
    },
    {
        id: 'T1003.001',
        name: 'OS Credential Dumping: LSASS Memory',
        description: 'Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('lsass')) {
                    return true;
                }
                if (eid === '10' && event.TargetProcessName?.toLowerCase().includes('lsass.exe')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('lsass memory');
        }
    },
    {
        id: 'T1003.002',
        name: 'OS Credential Dumping: Security Account Manager',
        description: 'Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sam database')) {
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
        description: 'Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
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
        description: 'Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts.',
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
        description: 'Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cached credential')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('mscache')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cached domain credentials');
        }
    },
    {
        id: 'T1003.006',
        name: 'OS Credential Dumping: DCSync',
        description: 'Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API) to simulate the replication process from a remote domain controller using a technique called DCSync.',
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
                if (eid === '4662' && event.AccessMask?.includes('0x100')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dcsync');
        }
    },
    {
        id: 'T1003.007',
        name: 'OS Credential Dumping: Proc Filesystem',
        description: 'Adversaries may gather credentials from information stored in the Proc filesystem or /proc.',
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
        description: 'Adversaries may attempt to dump the contents of /etc/passwd and /etc/shadow to enable offline password cracking.',
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
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/passwd|shadow/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('/etc/passwd and /etc/shadow');
        }
    },
    // T1040 - Network Sniffing
    {
        id: 'T1040',
        name: 'Network Sniffing',
        description: 'Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network.',
        mitre_link: 'https://attack.mitre.org/techniques/T1040/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/tcpdump|wireshark|ngrep/)) {
                    return true;
                }
                if (eid === '3' && event.Protocol === 'RAW') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network sniffing');
        }
    },
    // T1110 - Brute Force
    {
        id: 'T1110',
        name: 'Brute Force',
        description: 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.',
        mitre_link: 'https://attack.mitre.org/techniques/T1110/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4625' && event.FailureReason?.includes('unknown')) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/hydra|medusa|hashcat/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('brute force');
        }
    },
    {
        id: 'T1110.001',
        name: 'Brute Force: Password Guessing',
        description: 'Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1110/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4625' && event.LogonType === '3') {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/password guess/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('password guessing');
        }
    },
    {
        id: 'T1110.002',
        name: 'Brute Force: Password Cracking',
        description: 'Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when password hashes are obtained.',
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
        description: 'Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1110/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4625' && event.FailureReason?.includes('locked')) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/spray/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('password spraying');
        }
    },
    {
        id: 'T1110.004',
        name: 'Brute Force: Credential Stuffing',
        description: 'Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap.',
        mitre_link: 'https://attack.mitre.org/techniques/T1110/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if (eid === '4624' && event.LogonType === '3') {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/stuffing/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('credential stuffing');
        }
    },
    // T1111 - Multi-Factor Authentication Interception
    {
        id: 'T1111',
        name: 'Multi-Factor Authentication Interception',
        description: 'Adversaries may target multi-factor authentication (MFA) mechanisms to gain access to credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1111/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('mfa intercept')) {
                    return true;
                }
                if (eid === '4624' && event.MFA === 'Intercepted') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('multi-factor authentication interception');
        }
    },
    // T1187 - Forced Authentication
    {
        id: 'T1187',
        name: 'Forced Authentication',
        description: 'Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept it.',
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
    // T1212 - Exploitation for Credential Access
    {
        id: 'T1212',
        name: 'Exploitation for Credential Access',
        description: 'Adversaries may exploit software vulnerabilities in an attempt to collect credentials.',
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
                if (eid === '7030' && event.EventType === 'Exploit') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('exploitation for credential access');
        }
    },
    // T1552 - Unsecured Credentials
    {
        id: 'T1552',
        name: 'Unsecured Credentials',
        description: 'Adversaries may search compromised systems to find and obtain insecurely stored credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('unsecured credential')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('credential')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('unsecured credentials');
        }
    },
    {
        id: 'T1552.001',
        name: 'Unsecured Credentials: Credentials In Files',
        description: 'Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('credentials in files')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('config')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('credentials in files');
        }
    },
    {
        id: 'T1552.002',
        name: 'Unsecured Credentials: Credentials in Registry',
        description: 'Adversaries may search local system sources, such as the Registry, to find credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('reg query credential')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('credential')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('credentials in registry');
        }
    },
    {
        id: 'T1552.003',
        name: 'Unsecured Credentials: Bash History',
        description: 'Adversaries may search the bash command history on compromised systems for insecurely stored credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('bash history')) {
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
        description: 'Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('private key')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.pem|\.key/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('private keys');
        }
    },
    {
        id: 'T1552.005',
        name: 'Unsecured Credentials: Cloud Instance Metadata API',
        description: 'Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('metadata api')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().includes('169.254.169.254')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud instance metadata api');
        }
    },
    {
        id: 'T1552.006',
        name: 'Unsecured Credentials: Group Policy Preferences',
        description: 'Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP).',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('gpp')) {
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
        description: 'Adversaries may gather credentials via APIs within a containers environment.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('container api')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().includes('kubernetes')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('container api');
        }
    },
    {
        id: 'T1552.008',
        name: 'Unsecured Credentials: Chat Messages',
        description: 'Adversaries may directly collect unsecured credentials stored or passed through user communication services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('chat credential')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('slack')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('chat messages');
        }
    },
    {
        id: 'T1552.009',
        name: 'Unsecured Credentials: Stored Authentication Artifacts',
        description: 'Adversaries may search compromised systems for stored authentication artifacts that may be used to obtain credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/009/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('auth artifact')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('auth')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('stored authentication artifacts');
        }
    },
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
                if (eid === '10' && event.TargetProcessName?.toLowerCase().includes('securityd')) {
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
                    commandLine.toLowerCase().includes('password manager')) {
                    return true;
                }
                if (eid === '10' && event.TargetProcessName?.toLowerCase().includes('lastpass')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('password managers');
        }
    },
    {
        id: 'T1555.006',
        name: 'Credentials from Password Stores: Cloud Secrets Management Stores',
        description: 'Adversaries may acquire credentials from cloud-native secret management solutions, such as AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and ACI (Kubernetes Secrets).',
        mitre_link: 'https://attack.mitre.org/techniques/T1555/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('secrets manager')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().includes('secretsmanager')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud secrets management stores');
        }
    },
    // T1556 - Modify Authentication Process
    {
        id: 'T1556',
        name: 'Modify Authentication Process',
        description: 'Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('modify auth')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('authentication')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('modify authentication process');
        }
    },
    {
        id: 'T1556.001',
        name: 'Modify Authentication Process: Domain Controller Authentication',
        description: 'Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('domain controller auth')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('domain controller')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain controller authentication');
        }
    },
    {
        id: 'T1556.002',
        name: 'Modify Authentication Process: Password Filter DLL',
        description: 'Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('password filter dll')) {
                    return true;
                }
                if (eid === '7' && event.ImageLoaded?.toLowerCase().includes('passwordfilter')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('password filter dll');
        }
    },
    {
        id: 'T1556.003',
        name: 'Modify Authentication Process: Pluggable Authentication Modules',
        description: 'Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('pam')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('pam.d')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('pluggable authentication modules');
        }
    },
    {
        id: 'T1556.004',
        name: 'Modify Authentication Process: Doas Configuration',
        description: 'Adversaries may modify the doas.conf configuration file to enable unwarranted access to accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('doas.conf')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('doas.conf')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('doas configuration');
        }
    },
    {
        id: 'T1556.005',
        name: 'Modify Authentication Process: Reversible Encryption',
        description: 'Adversaries may abuse Reversible Encryption to bypass access controls on password data stored in the Active Directory (AD) Property msDS-PasswordReversibleEncryptionEnabled or similar mechanisms in other identity management systems.',
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
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('passwordreversible')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('reversible encryption');
        }
    },
    {
        id: 'T1556.006',
        name: 'Modify Authentication Process: Multi-Factor Authentication',
        description: 'Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts.',
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
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('mfa')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('multi-factor authentication');
        }
    },
    {
        id: 'T1556.007',
        name: 'Modify Authentication Process: Hybrid Identity',
        description: 'Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts.',
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
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('adfs')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('hybrid identity');
        }
    },
    {
        id: 'T1556.008',
        name: 'Modify Authentication Process: Network Provider DLL',
        description: 'Adversaries may register malicious network provider dynamic link libraries (DLLs) to capture plaintext credentials sent over the wire.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('network provider dll')) {
                    return true;
                }
                if (eid === '7' && event.ImageLoaded?.toLowerCase().includes('networkprovider')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network provider dll');
        }
    },
    {
        id: 'T1556.009',
        name: 'Modify Authentication Process: Conditional Access Policies',
        description: 'Adversaries may modify conditional access policies to enable persistent access to compromised accounts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/009/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('conditional access')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('conditionalaccess')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('conditional access policies');
        }
    },
    // T1558 - Steal or Forge Kerberos Tickets
    {
        id: 'T1558',
        name: 'Steal or Forge Kerberos Tickets',
        description: 'Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable unauthorized access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1558/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('kerberos ticket')) {
                    return true;
                }
                if (eid === '4769' && event.Status === '0x0') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('kerberos ticket');
        }
    },
    {
        id: 'T1558.001',
        name: 'Steal or Forge Kerberos Tickets: Golden Ticket',
        description: 'Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket.',
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
                if (eid === '4769' && event.TicketOptions?.includes('0x40810000')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('golden ticket');
        }
    },
    {
        id: 'T1558.002',
        name: 'Steal or Forge Kerberos Tickets: Silver Ticket',
        description: 'Adversaries who have the password hash of a target service account may forge Kerberos ticket-granting service (TGS) tickets, also known as a silver ticket.',
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
                if (eid === '4769' && event.TicketEncryptionType?.includes('0x17')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('silver ticket');
        }
    },
    {
        id: 'T1558.003',
        name: 'Steal or Forge Kerberos Tickets: Kerberoasting',
        description: 'Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to Brute Force.',
        mitre_link: 'https://attack.mitre.org/techniques/T1558/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('kerberoast')) {
                    return true;
                }
                if (eid === '4769' && event.TicketEncryptionType?.includes('0x17')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('kerberoasting');
        }
    },
    {
        id: 'T1558.004',
        name: 'Steal or Forge Kerberos Tickets: AS-REP Roasting',
        description: 'Adversaries may reveal credentials of accounts that have disabled Kerberos preauthentication by Password Cracking Kerberos messages.',
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
                if (eid === '4768' && event.PreAuthType === '0') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('as-rep roasting');
        }
    },
    // T1606 - Forge Web Credentials
    {
        id: 'T1606',
        name: 'Forge Web Credentials',
        description: 'Adversaries may forge web credentials in order to gain access to web services.',
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
                if (eid === '4624' && event.LogonType === '3' && event.AuthenticationPackageName?.toLowerCase().includes('forged')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('forge web credentials');
        }
    },
    {
        id: 'T1606.001',
        name: 'Forge Web Credentials: Web Cookies',
        description: 'Adversaries may forge web cookies that can be used to gain access to web applications or Internet services.',
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
        description: 'Adversaries may forge SAML tokens with any permissions claims and lifetimes if they possess a valid SAML token-signing certificate.',
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
            return typeof event === 'string' && event && event.toLowerCase().includes('saml tokens');
        }
    },
    // T1621 - Multi-Factor Authentication Request Generation
    {
        id: 'T1621',
        name: 'Multi-Factor Authentication Request Generation',
        description: 'Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and obtain access to accounts by generating MFA requests sent to users.',
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
                if (eid === '4624' && event.MFA === 'Generated') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('multi-factor authentication request generation');
        }
    },
    // T1649 - Steal or Forge Authentication Certificates
    {
        id: 'T1649',
        name: 'Steal or Forge Authentication Certificates',
        description: 'Adversaries may steal or forge certificates used for authentication to access remote systems or resources.',
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
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.cer|\.pem/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('authentication certificates');
        }
    },
    // T1651 - Cloud Administration Command
    {
        id: 'T1651',
        name: 'Cloud Administration Command',
        description: 'Adversaries may abuse cloud management APIs or CLI commands to access cloud-hosted credentials or further their access within cloud environments.',
        mitre_link: 'https://attack.mitre.org/techniques/T1651/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws|azure|gcloud/) && 
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
