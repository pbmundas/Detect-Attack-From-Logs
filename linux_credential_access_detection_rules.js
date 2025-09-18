// Detection rules for Credential Access tactic on Linux systems
const rules = [
    // T1003 - OS Credential Dumping
    {
        id: 'T1003',
        name: 'OS Credential Dumping',
        description: 'Adversaries may dump credentials from the operating system.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('cat /etc/shadow') || command.includes('wget') || command.includes('curl')) && 
                   description.includes('credential store') && description.includes('accessed /etc/shadow');
        }
    },
    {
        id: 'T1003.007',
        name: 'OS Credential Dumping: Proc Filesystem',
        description: 'Adversaries may dump credentials from /proc filesystem.',
        mitre_link: 'https://attack.mitre.org/techniques/T1003/007/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('cat /proc') && command.includes('mem');
        }
    },
    // T1555 - Credentials from Password Stores
    {
        id: 'T1555',
        name: 'Credentials from Password Stores',
        description: 'Adversaries may access password stores to obtain credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1555/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('cat /etc/passwd') || command.includes('keyring');
        }
    },
    {
        id: 'T1555.003',
        name: 'Credentials from Password Stores: Credentials from Web Browsers',
        description: 'Adversaries may access browser credential stores.',
        mitre_link: 'https://attack.mitre.org/techniques/T1555/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('firefox') && command.includes('passwords');
        }
    },
    // T1552 - Unsecured Credentials
    {
        id: 'T1552',
        name: 'Unsecured Credentials',
        description: 'Adversaries may access unsecured credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('grep -r password') || command.includes('credentials');
        }
    },
    {
        id: 'T1552.001',
        name: 'Unsecured Credentials: Credentials In Files',
        description: 'Adversaries may search for credentials in files.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('grep -r password /etc') || command.includes('find / -name *.conf');
        }
    },
    {
        id: 'T1552.004',
        name: 'Unsecured Credentials: Private Keys',
        description: 'Adversaries may access private keys.',
        mitre_link: 'https://attack.mitre.org/techniques/T1552/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('cat ~/.ssh/id_rsa') || command.includes('private key');
        }
    },
    // T1110 - Brute Force
    {
        id: 'T1110',
        name: 'Brute Force',
        description: 'Adversaries may use brute force to guess credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1110/',
        detection: (event) => {
            if (!event) return false;
            const log_type = (event.log_type || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return log_type.includes('auth') && description.includes('brute force');
        }
    },
    {
        id: 'T1110.001',
        name: 'Brute Force: Password Guessing',
        description: 'Adversaries may guess passwords.',
        mitre_link: 'https://attack.mitre.org/techniques/T1110/001/',
        detection: (event) => {
            if (!event) return false;
            const log_type = (event.log_type || '').toString().toLowerCase();
            return log_type.includes('auth') && event.description?.toString().toLowerCase().includes('password guessing');
        }
    },
    {
        id: 'T1110.003',
        name: 'Brute Force: Password Spraying',
        description: 'Adversaries may use password spraying.',
        mitre_link: 'https://attack.mitre.org/techniques/T1110/003/',
        detection: (event) => {
            if (!event) return false;
            const log_type = (event.log_type || '').toString().toLowerCase();
            return log_type.includes('auth') && event.description?.toString().toLowerCase().includes('password spraying');
        }
    },
    // T1556 - Modify Authentication Process
    {
        id: 'T1556',
        name: 'Modify Authentication Process',
        description: 'Adversaries may modify authentication processes to access credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('pam.d') || command.includes('sshd_config');
        }
    },
    {
        id: 'T1556.003',
        name: 'Modify Authentication Process: Pluggable Authentication Modules',
        description: 'Adversaries may modify PAM configurations to access credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('pam.d') || command.includes('pam_unix');
        }
    }
];