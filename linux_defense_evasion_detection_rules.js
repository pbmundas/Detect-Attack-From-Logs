// Detection rules for Defense Evasion tactic on Linux systems
const rules = [
    // T1070 - Indicator Removal
    {
        id: 'T1070',
        name: 'Indicator Removal',
        description: 'Adversaries may delete or modify artifacts to remove evidence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('rm') || command.includes('truncate') || command.includes('git clone')) && 
                   description.includes('deletion/truncation of audit logs');
        }
    },
    {
        id: 'T1070.001',
        name: 'Indicator Removal: Clear Linux or Mac System Logs',
        description: 'Adversaries may clear Linux system logs to hide activity.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('rm /var/log') || command.includes('truncate /var/log');
        }
    },
    {
        id: 'T1070.004',
        name: 'Indicator Removal: File Deletion',
        description: 'Adversaries may delete files to remove evidence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1070/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('rm -rf') || command.includes('shred');
        }
    },
    // T1562 - Impair Defenses
    {
        id: 'T1562',
        name: 'Impair Defenses',
        description: 'Adversaries may impair defensive mechanisms like AV or monitoring.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            const description = (event.description || '').toString().toLowerCase();
            return (command.includes('systemctl') || command.includes('bash /tmp/')) && 
                   description.includes('tampering with security tooling') && description.includes('disabling av');
        }
    },
    {
        id: 'T1562.001',
        name: 'Impair Defenses: Disable or Modify Tools',
        description: 'Adversaries may disable or modify security tools.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('systemctl stop') && (command.includes('clamav') || command.includes('auditd'));
        }
    },
    {
        id: 'T1562.002',
        name: 'Impair Defenses: Disable Linux Audit Logging',
        description: 'Adversaries may disable Linux audit logging.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('systemctl stop auditd') || command.includes('auditctl -D');
        }
    },
    {
        id: 'T1562.004',
        name: 'Impair Defenses: Disable or Modify System Firewall',
        description: 'Adversaries may disable or modify system firewalls.',
        mitre_link: 'https://attack.mitre.org/techniques/T1562/004/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('iptables -F') || command.includes('ufw disable');
        }
    },
    // T1222 - File and Directory Permissions Modification
    {
        id: 'T1222',
        name: 'File and Directory Permissions Modification',
        description: 'Adversaries may modify permissions to hide malicious files.',
        mitre_link: 'https://attack.mitre.org/techniques/T1222/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('chmod') || command.includes('chown');
        }
    },
    {
        id: 'T1222.002',
        name: 'File and Directory Permissions Modification: Linux Permissions',
        description: 'Adversaries may modify Linux file permissions to evade detection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1222/002/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('chmod 777') || command.includes('chown root');
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
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('mv /tmp/') || command.includes('hidden');
        }
    },
    {
        id: 'T1564.001',
        name: 'Hide Artifacts: Hidden Files and Directories',
        description: 'Adversaries may create hidden files or directories.',
        mitre_link: 'https://attack.mitre.org/techniques/T1564/001/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('mv .') || command.includes('touch .');
        }
    },
    // T1574 - Hijack Execution Flow
    {
        id: 'T1574',
        name: 'Hijack Execution Flow',
        description: 'Adversaries may hijack execution flow for evasion.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('LD_PRELOAD') || command.includes('ld.so.preload');
        }
    },
    {
        id: 'T1574.006',
        name: 'Hijack Execution Flow: Dynamic Linker Hijacking',
        description: 'Adversaries may use dynamic linker hijacking for evasion.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/006/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('ld.so.preload') || command.includes('LD_LIBRARY_PATH');
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
            const process = (event.process || '').toString().toLowerCase();
            const command = (event.command || '').toString().toLowerCase();
            return (process.includes('bash') && command.includes('ls')) || command.includes('rename');
        }
    },
    {
        id: 'T1036.005',
        name: 'Masquerading: Match Legitimate Name or Location',
        description: 'Adversaries may masquerade as legitimate processes.',
        mitre_link: 'https://attack.mitre.org/techniques/T1036/005/',
        detection: (event) => {
            if (!event) return false;
            const process = (event.process || '').toString().toLowerCase();
            return process.includes('systemd') && !process.includes('/lib/systemd');
        }
    },
    // T1556 - Modify Authentication Process
    {
        id: 'T1556',
        name: 'Modify Authentication Process',
        description: 'Adversaries may modify authentication processes.',
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
        description: 'Adversaries may modify PAM configurations.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/003/',
        detection: (event) => {
            if (!event) return false;
            const command = (event.command || '').toString().toLowerCase();
            return command.includes('pam.d') || command.includes('pam_unix');
        }
    }
];