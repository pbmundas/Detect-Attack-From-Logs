const rules = [
    // T1547 - Boot or Logon Autostart Execution
    {
        id: 'T1547',
        name: 'Boot or Logon Autostart Execution',
        description: 'Adversaries may configure system settings to execute programs during boot or logon.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('reg add') || 
                     commandLine.toLowerCase().includes('autostart'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('run')) {
                    return true; // Registry run key modifications
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('autostart');
        }
    },
    {
        id: 'T1547.001',
        name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder',
        description: 'Adversaries may use registry run keys or startup folder to achieve persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('hkcu\\software\\microsoft\\windows\\currentversion\\run')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().match(/run|runonce/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('startup')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('run key');
        }
    },
    {
        id: 'T1547.002',
        name: 'Boot or Logon Autostart Execution: Authentication Package',
        description: 'Adversaries may modify authentication packages for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('authentication package')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('authenticationpackages')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('authentication package');
        }
    },
    {
        id: 'T1547.003',
        name: 'Boot or Logon Autostart Execution: Time Providers',
        description: 'Adversaries may modify time providers for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('time provider')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('timeproviders')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('time provider');
        }
    },
    {
        id: 'T1547.004',
        name: 'Boot or Logon Autostart Execution: Winlogon Helper DLL',
        description: 'Adversaries may use Winlogon helper DLLs for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('winlogon')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('winlogon')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('winlogon');
        }
    },
    {
        id: 'T1547.005',
        name: 'Boot or Logon Autostart Execution: Security Support Provider',
        description: 'Adversaries may modify SSPs for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('security support provider')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('securitypackages')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('security support provider');
        }
    },
    {
        id: 'T1547.006',
        name: 'Boot or Logon Autostart Execution: Kernel Modules and Extensions',
        description: 'Adversaries may load kernel modules for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('kernel module')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.sys/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('kernel module');
        }
    },
    {
        id: 'T1547.007',
        name: 'Boot or Logon Autostart Execution: Re-opened Applications',
        description: 'Adversaries may configure re-opened applications for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('re-opened application')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('re-opened application');
        }
    },
    {
        id: 'T1547.008',
        name: 'Boot or Logon Autostart Execution: LSASS Driver',
        description: 'Adversaries may use LSASS drivers for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('lsass driver')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.sys/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('lsass driver');
        }
    },
    {
        id: 'T1547.009',
        name: 'Boot or Logon Autostart Execution: Shortcut Modification',
        description: 'Adversaries may modify shortcuts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/009/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('shortcut modification')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.lnk/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('shortcut modification');
        }
    },
    {
        id: 'T1547.010',
        name: 'Boot or Logon Autostart Execution: Port Monitors',
        description: 'Adversaries may use port monitors for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/010/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('port monitor')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('portmonitors')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('port monitor');
        }
    },
    {
        id: 'T1547.012',
        name: 'Boot or Logon Autostart Execution: Print Processors',
        description: 'Adversaries may use print processors for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/012/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('print processor')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('printprocessors')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('print processor');
        }
    },
    {
        id: 'T1547.013',
        name: 'Boot or Logon Autostart Execution: XDG Autostart Entries',
        description: 'Adversaries may use XDG autostart entries for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/013/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('xdg autostart')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.desktop/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('xdg autostart');
        }
    },
    {
        id: 'T1547.014',
        name: 'Boot or Logon Autostart Execution: Active Setup',
        description: 'Adversaries may use Active Setup for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/014/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('active setup')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('activesetup')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('active setup');
        }
    },
    // T1037 - Boot or Logon Initialization Scripts
    {
        id: 'T1037',
        name: 'Boot or Logon Initialization Scripts',
        description: 'Adversaries may use initialization scripts to achieve persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('logon script')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.bat|\.vbs/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('logon script');
        }
    },
    {
        id: 'T1037.001',
        name: 'Boot or Logon Initialization Scripts: Logon Script (Windows)',
        description: 'Adversaries may use Windows logon scripts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('logon script')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.bat|\.vbs/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('windows logon script');
        }
    },
    {
        id: 'T1037.002',
        name: 'Boot or Logon Initialization Scripts: Logon Script (Mac)',
        description: 'Adversaries may use macOS logon scripts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('mac logon script')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.sh/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('mac logon script');
        }
    },
    {
        id: 'T1037.003',
        name: 'Boot or Logon Initialization Scripts: Network Logon Script',
        description: 'Adversaries may use network logon scripts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('network logon script')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.bat|\.vbs/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network logon script');
        }
    },
    {
        id: 'T1037.004',
        name: 'Boot or Logon Initialization Scripts: RC Scripts',
        description: 'Adversaries may use RC scripts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('rc script')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.rc/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('rc script');
        }
    },
    {
        id: 'T1037.005',
        name: 'Boot or Logon Initialization Scripts: Startup Items',
        description: 'Adversaries may use startup items for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('startup item')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.plist/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('startup item');
        }
    },
    // T1556 - Modify Authentication Process
    {
        id: 'T1556',
        name: 'Modify Authentication Process',
        description: 'Adversaries may modify authentication mechanisms for persistence.',
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
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('authentication')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('authentication process');
        }
    },
    {
        id: 'T1556.001',
        name: 'Modify Authentication Process: Domain Controller Authentication',
        description: 'Adversaries may modify domain controller authentication for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('domain controller authentication')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain controller authentication');
        }
    },
    {
        id: 'T1556.002',
        name: 'Modify Authentication Process: Password Filter DLL',
        description: 'Adversaries may use password filter DLLs for persistence.',
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
        description: 'Adversaries may modify PAM for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('pam module')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.so/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('pam module');
        }
    },
    {
        id: 'T1556.004',
        name: 'Modify Authentication Process: Network Device Authentication',
        description: 'Adversaries may modify network device authentication for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('network device authentication')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network device authentication');
        }
    },
    {
        id: 'T1556.005',
        name: 'Modify Authentication Process: Reversible Encryption',
        description: 'Adversaries may enable reversible encryption for persistence.',
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
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('encryptpasswords')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('reversible encryption');
        }
    },
    {
        id: 'T1556.006',
        name: 'Modify Authentication Process: Multi-Factor Authentication',
        description: 'Adversaries may modify MFA for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('multi-factor authentication')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('multi-factor authentication');
        }
    },
    {
        id: 'T1556.007',
        name: 'Modify Authentication Process: Hybrid Identity',
        description: 'Adversaries may modify hybrid identity for persistence.',
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
        name: 'Modify Authentication Process: Cloud API Key',
        description: 'Adversaries may modify cloud API keys for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cloud api key')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/amazonaws\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud api key');
        }
    },
    // T1136 - Create Account
    {
        id: 'T1136',
        name: 'Create Account',
        description: 'Adversaries may create accounts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1136/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net user /add')) {
                    return true;
                }
                if (eid === '4720' && event.TargetUserName) {
                    return true; // User account creation
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('account creation');
        }
    },
    {
        id: 'T1136.001',
        name: 'Create Account: Local Account',
        description: 'Adversaries may create local accounts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1136/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net user /add')) {
                    return true;
                }
                if (eid === '4720' && event.TargetUserName && !event.TargetDomainName) {
                    return true; // Local account creation
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('local account creation');
        }
    },
    {
        id: 'T1136.002',
        name: 'Create Account: Domain Account',
        description: 'Adversaries may create domain accounts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1136/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net user /add /domain')) {
                    return true;
                }
                if (eid === '4720' && event.TargetDomainName) {
                    return true; // Domain account creation
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain account creation');
        }
    },
    {
        id: 'T1136.003',
        name: 'Create Account: Cloud Account',
        description: 'Adversaries may create cloud accounts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1136/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cloud account')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud account creation');
        }
    },
    // T1543 - Create or Modify System Process
    {
        id: 'T1543',
        name: 'Create or Modify System Process',
        description: 'Adversaries may create or modify system processes for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sc create')) {
                    return true;
                }
                if (eid === '7045' && event.ServiceName) {
                    return true; // Service creation
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system process');
        }
    },
    {
        id: 'T1543.001',
        name: 'Create or Modify System Process: Launch Agent',
        description: 'Adversaries may create or modify launch agents for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('launch agent')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.plist/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('launch agent');
        }
    },
    {
        id: 'T1543.002',
        name: 'Create or Modify System Process: Systemd Service',
        description: 'Adversaries may create or modify systemd services for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('systemctl')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.service/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('systemd service');
        }
    },
    {
        id: 'T1543.003',
        name: 'Create or Modify System Process: Windows Service',
        description: 'Adversaries may create or modify Windows services for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sc create')) {
                    return true;
                }
                if (eid === '7045' && event.ServiceName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('windows service');
        }
    },
    {
        id: 'T1543.004',
        name: 'Create or Modify System Process: Launch Daemon',
        description: 'Adversaries may create or modify launch daemons for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('launch daemon')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.plist/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('launch daemon');
        }
    },
    // T1548 - Abuse Elevation Control Mechanism
    {
        id: 'T1548',
        name: 'Abuse Elevation Control Mechanism',
        description: 'Adversaries may abuse elevation control mechanisms for persistence.',
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
        description: 'Adversaries may use setuid/setgid for persistence.',
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
        description: 'Adversaries may bypass UAC for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/002/',
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
        id: 'T1548.003',
        name: 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching',
        description: 'Adversaries may abuse sudo for persistence.',
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
        description: 'Adversaries may use elevated execution with prompt for persistence.',
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
        description: 'Adversaries may use temporary elevated cloud access for persistence.',
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
        description: 'Adversaries may modify sudoers file for persistence.',
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
    // T1546 - Event Triggered Execution
    {
        id: 'T1546',
        name: 'Event Triggered Execution',
        description: 'Adversaries may establish persistence through event-triggered execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('event trigger')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('event trigger');
        }
    },
    {
        id: 'T1546.001',
        name: 'Event Triggered Execution: Change Default File Association',
        description: 'Adversaries may change file associations for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('assoc')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('fileexts')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('file association');
        }
    },
    {
        id: 'T1546.002',
        name: 'Event Triggered Execution: Screensaver',
        description: 'Adversaries may use screensavers for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('screensaver')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.scr/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('screensaver');
        }
    },
    {
        id: 'T1546.003',
        name: 'Event Triggered Execution: Windows Management Instrumentation Event Subscription',
        description: 'Adversaries may use WMI event subscriptions for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('wmic event')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('wmi event');
        }
    },
    {
        id: 'T1546.004',
        name: 'Event Triggered Execution: Unix Shell Configuration Modification',
        description: 'Adversaries may modify Unix shell configurations for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('.bashrc')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.bashrc|\.bash_profile/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('bashrc');
        }
    },
    {
        id: 'T1546.005',
        name: 'Event Triggered Execution: Trap',
        description: 'Adversaries may use trap commands for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('trap')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('trap');
        }
    },
    {
        id: 'T1546.006',
        name: 'Event Triggered Execution: LC_LOAD_DYLIB Addition',
        description: 'Adversaries may use LC_LOAD_DYLIB for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('lc_load_dylib')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('lc_load_dylib');
        }
    },
    {
        id: 'T1546.007',
        name: 'Event Triggered Execution: Netsh Helper DLL',
        description: 'Adversaries may use Netsh helper DLLs for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('netsh add helper')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('netsh helper');
        }
    },
    {
        id: 'T1546.008',
        name: 'Event Triggered Execution: Accessibility Features',
        description: 'Adversaries may use accessibility features for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sethc.exe')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('stickykeys')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('accessibility feature');
        }
    },
    {
        id: 'T1546.009',
        name: 'Event Triggered Execution: AppCert DLLs',
        description: 'Adversaries may use AppCert DLLs for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/009/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('appcert dll')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('appcertdlls')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('appcert dll');
        }
    },
    {
        id: 'T1546.010',
        name: 'Event Triggered Execution: AppInit DLLs',
        description: 'Adversaries may use AppInit DLLs for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/010/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('appinit dll')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('appinit_dlls')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('appinit dll');
        }
    },
    {
        id: 'T1546.011',
        name: 'Event Triggered Execution: Application Shimming',
        description: 'Adversaries may use application shimming for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/011/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sdbinst')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('application shimming');
        }
    },
    {
        id: 'T1546.012',
        name: 'Event Triggered Execution: Image File Execution Options Injection',
        description: 'Adversaries may use IFEO for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/012/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('image file execution options')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('ifeo')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('ifeo');
        }
    },
    {
        id: 'T1546.013',
        name: 'Event Triggered Execution: PowerShell Profile',
        description: 'Adversaries may use PowerShell profiles for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/013/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('powershell profile')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/profile\.ps1/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('powershell profile');
        }
    },
    {
        id: 'T1546.014',
        name: 'Event Triggered Execution: Emond',
        description: 'Adversaries may use emond for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/014/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('emond')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/emond/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('emond');
        }
    },
    {
        id: 'T1546.015',
        name: 'Event Triggered Execution: Component Object Model Hijacking',
        description: 'Adversaries may use COM hijacking for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/015/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('com hijacking')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('clsid')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('com hijacking');
        }
    },
    {
        id: 'T1546.016',
        name: 'Event Triggered Execution: Installer Packages',
        description: 'Adversaries may use installer packages for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/016/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('installer package')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.pkg/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('installer package');
        }
    },
    // T1574 - Hijack Execution Flow
    {
        id: 'T1574',
        name: 'Hijack Execution Flow',
        description: 'Adversaries may hijack execution flow for persistence.',
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
        description: 'Adversaries may use DLL search order hijacking for persistence.',
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
            return typeof event === 'string' && event && event.toLowerCase().includes('dll hijacking');
        }
    },
    {
        id: 'T1574.002',
        name: 'Hijack Execution Flow: DLL Side-Loading',
        description: 'Adversaries may use DLL side-loading for persistence.',
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
        description: 'Adversaries may use dylib hijacking for persistence.',
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
        description: 'Adversaries may use executable installers for persistence.',
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
        description: 'Adversaries may use dynamic linker hijacking for persistence.',
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
        description: 'Adversaries may manipulate PATH environment variable for persistence.',
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
        description: 'Adversaries may use search order hijacking for persistence.',
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
        description: 'Adversaries may exploit unquoted paths for persistence.',
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
        description: 'Adversaries may exploit service file permissions for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/010/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cacls') || commandLine.toLowerCase().includes('icacls')) {
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
        description: 'Adversaries may exploit service registry permissions for persistence.',
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
        description: 'Adversaries may use COR_PROFILER for persistence.',
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
        description: 'Adversaries may use KernelCallbackTable for persistence.',
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
        description: 'Adversaries may use AppDomainManager for persistence.',
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
    // T1098 - Account Manipulation
    {
        id: 'T1098',
        name: 'Account Manipulation',
        description: 'Adversaries may manipulate accounts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('net user') || 
                    commandLine.toLowerCase().includes('net group')) {
                    return true;
                }
                if (eid === '4720' || eid === '4738') {
                    return true; // User account creation or modification
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('account manipulation');
        }
    },
    {
        id: 'T1098.001',
        name: 'Account Manipulation: Additional Cloud Credentials',
        description: 'Adversaries may add cloud credentials for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cloud credential')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud credential');
        }
    },
    {
        id: 'T1098.002',
        name: 'Account Manipulation: Additional Email Delegate Permissions',
        description: 'Adversaries may add email delegate permissions for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('email delegate')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('email delegate');
        }
    },
    {
        id: 'T1098.003',
        name: 'Account Manipulation: Additional Cloud Roles',
        description: 'Adversaries may add cloud roles for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cloud role')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud role');
        }
    },
    {
        id: 'T1098.004',
        name: 'Account Manipulation: SSH Authorized Keys',
        description: 'Adversaries may modify SSH authorized keys for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('authorized_keys')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/authorized_keys/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('ssh authorized keys');
        }
    },
    {
        id: 'T1098.005',
        name: 'Account Manipulation: Device Registration',
        description: 'Adversaries may register devices for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('device registration')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('device registration');
        }
    },
    {
        id: 'T1098.006',
        name: 'Account Manipulation: Additional Container Cluster Roles',
        description: 'Adversaries may add container cluster roles for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('container cluster role')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('container cluster role');
        }
    },
    // T1197 - BITS Jobs
    {
        id: 'T1197',
        name: 'BITS Jobs',
        description: 'Adversaries may abuse BITS jobs for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1197/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('bitsadmin')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('bitsadmin');
        }
    },
    // T1611 - Escape to Host
    {
        id: 'T1611',
        name: 'Escape to Host',
        description: 'Adversaries may break out of containers to gain persistence on the host.',
        mitre_link: 'https://attack.mitre.org/techniques/T1611/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('docker escape') || 
                    commandLine.toLowerCase().includes('container breakout')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('container escape');
        }
    },
    // T1053 - Scheduled Task/Job
    {
        id: 'T1053',
        name: 'Scheduled Task/Job',
        description: 'Adversaries may abuse task scheduling for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('schtasks') || 
                    commandLine.toLowerCase().includes('at ') || 
                    commandLine.toLowerCase().includes('cron')) {
                    return true;
                }
                if (eid === '4698') {
                    return true; // Scheduled task creation
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('scheduled task');
        }
    },
    {
        id: 'T1053.002',
        name: 'Scheduled Task/Job: At',
        description: 'Adversaries may use the at command for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('at ')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('at command');
        }
    },
    {
        id: 'T1053.003',
        name: 'Scheduled Task/Job: Cron',
        description: 'Adversaries may use cron for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cron')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/crontab/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cron');
        }
    },
    {
        id: 'T1053.005',
        name: 'Scheduled Task/Job: Scheduled Task',
        description: 'Adversaries may use schtasks for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('schtasks /create')) {
                    return true;
                }
                if (eid === '4698') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('schtasks');
        }
    },
    {
        id: 'T1053.006',
        name: 'Scheduled Task/Job: Systemd Timers',
        description: 'Adversaries may use systemd timers for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('systemd timer')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.timer/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('systemd timer');
        }
    },
    {
        id: 'T1053.007',
        name: 'Scheduled Task/Job: Container Orchestration Job',
        description: 'Adversaries may use container orchestration jobs for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('kubectl create')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('container orchestration');
        }
    },
    // T1505 - Server Software Component
    {
        id: 'T1505',
        name: 'Server Software Component',
        description: 'Adversaries may abuse server software components for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1505/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('server component')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dll|\.so/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('server component');
        }
    },
    {
        id: 'T1505.001',
        name: 'Server Software Component: SQL Stored Procedures',
        description: 'Adversaries may abuse SQL stored procedures for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1505/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sp_addextendedproc')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('sql stored procedure');
        }
    },
    {
        id: 'T1505.002',
        name: 'Server Software Component: Transport Agent',
        description: 'Adversaries may abuse transport agents for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1505/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('transport agent')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('transport agent');
        }
    },
    {
        id: 'T1505.003',
        name: 'Server Software Component: Web Shell',
        description: 'Adversaries may use web shells for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1505/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('web shell')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.php|\.asp|\.aspx|\.jsp/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('web shell');
        }
    },
    {
        id: 'T1505.004',
        name: 'Server Software Component: IIS Components',
        description: 'Adversaries may abuse IIS components for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1505/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('iis component')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('iis component');
        }
    },
    {
        id: 'T1505.005',
        name: 'Server Software Component: Terminal Services DLL',
        description: 'Adversaries may abuse terminal services DLLs for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1505/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('terminal services dll')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('terminal services dll');
        }
    },
    // T1078 - Valid Accounts
    {
        id: 'T1078',
        name: 'Valid Accounts',
        description: 'Adversaries may use valid accounts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && event.TargetUserName) {
                    return true; // Successful or failed logon attempts
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('valid account');
        }
    },
    {
        id: 'T1078.001',
        name: 'Valid Accounts: Default Accounts',
        description: 'Adversaries may use default accounts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && 
                    event.TargetUserName?.toLowerCase().match(/administrator|guest/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('default account');
        }
    },
    {
        id: 'T1078.002',
        name: 'Valid Accounts: Domain Accounts',
        description: 'Adversaries may use domain accounts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && event.TargetDomainName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('domain account');
        }
    },
    {
        id: 'T1078.003',
        name: 'Valid Accounts: Local Accounts',
        description: 'Adversaries may use local accounts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && !event.TargetDomainName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('local account');
        }
    },
    {
        id: 'T1078.004',
        name: 'Valid Accounts: Cloud Accounts',
        description: 'Adversaries may use cloud accounts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cloud account')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud account');
        }
    },
    // T1133 - External Remote Services
    {
        id: 'T1133',
        name: 'External Remote Services',
        description: 'Adversaries may use external remote services for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1133/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '3' || eid === '5156') && 
                    event.DestinationHostname?.toLowerCase().includes('rdp') || 
                    event.DestinationPort === '3389') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('remote desktop');
        }
    },
    // T1137 - Office Application Startup
    {
        id: 'T1137',
        name: 'Office Application Startup',
        description: 'Adversaries may abuse Office application startup for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1137/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('office startup')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.docm|\.xlsm/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('office startup');
        }
    },
    {
        id: 'T1137.001',
        name: 'Office Application Startup: Office Template Macros',
        description: 'Adversaries may use Office template macros for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1137/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('office macro')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dotm/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('office macro');
        }
    },
    {
        id: 'T1137.002',
        name: 'Office Application Startup: Office Test',
        description: 'Adversaries may use Office test registry for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1137/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('office test')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('officetest')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('office test');
        }
    },
    {
        id: 'T1137.003',
        name: 'Office Application Startup: Outlook Forms',
        description: 'Adversaries may use Outlook forms for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1137/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('outlook form')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('outlook form');
        }
    },
    {
        id: 'T1137.004',
        name: 'Office Application Startup: Outlook Home Page',
        description: 'Adversaries may use Outlook home page for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1137/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('outlook home page')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('outlook\\homepage')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('outlook home page');
        }
    },
    {
        id: 'T1137.005',
        name: 'Office Application Startup: Outlook Rules',
        description: 'Adversaries may use Outlook rules for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1137/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('outlook rule')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('outlook rule');
        }
    },
    {
        id: 'T1137.006',
        name: 'Office Application Startup: Add-ins',
        description: 'Adversaries may use Office add-ins for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1137/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('office add-in')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.xll|\.wll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('office add-in');
        }
    }
	
];