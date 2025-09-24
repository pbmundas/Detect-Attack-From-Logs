const rules = [
    // T1053 - Scheduled Task/Job
    {
        id: 'T1053',
        name: 'Scheduled Task/Job',
        description: 'Adversaries may use scheduled tasks for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('schtasks')) {
                    return true;
                }
                if (eid === '4698' || eid === '7045') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('scheduled task');
        }
    },
    {
        id: 'T1053.005',
        name: 'Scheduled Task/Job: Scheduled Task',
        description: 'Adversaries may use Windows scheduled tasks for persistence.',
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
            return typeof event === 'string' && event && event.toLowerCase().includes('scheduled task create');
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
                if (eid === '7045' && event.ServiceName?.toLowerCase().includes('at')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('at job');
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
                if ((eid === '4624' || eid === '4672') && 
                    event.TargetUserName && !event.TargetUserName.toLowerCase().includes('system')) {
                    return true;
                }
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('net.exe') && 
                    commandLine.toLowerCase().includes('user')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && 
                (event.toLowerCase().includes('net user') || event.toLowerCase().includes('logon'));
        }
    },
    // T1133 - External Remote Services
    {
        id: 'T1133',
        name: 'External Remote Services',
        description: 'Adversaries may maintain persistence via external remote services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1133/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('rdp') || 
                    commandLine.toLowerCase().includes('ssh')) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/3389|22/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('remote services');
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
                if (eid === '4720') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('create account');
        }
    },
    // T1137 - Office Application Startup
    {
        id: 'T1137',
        name: 'Office Application Startup',
        description: 'Adversaries may use Office applications for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1137/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('winword.exe') || 
                     image.toLowerCase().includes('excel.exe') || 
                     commandLine.toLowerCase().includes('macro'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.docm|\.xlsm/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('office application');
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
                    commandLine.toLowerCase().includes('template macro')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dotm|\.xltm/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('template macro');
        }
    },
    {
        id: 'T1137.002',
        name: 'Office Application Startup: Office Test',
        description: 'Adversaries may use Office test for persistence.',
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
                    commandLine.toLowerCase().includes('svc')) {
                    return true;
                }
                if (eid === '7045') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system process');
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
                if (eid === '7045') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('windows service');
        }
    },
    // T1546 - Event Triggered Execution
    {
        id: 'T1546',
        name: 'Event Triggered Execution',
        description: 'Adversaries may establish persistence via event triggered execution.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('trigger')) {
                    return true;
                }
                if (eid === '4689' && event.ParentImage) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('event trigger');
        }
    },
    {
        id: 'T1546.001',
        name: 'Event Triggered Execution: Change Default File Association',
        description: 'Adversaries may modify file associations for persistence.',
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
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('filetype')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('file association');
        }
    },
    // T1547 - Boot or Logon Autostart Execution
    {
        id: 'T1547',
        name: 'Boot or Logon Autostart Execution',
        description: 'Adversaries may configure autostart for persistence.',
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
        description: 'Adversaries may use run keys or startup folder for persistence.',
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
                    commandLine.toLowerCase().includes('authpackage')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('authpackage')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('authentication package');
        }
    },
    {
        id: 'T1547.003',
        name: 'Boot or Logon Autostart Execution: Time Providers',
        description: 'Adversaries may use time providers for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('w32time')) {
                    return true;
                }
                if (eid === '7045' && event.ServiceName?.toLowerCase().includes('w32time')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('time provider');
        }
    },
    {
        id: 'T1547.004',
        name: 'Boot or Logon Autostart Execution: Winlogon Helper DLL',
        description: 'Adversaries may use Winlogon helper DLL for persistence.',
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
            return typeof event === 'string' && event && event.toLowerCase().includes('winlogon helper');
        }
    },
    {
        id: 'T1547.005',
        name: 'Boot or Logon Autostart Execution: Security Support Provider',
        description: 'Adversaries may use SSP for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('ssp')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('ssp')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('security support');
        }
    },
    {
        id: 'T1547.006',
        name: 'Boot or Logon Autostart Execution: Kernel Modules and Extensions',
        description: 'Adversaries may use kernel modules for persistence.',
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
                if (eid === '7045' && event.ServiceName?.toLowerCase().includes('kernel')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('kernel module');
        }
    },
    {
        id: 'T1547.007',
        name: 'Boot or Logon Autostart Execution: Re-opened Applications',
        description: 'Adversaries may use re-opened applications for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('reopen app')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('re-opened application');
        }
    },
    {
        id: 'T1547.008',
        name: 'Boot or Logon Autostart Execution: LSASS Driver',
        description: 'Adversaries may use LSASS driver for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/008/',
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
                if (eid === '7045' && event.ServiceName?.toLowerCase().includes('lsass')) {
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
                    commandLine.toLowerCase().includes('shortcut')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.lnk/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('shortcut modification');
        }
    },
    // T1548 - Abuse Elevation Control Mechanism
    {
        id: 'T1548',
        name: 'Abuse Elevation Control Mechanism',
        description: 'Adversaries may bypass elevation controls for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('bypassuac')) {
                    return true;
                }
                if (eid === '4672' && event.Privileges?.includes('SeDebugPrivilege')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('elevation control');
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
                    commandLine.toLowerCase().includes('bypassuac')) {
                    return true;
                }
                if (eid === '4672' && event.Privileges?.includes('SeDebugPrivilege')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('bypass uac');
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
                    commandLine.toLowerCase().includes('hijack')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('path')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('hijack execution');
        }
    },
    {
        id: 'T1574.001',
        name: 'Hijack Execution Flow: DLL Search Order Hijacking',
        description: 'Adversaries may hijack DLL search order for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('dll hijack')) {
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
                    commandLine.toLowerCase().includes('side-load')) {
                    return true;
                }
                if (eid === '7' && event.ImageLoaded?.toLowerCase().match(/\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dll side-loading');
        }
    },
    // T1619 - Cloud Administration Command
    {
        id: 'T1619',
        name: 'Cloud Administration Command',
        description: 'Adversaries may use cloud admin commands for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1619/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws|azure|gcloud/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/amazonaws\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud admin');
        }
    }
    // Additional techniques can be added for full coverage...
];
