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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            const parentImage = (event.ParentImage || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('reg add') || commandLine.includes('autostart') || commandLine.includes('startup') || 
                     commandLine.includes('boot') || parentImage.includes('powershell.exe'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().match(/run|startup|boot/)) { // Expanded registry keys
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('startup')) { // File creation in startup
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('autostart');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('hkcu\\software\\microsoft\\windows\\currentversion\\run') || 
                     commandLine.includes('hklm\\software\\microsoft\\windows\\currentversion\\run') || 
                     commandLine.includes('runonce') || commandLine.includes('startup folder'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().match(/run|runonce|startup/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/startup|start menu/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('run key');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('authentication package') || commandLine.includes('lsa') || commandLine.includes('security package'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().match(/authenticationpackages|lsp/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('authentication package');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('time provider') || commandLine.includes('w32tm') || commandLine.includes('ntp'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().match(/timeproviders|w32time/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('time provider');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('winlogon') || commandLine.includes('notify') || commandLine.includes('shell'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().match(/winlogon|notify/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('winlogon');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('security support provider') || commandLine.includes('ssp') || commandLine.includes('securitypackages'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().match(/securitypackages|ssp/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('security support provider');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('kernel module') || commandLine.includes('insmod') || commandLine.includes('modprobe') || commandLine.includes('driver load'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.sys|\.ko/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('kernel module');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('re-opened application') || commandLine.includes('reopen') || commandLine.includes('loginitems'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('reopen')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('re-opened application');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('lsass driver') || commandLine.includes('lsass') || commandLine.includes('load driver'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.sys/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('lsass driver');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('shortcut modification') || commandLine.includes('lnk') || commandLine.includes('modify shortcut'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.lnk/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('shortcut modification');
        }
    },
    // T1547.010 - Boot or Logon Autostart Execution: Port Monitors
    {
        id: 'T1547.010',
        name: 'Boot or Logon Autostart Execution: Port Monitors',
        description: 'Adversaries may configure port monitors for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/010/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('port monitor') || commandLine.includes('add-portmonitor') || commandLine.includes('spooler'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('portmonitors')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('port monitor');
        }
    },
    // T1547.012 - Boot or Logon Autostart Execution: Print Processors
    {
        id: 'T1547.012',
        name: 'Boot or Logon Autostart Execution: Print Processors',
        description: 'Adversaries may configure print processors for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/012/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('print processor') || commandLine.includes('add-printprocessor') || commandLine.includes('spoolsv'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('printprocessors')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('print processor');
        }
    },
    // T1547.013 - Boot or Logon Autostart Execution: XDG Autostart Entries
    {
        id: 'T1547.013',
        name: 'Boot or Logon Autostart Execution: XDG Autostart Entries',
        description: 'Adversaries may use XDG autostart entries for persistence on Linux.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/013/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('xdg') || commandLine.includes('autostart') || commandLine.includes('desktop entry'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.desktop/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('xdg');
        }
    },
    // T1547.014 - Boot or Logon Autostart Execution: Active Setup
    {
        id: 'T1547.014',
        name: 'Boot or Logon Autostart Execution: Active Setup',
        description: 'Adversaries may use Active Setup for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/014/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('active setup') || commandLine.includes('stubpath'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('activesetup')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('active setup');
        }
    },
    // T1547.015 - Boot or Logon Autostart Execution: Login Items
    {
        id: 'T1547.015',
        name: 'Boot or Logon Autostart Execution: Login Items',
        description: 'Adversaries may use login items for persistence on macOS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/015/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('login item') || commandLine.includes('system preferences') || commandLine.includes('loginitems'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('loginitems')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('login item');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('sc create') || commandLine.includes('new-service') || commandLine.includes('systemd'))) {
                    return true;
                }
                if (eid === '7045' && event.ServiceName) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('sc create');
        }
    },
    {
        id: 'T1543.001',
        name: 'Create or Modify System Process: Launch Agent',
        description: 'Adversaries may create or modify launch agents for persistence on macOS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('launchctl') || commandLine.includes('launch agent') || commandLine.includes('plist'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.plist/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('launch agent');
        }
    },
    {
        id: 'T1543.002',
        name: 'Create or Modify System Process: Systemd Service',
        description: 'Adversaries may create or modify systemd services for persistence on Linux.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('systemctl') || commandLine.includes('systemd service') || commandLine.includes('enable'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.service/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('systemd service');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('sc create') || commandLine.includes('new-service') || commandLine.includes('installutil'))) {
                    return true;
                }
                if (eid === '7045' && event.ServiceName && event.ImagePath?.includes('.exe')) { // Service with executable path
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('sc create');
        }
    },
    {
        id: 'T1543.004',
        name: 'Create or Modify System Process: Launch Daemon',
        description: 'Adversaries may create or modify launch daemons for persistence on macOS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1543/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('launch daemon') || commandLine.includes('launchctl') || commandLine.includes('daemon plist'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.plist/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('launch daemon');
        }
    },
    // T1546 - Event Triggered Execution
    {
        id: 'T1546',
        name: 'Event Triggered Execution',
        description: 'Adversaries may establish persistence using event triggers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('event trigger') || commandLine.includes('wmi event') || commandLine.includes('notify'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('notify')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('event trigger');
        }
    },
    {
        id: 'T1546.001',
        name: 'Event Triggered Execution: Change Default File Association',
        description: 'Adversaries may change default file associations for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('file association') || commandLine.includes('assoc') || commandLine.includes('ftype'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('classes\\')) { // ProgID changes
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('file association');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('screensaver') || commandLine.includes('scr'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('screensaver')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.scr/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('screensaver');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('wmi subscription') || commandLine.includes('wmic create') || commandLine.includes('eventconsumer'))) {
                    return true;
                }
                if (eid === '5859' && event.FilterName) { // WMI subscription creation
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('wmi subscription');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('shell config') || commandLine.includes('bashrc') || commandLine.includes('profile') || commandLine.includes('echo >>'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.bashrc|\.bash_profile|\.profile/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('bashrc');
        }
    },
    {
        id: 'T1546.005',
        name: 'Event Triggered Execution: Trap',
        description: 'Adversaries may use trap command for persistence on Unix.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('trap') || commandLine.includes('signal handler'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('trap');
        }
    },
    {
        id: 'T1546.006',
        name: 'Event Triggered Execution: LC_LOAD_DYLIB Addition',
        description: 'Adversaries may add LC_LOAD_DYLIB for persistence on macOS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('lc_load_dylib') || commandLine.includes('install_name_tool') || commandLine.includes('dylib'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dylib/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('lc_load_dylib');
        }
    },
    {
        id: 'T1546.007',
        name: 'Event Triggered Execution: Netsh Helper DLL',
        description: 'Adversaries may use netsh helper DLLs for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('netsh add helper') || commandLine.includes('netsh helper dll'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('netsh\\helpers')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('netsh helper');
        }
    },
    {
        id: 'T1546.008',
        name: 'Event Triggered Execution: Accessibility Features',
        description: 'Adversaries may replace accessibility features for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('sethc.exe') || commandLine.includes('utilman.exe') || commandLine.includes('magnify.exe') || commandLine.includes('sticky keys'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('debugger')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('sticky keys');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('appcert dll') || commandLine.includes('appcertdlls'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('appcertdlls')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('appcert dll');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('appinit dll') || commandLine.includes('appinit_dlls'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('appinit_dlls')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('appinit dll');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('sdbinst') || commandLine.includes('shim database'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.sdb/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('sdbinst');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('ifeo') || commandLine.includes('debugger') || commandLine.includes('image file execution options'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('debugger')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('ifeo');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('powershell profile') || commandLine.includes('profile.ps1'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/profile\.ps1/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('powershell profile');
        }
    },
    {
        id: 'T1546.014',
        name: 'Event Triggered Execution: Emond',
        description: 'Adversaries may use emond for persistence on macOS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/014/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('emond') || commandLine.includes('event monitor'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/rules\/.*\.plist/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('emond');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('com hijack') || commandLine.includes('clsid') || commandLine.includes('treatas'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().match(/clsid|treatas/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('com hijack');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('installer package') || commandLine.includes('pkg') || commandLine.includes('installer'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.pkg/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('installer package');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('hijack') || commandLine.includes('dll search order') || commandLine.includes('path interception'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('path')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('hijack');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('dll search order') || commandLine.includes('known dlls'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('knowndlls')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('dll search order');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('dll side-loading') || commandLine.includes('loadlibrary'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('dll side-loading');
        }
    },
    {
        id: 'T1574.004',
        name: 'Hijack Execution Flow: Dylib Hijacking',
        description: 'Adversaries may use dylib hijacking for persistence on macOS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('dylib hijacking') || commandLine.includes('dyld_insert_libraries'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dylib/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('dylib hijacking');
        }
    },
    {
        id: 'T1574.005',
        name: 'Hijack Execution Flow: Executable Installer File Permissions Weakness',
        description: 'Adversaries may exploit installer file permissions for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('installer permissions') || commandLine.includes('chmod') || commandLine.includes('icacls'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.msi|\.exe/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('installer permissions');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('ld_preload') || commandLine.includes('ld_library_path') || commandLine.includes('linker hijack'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('ld_preload')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('ld_preload');
        }
    },
    {
        id: 'T1574.007',
        name: 'Hijack Execution Flow: Path Interception by PATH Environment Variable',
        description: 'Adversaries may use PATH interception for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('path interception') || commandLine.includes('path=') || commandLine.includes('export path'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('path')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('path interception');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('search order hijacking') || commandLine.includes('safe dll search mode'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('safedllsearchmode')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('search order hijacking');
        }
    },
    {
        id: 'T1574.009',
        name: 'Hijack Execution Flow: Path Interception by Unquoted Path',
        description: 'Adversaries may use unquoted paths for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/009/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('unquoted path') || commandLine.match(/\s[a-z]:\\[a-z ]*\\ /i))) { // Unquoted paths with spaces
                    return true;
                }
                if (eid === '7045' && event.ImagePath?.match(/\s[a-z]:\\[a-z ]*\\ /i)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('unquoted path');
        }
    },
    {
        id: 'T1574.010',
        name: 'Hijack Execution Flow: Services File Permissions Weakness',
        description: 'Adversaries may exploit services file permissions for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/010/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('services permissions') || commandLine.includes('icacls') || commandLine.includes('cacls') || commandLine.includes('chmod'))) {
                    return true;
                }
                if (eid === '7045' && event.ImagePath?.includes('weak permissions')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('services permissions');
        }
    },
    {
        id: 'T1574.011',
        name: 'Hijack Execution Flow: Services Registry Permissions Weakness',
        description: 'Adversaries may exploit services registry permissions for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/011/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('services registry') || commandLine.includes('reg add') || commandLine.includes('icacls /grant'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('system\\currentcontrolset\\services')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('services registry');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('cor_profiler') || commandLine.includes('cor_enable_profiling'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('cor_profiler')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('cor_profiler');
        }
    },
    {
        id: 'T1574.013',
        name: 'Hijack Execution Flow: KernelCallbackTable',
        description: 'Adversaries may hijack KernelCallbackTable for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1574/013/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('kernelcallbacktable') || commandLine.includes('kcb'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('kernelcallbacktable');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('net user') || commandLine.includes('account manipulation') || commandLine.includes('passwd'))) {
                    return true;
                }
                if ((eid === '4722' || eid === '4724' || eid === '4738')) { // User enable/reset/change
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('account manipulation');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('cloud credentials') || commandLine.includes('aws access key') || commandLine.includes('az ad'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/amazonaws\.com|azure\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('cloud credentials');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('email delegate') || commandLine.includes('add-mailboxpermission'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('email delegate');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('cloud roles') || commandLine.includes('iam role') || commandLine.includes('az role'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('cloud roles');
        }
    },
    {
        id: 'T1098.004',
        name: 'Account Manipulation: SSH Authorized Keys',
        description: 'Adversaries may add SSH keys for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1098/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('ssh key') || commandLine.includes('authorized_keys') || commandLine.includes('ssh-add'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('authorized_keys')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('ssh key');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('device registration') || commandLine.includes('az device') || commandLine.includes('register-device'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('device registration');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('container roles') || commandLine.includes('kubectl create role') || commandLine.includes('clusterrole'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('container roles');
        }
    },
    // T1197 - BITS Jobs
    {
        id: 'T1197',
        name: 'BITS Jobs',
        description: 'Adversaries may use BITS jobs for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1197/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('bitsadmin') || commandLine.includes('bits job'))) {
                    return true;
                }
                if (eid === '59' || eid === '60') { // BITS job notifications
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('bitsadmin');
        }
    },
    // T1542 - Pre-OS Boot
    {
        id: 'T1542',
        name: 'Pre-OS Boot',
        description: 'Adversaries may modify pre-OS boot components for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1542/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('bootkit') || commandLine.includes('bios') || commandLine.includes('uefi'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('bootkit');
        }
    },
    {
        id: 'T1542.001',
        name: 'Pre-OS Boot: System Firmware',
        description: 'Adversaries may modify system firmware for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1542/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('system firmware') || commandLine.includes('bios flash') || commandLine.includes('uefi update'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('system firmware');
        }
    },
    {
        id: 'T1542.002',
        name: 'Pre-OS Boot: Component Firmware',
        description: 'Adversaries may modify component firmware for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1542/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('component firmware') || commandLine.includes('firmware update') || commandLine.includes('flash'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('component firmware');
        }
    },
    {
        id: 'T1542.003',
        name: 'Pre-OS Boot: Bootkit',
        description: 'Adversaries may use bootkits for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1542/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('bootkit') || commandLine.includes('mbr') || commandLine.includes('vbr'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('boot')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('bootkit');
        }
    },
    {
        id: 'T1542.004',
        name: 'Pre-OS Boot: ROMMONkit',
        description: 'Adversaries may use ROMMONkit for persistence on network devices.',
        mitre_link: 'https://attack.mitre.org/techniques/T1542/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('rommonkit') || commandLine.includes('rommon') || commandLine.includes('boot rom'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('rommonkit');
        }
    },
    {
        id: 'T1542.005',
        name: 'Pre-OS Boot: TFTP Boot',
        description: 'Adversaries may use TFTP boot for persistence on network devices.',
        mitre_link: 'https://attack.mitre.org/techniques/T1542/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('tftp boot') || commandLine.includes('tftp') || commandLine.includes('netboot'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().includes('69')) { // TFTP port
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('tftp boot');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('web shell') || commandLine.includes('sql trigger') || commandLine.includes('server component'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.jsp|\.asp|\.php/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('web shell');
        }
    },
    {
        id: 'T1505.001',
        name: 'Server Software Component: SQL Stored Procedures',
        description: 'Adversaries may use SQL stored procedures for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1505/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('sql procedure') || commandLine.includes('sp_addextendedproc') || commandLine.includes('create procedure'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('sql procedure');
        }
    },
    {
        id: 'T1505.002',
        name: 'Server Software Component: Transport Agent',
        description: 'Adversaries may use transport agents for persistence in email servers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1505/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('transport agent') || commandLine.includes('install-transportagent'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('transport agent');
        }
    },
    {
        id: 'T1505.003',
        name: 'Server Software Component: Web Shell',
        description: 'Adversaries may use web shells for persistence on web servers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1505/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('web shell') || commandLine.includes('cmd.asp') || commandLine.includes('eval request'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.asp|\.aspx|\.php|\.jsp/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('web shell');
        }
    },
    {
        id: 'T1505.004',
        name: 'Server Software Component: IIS Components',
        description: 'Adversaries may use IIS components for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1505/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('iis component') || commandLine.includes('appcmd') || commandLine.includes('iis module'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('iis component');
        }
    },
    {
        id: 'T1505.005',
        name: 'Server Software Component: Terminal Services DLL',
        description: 'Adversaries may use Terminal Services DLL for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1505/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('terminal services dll') || commandLine.includes('termsrv'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('termsrv')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('terminal services dll');
        }
    },
    // T1525 - Implant Internal Image
    {
        id: 'T1525',
        name: 'Implant Internal Image',
        description: 'Adversaries may implant cloud or container images for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1525/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('implant image') || commandLine.includes('docker push') || commandLine.includes('container registry'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('dockerfile')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('implant image');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('elevation control') || commandLine.includes('uac bypass') || commandLine.includes('sudo'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('uac')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('uac bypass');
        }
    },
    {
        id: 'T1548.001',
        name: 'Abuse Elevation Control Mechanism: Setuid and Setgid',
        description: 'Adversaries may use setuid/setgid for persistence on Unix.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('setuid') || commandLine.includes('setgid') || commandLine.includes('chmod 4'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('setuid');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('uac bypass') || commandLine.includes('cmstp') || commandLine.includes('fodhelper') || commandLine.includes('eventvwr'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('uac')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('uac bypass');
        }
    },
    {
        id: 'T1548.003',
        name: 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching',
        description: 'Adversaries may abuse sudo and caching for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1548/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('sudo') || commandLine.includes('sudoers') || commandLine.includes('visudo'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('sudoers')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('sudo');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('elevated execution') || commandLine.includes('osascript -e') || commandLine.includes('sudo'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('elevated execution');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('cloud access') || commandLine.includes('aws sts') || commandLine.includes('az role assignment'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('cloud access');
        }
    },
    // T1554 - Compromise Client Software Binary
    {
        id: 'T1554',
        name: 'Compromise Client Software Binary',
        description: 'Adversaries may compromise client software binaries for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1554/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('binary compromise') || commandLine.includes('patch binary') || commandLine.includes('modify exe'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('binary compromise');
        }
    },
    // T1556 - Modify Authentication Process
    {
        id: 'T1556',
        name: 'Modify Authentication Process',
        description: 'Adversaries may modify authentication processes for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('auth modification') || commandLine.includes('pam') || commandLine.includes('pluggable authentication'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('authentication')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('auth modification');
        }
    },
    {
        id: 'T1556.001',
        name: 'Modify Authentication Process: Domain Controller Authentication',
        description: 'Adversaries may modify DC authentication for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('dc auth') || commandLine.includes('kerberos') || commandLine.includes('ntlm'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('dc auth');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('password filter') || commandLine.includes('notificationpackages'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('notificationpackages')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('password filter');
        }
    },
    {
        id: 'T1556.003',
        name: 'Modify Authentication Process: Pluggable Authentication Modules',
        description: 'Adversaries may modify PAM for persistence on Linux.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('pam') || commandLine.includes('pluggable authentication') || commandLine.includes('pam.d'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('pam.d')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('pam');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('network auth') || commandLine.includes('aaa') || commandLine.includes('radius'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('network auth');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('reversible encryption') || commandLine.includes('set-aduser') || commandLine.includes('pwdproperties'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('reversible encryption');
        }
    },
    {
        id: 'T1556.006',
        name: 'Modify Authentication Process: Multi-Factor Authentication',
        description: 'Adversaries may disable or modify MFA for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('mfa') || commandLine.includes('multi-factor') || commandLine.includes('disable mfa'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('mfa');
        }
    },
    {
        id: 'T1556.007',
        name: 'Modify Authentication Process: Hybrid Identity',
        description: 'Adversaries may modify hybrid identity configurations for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('hybrid identity') || commandLine.includes('azure ad connect') || commandLine.includes('pass-through auth'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('hybrid identity');
        }
    },
    {
        id: 'T1556.008',
        name: 'Modify Authentication Process: Network Provider DLL',
        description: 'Adversaries may register malicious network provider DLLs.',
        mitre_link: 'https://attack.mitre.org/techniques/T1556/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('network provider dll') || commandLine.includes('npdll'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('networkprovider\\order')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('network provider dll');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('net user /add') || commandLine.includes('new-localuser') || commandLine.includes('adduser'))) {
                    return true;
                }
                if (eid === '4720' && event.TargetUserName) { // User creation
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('net user /add');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('net user /add') || commandLine.includes('new-localuser'))) {
                    return true;
                }
                if (eid === '4720' && !event.TargetDomainName) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('net user /add');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('net user /add /domain') || commandLine.includes('new-aduser'))) {
                    return true;
                }
                if (eid === '4720' && event.TargetDomainName) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('net user /add /domain');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('cloud account') || commandLine.includes('aws create-user') || commandLine.includes('az ad user create'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('cloud account');
        }
    },
    // T1037 - Boot or Logon Initialization Scripts
    {
        id: 'T1037',
        name: 'Boot or Logon Initialization Scripts',
        description: 'Adversaries may use initialization scripts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('logon script') || commandLine.includes('init script') || commandLine.includes('rc.local'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/rc\.local|\.sh/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('logon script');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('logon script') || commandLine.includes('userinit') || commandLine.includes('gpresult'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('userinit')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('logon script');
        }
    },
    {
        id: 'T1037.002',
        name: 'Boot or Logon Initialization Scripts: Login Hook',
        description: 'Adversaries may use login hooks for persistence on macOS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('login hook') || commandLine.includes('defaults write com.apple.loginwindow'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('login hook');
        }
    },
    {
        id: 'T1037.003',
        name: 'Boot or Logon Initialization Scripts: Network Device CLI',
        description: 'Adversaries may use network device CLI scripts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('network cli') || commandLine.includes('event manager') || commandLine.includes('tclsh'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('network cli');
        }
    },
    {
        id: 'T1037.004',
        name: 'Boot or Logon Initialization Scripts: RC Scripts',
        description: 'Adversaries may use RC scripts for persistence on Android.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('rc script') || commandLine.includes('init.rc'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('init.rc')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('rc script');
        }
    },
    {
        id: 'T1037.005',
        name: 'Boot or Logon Initialization Scripts: Startup Items',
        description: 'Adversaries may use startup items for persistence on macOS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1037/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('startup items') || commandLine.includes('loginitems') || commandLine.includes('system preferences'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('startupitems')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('startup items');
        }
    },
    // T1542.006 - Pre-OS Boot: Component Firmware (duplicate, skipped)
    // Assuming no duplicates in original, but adjust if needed

    // T1078 - Valid Accounts
    {
        id: 'T1078',
        name: 'Valid Accounts',
        description: 'Adversaries may use valid accounts for persistence.',
        mitre_link: 'https://attack.mitre.org/techniques/T1078/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625' || eid === '4672') && // Added privilege checks
                    event.TargetUserName && !event.TargetUserName.toLowerCase().includes('system') && event.LogonType?.match(/2|3|10/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('valid account');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && 
                    event.TargetUserName?.toLowerCase().match(/admin|guest|default|root/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('default account');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && event.TargetDomainName) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('domain account');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '4624' || eid === '4625') && !event.TargetDomainName) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('local account');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('cloud account') || commandLine.includes('aws login') || commandLine.includes('az login'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/aws\.amazon\.com|azure\.com|gcp\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('cloud account');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '3' || eid === '5156' || eid === '4624') && 
                    (event.DestinationHostname?.toLowerCase().includes('rdp') || event.DestinationPort === '3389' || event.DestinationPort === '1194' || // VPN
                     event.LogonType === '10')) { // Remote logon
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('remote desktop');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('office startup') || commandLine.includes('word / startup') || commandLine.includes('excel addin'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.docm|\.xlsm|\.pptm/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('office startup');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('office macro') || commandLine.includes('enablecontent') || commandLine.includes('automacro'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.dotm|\.xltm|\.potm/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('office macro');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('office test') || commandLine.includes('loadpoint'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('officetest')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('office test');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('outlook form') || commandLine.includes('custom form'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('outlook form');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('outlook home page') || commandLine.includes('webview'))) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('outlook\\homepage')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('outlook home page');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4103') && 
                    (commandLine.includes('outlook rule') || commandLine.includes('new-inboxrule'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('outlook rule');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString().toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toString().toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688' || eid === '4104') && 
                    (commandLine.includes('office add-in') || commandLine.includes('add-in') || commandLine.includes('vsto') || commandLine.includes('xll'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.xll|\.wll|\.vsto/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('office add-in');
        }
    }
];
