const rules = [
    // T1548 - Abuse Elevation Control Mechanism
    {
        id: 'T1548',
        name: 'Abuse Elevation Control Mechanism',
        description: 'Adversaries may abuse elevation control mechanisms to escalate privileges.',
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
        description: 'Adversaries may use setuid/setgid to escalate privileges.',
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
        description: 'Adversaries may bypass UAC to escalate privileges.',
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
        description: 'Adversaries may abuse sudo to escalate privileges.',
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
        description: 'Adversaries may use elevated execution with prompt to escalate privileges.',
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
        description: 'Adversaries may use temporary elevated cloud access to escalate privileges.',
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
        description: 'Adversaries may modify sudoers file to escalate privileges.',
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
    // T1134 - Access Token Manipulation
    {
        id: 'T1134',
        name: 'Access Token Manipulation',
        description: 'Adversaries may manipulate access tokens to escalate privileges.',
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
        description: 'Adversaries may impersonate or steal tokens to escalate privileges.',
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
        description: 'Adversaries may create processes with stolen tokens to escalate privileges.',
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
        description: 'Adversaries may create and impersonate tokens to escalate privileges.',
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
        description: 'Adversaries may spoof parent PIDs to escalate privileges.',
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
        description: 'Adversaries may inject SID history to escalate privileges.',
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
    // T1068 - Exploitation for Privilege Escalation
    {
        id: 'T1068',
        name: 'Exploitation for Privilege Escalation',
        description: 'Adversaries may exploit vulnerabilities to escalate privileges.',
        mitre_link: 'https://attack.mitre.org/techniques/T1068/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('exploit') || 
                    commandLine.toLowerCase().includes('cve-')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('privilege escalation exploit');
        }
    },
    // T1547 - Boot or Logon Autostart Execution
    {
        id: 'T1547',
        name: 'Boot or Logon Autostart Execution',
        description: 'Adversaries may configure autostart settings to escalate privileges.',
        mitre_link: 'https://attack.mitre.org/techniques/T1547/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('reg add') && 
                    commandLine.toLowerCase().includes('run')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('run')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('autostart');
        }
    },
    {
        id: 'T1547.001',
        name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder',
        description: 'Adversaries may use registry run keys or startup folder to escalate privileges.',
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
        description: 'Adversaries may modify authentication packages to escalate privileges.',
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
        description: 'Adversaries may modify time providers to escalate privileges.',
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
        description: 'Adversaries may use Winlogon helper DLLs to escalate privileges.',
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
        description: 'Adversaries may modify SSPs to escalate privileges.',
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
        description: 'Adversaries may load kernel modules to escalate privileges.',
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
        description: 'Adversaries may configure re-opened applications to escalate privileges.',
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
        description: 'Adversaries may use LSASS drivers to escalate privileges.',
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
        description: 'Adversaries may modify shortcuts to escalate privileges.',
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
        description: 'Adversaries may use port monitors to escalate privileges.',
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
        description: 'Adversaries may use print processors to escalate privileges.',
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
        description: 'Adversaries may use XDG autostart entries to escalate privileges.',
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
        description: 'Adversaries may use Active Setup to escalate privileges.',
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
        description: 'Adversaries may use initialization scripts to escalate privileges.',
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
        description: 'Adversaries may use Windows logon scripts to escalate privileges.',
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
        description: 'Adversaries may use macOS logon scripts to escalate privileges.',
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
        description: 'Adversaries may use network logon scripts to escalate privileges.',
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
        description: 'Adversaries may use RC scripts to escalate privileges.',
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
        description: 'Adversaries may use startup items to escalate privileges.',
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
    // T1543 - Create or Modify System Process
    {
        id: 'T1543',
        name: 'Create or Modify System Process',
        description: 'Adversaries may create or modify system processes to escalate privileges.',
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
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('system process');
        }
    },
    {
        id: 'T1543.001',
        name: 'Create or Modify System Process: Launch Agent',
        description: 'Adversaries may create or modify launch agents to escalate privileges.',
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
        description: 'Adversaries may create or modify systemd services to escalate privileges.',
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
        description: 'Adversaries may create or modify Windows services to escalate privileges.',
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
        description: 'Adversaries may create or modify launch daemons to escalate privileges.',
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
    // T1484 - Domain or Tenant Policy Modification
    {
        id: 'T1484',
        name: 'Domain or Tenant Policy Modification',
        description: 'Adversaries may modify domain or tenant policies to escalate privileges.',
        mitre_link: 'https://attack.mitre.org/techniques/T1484/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('gpedit') || 
                    commandLine.toLowerCase().includes('group policy')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('group policy');
        }
    },
    {
        id: 'T1484.001',
        name: 'Domain or Tenant Policy Modification: Group Policy Modification',
        description: 'Adversaries may modify group policies to escalate privileges.',
        mitre_link: 'https://attack.mitre.org/techniques/T1484/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('gpedit') || 
                    commandLine.toLowerCase().includes('group policy')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('group policy modification');
        }
    },
    {
        id: 'T1484.002',
        name: 'Domain or Tenant Policy Modification: Trust Provider Modification',
        description: 'Adversaries may modify trust providers to escalate privileges.',
        mitre_link: 'https://attack.mitre.org/techniques/T1484/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('trust provider')) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('trustprovider')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('trust provider');
        }
    },
    // T1611 - Escape to Host
    {
        id: 'T1611',
        name: 'Escape to Host',
        description: 'Adversaries may break out of containers to escalate privileges on the host.',
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
    // T1546 - Event Triggered Execution
    {
        id: 'T1546',
        name: 'Event Triggered Execution',
        description: 'Adversaries may use event-triggered execution to escalate privileges.',
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
        description: 'Adversaries may change file associations to escalate privileges.',
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
        description: 'Adversaries may use screensavers to escalate privileges.',
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
        description: 'Adversaries may use WMI event subscriptions to escalate privileges.',
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
        description: 'Adversaries may modify Unix shell configurations to escalate privileges.',
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
        description: 'Adversaries may use trap commands to escalate privileges.',
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
        description: 'Adversaries may use LC_LOAD_DYLIB to escalate privileges.',
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
        description: 'Adversaries may use Netsh helper DLLs to escalate privileges.',
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
        description: 'Adversaries may use accessibility features to escalate privileges.',
        mitre_link: 'https://attack.mitre.org/techniques/T1546/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sethc.exe') || 
                    commandLine.toLowerCase().includes('utilman.exe')) {
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
        description: 'Adversaries may use AppCert DLLs to escalate privileges.',
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
        description: 'Adversaries may use AppInit DLLs to escalate privileges.',
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
        description: 'Adversaries may use application shimming to escalate privileges.',
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
        description: 'Adversaries may use IFEO to escalate privileges.',
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
        description: 'Adversaries may use PowerShell profiles to escalate privileges.',
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
        description: 'Adversaries may use emond to escalate privileges.',
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
        description: 'Adversaries may use COM hijacking to escalate privileges.',
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
        description: 'Adversaries may use installer packages to escalate privileges.',
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
        description: 'Adversaries may hijack execution flow to escalate privileges.',
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
        description: 'Adversaries may use DLL search order hijacking to escalate privileges.',
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
        description: 'Adversaries may use DLL side-loading to escalate privileges.',
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
        description: 'Adversaries may use dylib hijacking to escalate privileges.',
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
        description: 'Adversaries may use executable installers for privilege escalation.',
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
        description: 'Adversaries may use dynamic linker hijacking for privilege escalation.',
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
        description: 'Adversaries may manipulate PATH environment variable for privilege escalation.',
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
        description: 'Adversaries may use search order hijacking for privilege escalation.',
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
        description: 'Adversaries may exploit unquoted paths for privilege escalation.',
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
        description: 'Adversaries may exploit service file permissions for privilege escalation.',
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
        description: 'Adversaries may exploit service registry permissions for privilege escalation.',
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
        description: 'Adversaries may use COR_PROFILER for privilege escalation.',
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
        description: 'Adversaries may use KernelCallbackTable for privilege escalation.',
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
        description: 'Adversaries may use AppDomainManager for privilege escalation.',
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
    // T1055 - Process Injection
    {
        id: 'T1055',
        name: 'Process Injection',
        description: 'Adversaries may inject code into processes to escalate privileges.',
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
        description: 'Adversaries may inject DLLs into processes to escalate privileges.',
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
        description: 'Adversaries may inject PEs into processes to escalate privileges.',
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
        description: 'Adversaries may hijack thread execution to escalate privileges.',
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
        description: 'Adversaries may use APC injection to escalate privileges.',
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
        description: 'Adversaries may use TLS callbacks for privilege escalation.',
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
        description: 'Adversaries may use ptrace to inject code and escalate privileges.',
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
        description: 'Adversaries may inject code via /proc memory to escalate privileges.',
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
        description: 'Adversaries may use extra window memory injection to escalate privileges.',
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
        description: 'Adversaries may use process hollowing to escalate privileges.',
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
        description: 'Adversaries may use process doppelgänging to escalate privileges.',
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
        description: 'Adversaries may use VDSO hijacking to escalate privileges.',
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
        description: 'Adversaries may use ListPlanting to escalate privileges.',
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
    // T1053 - Scheduled Task/Job
    {
        id: 'T1053',
        name: 'Scheduled Task/Job',
        description: 'Adversaries may abuse task scheduling for privilege escalation.',
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
        description: 'Adversaries may use the at command for privilege escalation.',
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
        description: 'Adversaries may use cron for privilege escalation.',
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
        description: 'Adversaries may use schtasks for privilege escalation.',
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
        description: 'Adversaries may use systemd timers for privilege escalation.',
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
        description: 'Adversaries may use container orchestration jobs for privilege escalation.',
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
    // T1078 - Valid Accounts
    {
        id: 'T1078',
        name: 'Valid Accounts',
        description: 'Adversaries may use valid accounts for privilege escalation.',
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
        description: 'Adversaries may use default accounts for privilege escalation.',
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
        description: 'Adversaries may use domain accounts for privilege escalation.',
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
        description: 'Adversaries may use local accounts for privilege escalation.',
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
        description: 'Adversaries may use cloud accounts for privilege escalation.',
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
    }
];