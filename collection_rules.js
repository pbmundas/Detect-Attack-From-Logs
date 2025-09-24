const rules = [
    // T1530 - Data from Cloud Storage
    {
        id: 'T1530',
        name: 'Data from Cloud Storage',
        description: 'Adversaries may collect data from cloud storage services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1530/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/aws s3 cp|gcloud storage cp/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/s3\.amazonaws\.com|storage\.googleapis\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cloud storage');
        }
    },
    // T1602 - Data from Configuration Repository
    {
        id: 'T1602',
        name: 'Data from Configuration Repository',
        description: 'Adversaries may collect data from configuration repositories.',
        mitre_link: 'https://attack.mitre.org/techniques/T1602/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/snmpwalk|git clone/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '161') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('configuration repository');
        }
    },
    {
        id: 'T1602.001',
        name: 'Data from Configuration Repository: SNMP (MIB Dump)',
        description: 'Adversaries may collect SNMP Management Information Base (MIB) data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1602/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('snmpwalk')) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '161') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('snmp');
        }
    },
    {
        id: 'T1602.002',
        name: 'Data from Configuration Repository: Network Device Configuration Dump',
        description: 'Adversaries may collect network device configuration data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1602/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/show running-config|tftp/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '69') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network device configuration');
        }
    },
    // T1213 - Data from Information Repositories
    {
        id: 'T1213',
        name: 'Data from Information Repositories',
        description: 'Adversaries may collect data from information repositories.',
        mitre_link: 'https://attack.mitre.org/techniques/T1213/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/confluence|sharepoint|git/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/confluence|sharepoint/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('information repositories');
        }
    },
    {
        id: 'T1213.001',
        name: 'Data from Information Repositories: Confluence',
        description: 'Adversaries may collect data from Confluence repositories.',
        mitre_link: 'https://attack.mitre.org/techniques/T1213/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('confluence')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().includes('confluence')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('confluence');
        }
    },
    {
        id: 'T1213.002',
        name: 'Data from Information Repositories: SharePoint',
        description: 'Adversaries may collect data from SharePoint repositories.',
        mitre_link: 'https://attack.mitre.org/techniques/T1213/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('sharepoint')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().includes('sharepoint')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('sharepoint');
        }
    },
    {
        id: 'T1213.003',
        name: 'Data from Information Repositories: Code Repositories',
        description: 'Adversaries may collect data from code repositories.',
        mitre_link: 'https://attack.mitre.org/techniques/T1213/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/git clone|git pull/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().match(/github\.com|gitlab\.com|bitbucket\.org/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('code repository');
        }
    },
    // T1005 - Data from Local System
    {
        id: 'T1005',
        name: 'Data from Local System',
        description: 'Adversaries may collect data from local systems.',
        mitre_link: 'https://attack.mitre.org/techniques/T1005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/copy.*documents|dir.*\.doc/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.doc|\.pdf|\.txt/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('data from local system');
        }
    },
    // T1039 - Data from Network Shared Drive
    {
        id: 'T1039',
        name: 'Data from Network Shared Drive',
        description: 'Adversaries may collect data from network shared drives.',
        mitre_link: 'https://attack.mitre.org/techniques/T1039/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/net use.*\\\\|copy.*\\\\|robocopy.*\\\\|smbclient/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '445') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('network shared drive');
        }
    },
    // T1025 - Data from Removable Media
    {
        id: 'T1025',
        name: 'Data from Removable Media',
        description: 'Adversaries may collect data from removable media.',
        mitre_link: 'https://attack.mitre.org/techniques/T1025/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/copy.*[a-z]:\\|robocopy.*[a-z]:/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/[a-z]:\\.*\.doc|[a-z]:\\.*\.pdf/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('removable media');
        }
    },
    // T1074 - Data Staged
    {
        id: 'T1074',
        name: 'Data Staged',
        description: 'Adversaries may stage collected data in a central location.',
        mitre_link: 'https://attack.mitre.org/techniques/T1074/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/copy.*temp|move.*staging/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/temp\\.*\.zip|staging\\.*\.zip/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('data staged');
        }
    },
    {
        id: 'T1074.001',
        name: 'Data Staged: Local Data Staging',
        description: 'Adversaries may stage data locally before exfiltration.',
        mitre_link: 'https://attack.mitre.org/techniques/T1074/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/copy.*temp|move.*temp/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('temp\\')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('local data staging');
        }
    },
    {
        id: 'T1074.002',
        name: 'Data Staged: Remote Data Staging',
        description: 'Adversaries may stage data on a remote system before exfiltration.',
        mitre_link: 'https://attack.mitre.org/techniques/T1074/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/copy.*\\\\|robocopy.*\\\\|scp/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString() === '445') {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('remote data staging');
        }
    },
    // T1119 - Automated Collection
    {
        id: 'T1119',
        name: 'Automated Collection',
        description: 'Adversaries may use scripts or tools for automated data collection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1119/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/powershell.*get-.*|python.*collect/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.ps1|\.py/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('automated collection');
        }
    },
    // T1185 - Browser Session Hijacking
    {
        id: 'T1185',
        name: 'Browser Session Hijacking',
        description: 'Adversaries may hijack browser sessions to collect data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1185/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/chrome.*--dump-dom|firefox.*session/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/cookies\.sqlite|sessionstore\.jsonlz4/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('browser session hijacking');
        }
    },
    // T1115 - Clipboard Data
    {
        id: 'T1115',
        name: 'Clipboard Data',
        description: 'Adversaries may collect data from the clipboard.',
        mitre_link: 'https://attack.mitre.org/techniques/T1115/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/clip|set-clipboard|get-clipboard/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('clipboard data');
        }
    },
    // T1123 - Audio Capture
    {
        id: 'T1123',
        name: 'Audio Capture',
        description: 'Adversaries may capture audio to collect data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1123/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/soundrecorder|ffmpeg.*audio/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.wav|\.mp3/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('audio capture');
        }
    },
    // T1113 - Screen Capture
    {
        id: 'T1113',
        name: 'Screen Capture',
        description: 'Adversaries may capture screenshots to collect data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1113/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/snippingtool|printscreen|scrot/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.png|\.jpg|\.jpeg/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('screen capture');
        }
    },
    // T1125 - Video Capture
    {
        id: 'T1125',
        name: 'Video Capture',
        description: 'Adversaries may capture video to collect data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1125/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/ffmpeg.*video|obs.*record/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.mp4|\.avi/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('video capture');
        }
    },
    // T1056 - Input Capture
    {
        id: 'T1056',
        name: 'Input Capture',
        description: 'Adversaries may capture user input to collect data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/keylogger|setwindowshook/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('keyboard')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('input capture');
        }
    },
    {
        id: 'T1056.001',
        name: 'Input Capture: Keylogging',
        description: 'Adversaries may log keyboard input to collect data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/keylogger|setwindowshookex/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('keyboard')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('keylogging');
        }
    },
    {
        id: 'T1056.002',
        name: 'Input Capture: GUI Input Capture',
        description: 'Adversaries may capture GUI input to collect data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/getforegroundwindow|mouse_event/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('gui input capture');
        }
    },
    {
        id: 'T1056.003',
        name: 'Input Capture: Web Portal Capture',
        description: 'Adversaries may capture input from web portals.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/web.*form|credential.*web/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/login|portal/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('web portal capture');
        }
    },
    {
        id: 'T1056.004',
        name: 'Input Capture: Credential API Hooking',
        description: 'Adversaries may hook credential APIs to collect data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/setwindowshook|credential.*hook/)) {
                    return true;
                }
                if (eid === '13' && event.TargetObject?.toLowerCase().includes('credential')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('credential api hooking');
        }
    },
    // T1114 - Email Collection
    {
        id: 'T1114',
        name: 'Email Collection',
        description: 'Adversaries may collect email data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1114/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/outlook|thunderbird|mail/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/outlook\.office|exchange/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('email collection');
        }
    },
    {
        id: 'T1114.001',
        name: 'Email Collection: Local Email Collection',
        description: 'Adversaries may collect email data from local systems.',
        mitre_link: 'https://attack.mitre.org/techniques/T1114/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/outlook.*\.pst|thunderbird.*profile/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.pst|\.ost/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('local email collection');
        }
    },
    {
        id: 'T1114.002',
        name: 'Email Collection: Remote Email Collection',
        description: 'Adversaries may collect email data from remote servers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1114/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/imap|pop3|smtp/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/143|110|25/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('remote email collection');
        }
    },
    {
        id: 'T1114.003',
        name: 'Email Collection: Email Forwarding Rule',
        description: 'Adversaries may create email forwarding rules to collect data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1114/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/new-inboxrule|set-inboxrule/)) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toLowerCase().match(/outlook\.office|exchange/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('email forwarding rule');
        }
    },
    // T1560 - Archive Collected Data
    {
        id: 'T1560',
        name: 'Archive Collected Data',
        description: 'Adversaries may archive collected data for exfiltration.',
        mitre_link: 'https://attack.mitre.org/techniques/T1560/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/zip|rar|7z|tar/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.zip|\.rar|\.7z|\.tar/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('archive collected data');
        }
    },
    {
        id: 'T1560.001',
        name: 'Archive Collected Data: Archive via Utility',
        description: 'Adversaries may use utilities to archive collected data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1560/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/winzip|7z|tar|zip|rar/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.zip|\.rar|\.7z/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('archive via utility');
        }
    },
    {
        id: 'T1560.002',
        name: 'Archive Collected Data: Archive via Library',
        description: 'Adversaries may use libraries to archive collected data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1560/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/zlib|libzip/)) {
                    return true;
                }
                if (eid === '7' && event.ImageLoaded?.toLowerCase().match(/zlib|libzip/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('archive via library');
        }
    },
    {
        id: 'T1560.003',
        name: 'Archive Collected Data: Archive via Custom Method',
        description: 'Adversaries may use custom methods to archive collected data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1560/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().match(/archive.*custom|compress.*custom/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.archive|\.compressed/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('archive via custom method');
        }
    }
];
