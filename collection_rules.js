const rules = [
    // T1005 - Data from Local System
    {
        id: 'T1005',
        name: 'Data from Local System',
        description: 'Adversaries may search local system sources to find files of interest.',
        mitre_link: 'https://attack.mitre.org/techniques/T1005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/dir \/s|findstr|type c:\\users|cat \/etc\/passwd/)) {
                    return true;
                }
                if (eid === '11' && (event.TargetFilename || '').toLowerCase().match(/\\users\\|\\documents|\/etc\//)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('data from local system');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/copy [d-z]:\\|xcopy [d-z]:\\|robocopy [d-z]:/)) {
                    return true;
                }
                if (eid === '15' && (event.Device || '').toLowerCase().includes('removable')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('removable media');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/net use|copy \\\\server|xcopy \\\\share/)) {
                    return true;
                }
                if (eid === '3' && (event.DestinationPort || '') === '445') {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('network shared drive');
        }
    },
    // T1056 - Input Capture
    {
        id: 'T1056',
        name: 'Input Capture',
        description: 'Adversaries may capture user input to obtain credentials.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/keylogger|setwindowshookex/)) {
                    return true;
                }
                if (eid === '7' && (event.ImageLoaded || '').toLowerCase().match(/user32.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('input capture');
        }
    },
    // T1056.001 - Keylogging
    {
        id: 'T1056.001',
        name: 'Input Capture: Keylogging',
        description: 'Adversaries may log keystrokes.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/keylog|setkeyboardstate/)) {
                    return true;
                }
                if (eid === '13' && (event.TargetObject || '').toLowerCase().includes('keyboard')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('keylogging');
        }
    },
    // T1056.002 - GUI Input Capture
    {
        id: 'T1056.002',
        name: 'Input Capture: GUI Input Capture',
        description: 'Adversaries may mimic GUI to capture input.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/prompt cred|gui input/)) {
                    return true;
                }
                if (eid === '7' && (event.ImageLoaded || '').toLowerCase().match(/comdlg32.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('gui input capture');
        }
    },
    // T1056.003 - Web Portal Capture
    {
        id: 'T1056.003',
        name: 'Input Capture: Web Portal Capture',
        description: 'Adversaries may install code on web portals to capture input.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/form grab|web portal capture/)) {
                    return true;
                }
                if (eid === '3' && (event.DestinationPort || '') === '80' || (event.DestinationPort || '') === '443') {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('web portal capture');
        }
    },
    // T1056.004 - Credential API Hooking
    {
        id: 'T1056.004',
        name: 'Input Capture: Credential API Hooking',
        description: 'Adversaries may hook credential APIs to capture input.',
        mitre_link: 'https://attack.mitre.org/techniques/T1056/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/creduipromptforcredentials|api hook/)) {
                    return true;
                }
                if (eid === '7' && (event.ImageLoaded || '').toLowerCase().match(/secur32.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('credential api hooking');
        }
    },
    // T1074 - Data Staged
    {
        id: 'T1074',
        name: 'Data Staged',
        description: 'Adversaries may stage collected data in a central location prior to exfiltration.',
        mitre_link: 'https://attack.mitre.org/techniques/T1074/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/copy to %temp%|move to \/tmp/)) {
                    return true;
                }
                if (eid === '11' && (event.TargetFilename || '').toLowerCase().match(/\\temp\\|\/tmp\//)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('data staged');
        }
    },
    // T1074.001 - Local Data Staging
    {
        id: 'T1074.001',
        name: 'Data Staged: Local Data Staging',
        description: 'Adversaries may stage data locally.',
        mitre_link: 'https://attack.mitre.org/techniques/T1074/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/copy to c:\\staging/)) {
                    return true;
                }
                if (eid === '11' && (event.TargetFilename || '').toLowerCase().match(/staging/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('local data staging');
        }
    },
    // T1074.002 - Remote Data Staging
    {
        id: 'T1074.002',
        name: 'Data Staged: Remote Data Staging',
        description: 'Adversaries may stage data remotely.',
        mitre_link: 'https://attack.mitre.org/techniques/T1074/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/copy to \\\\remote/)) {
                    return true;
                }
                if (eid === '3' && (event.DestinationHostname || '').toLowerCase().includes('staging')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('remote data staging');
        }
    },
    // T1074.003 - Alternative Data Staging
    {
        id: 'T1074.003',
        name: 'Data Staged: Alternative Data Staging',
        description: 'Adversaries may use alternative methods to stage data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1074/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/copy to \/dev\/shm|use memory staging/)) {
                    return true;
                }
                if (eid === '11' && (event.TargetFilename || '').toLowerCase().match(/\/dev\/shm/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('alternative data staging');
        }
    },
    // T1113 - Screen Capture
    {
        id: 'T1113',
        name: 'Screen Capture',
        description: 'Adversaries may capture screen content.',
        mitre_link: 'https://attack.mitre.org/techniques/T1113/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/screenshot|printscreen|psr.exe/)) {
                    return true;
                }
                if (eid === '7' && (event.ImageLoaded || '').toLowerCase().match(/gdi32.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('screen capture');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/outlook|thunderbird|mail/)) {
                    return true;
                }
                if (eid === '3' && (event.DestinationPort || '').match(/143|110|25/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('email collection');
        }
    },
    // T1114.001 - Local Email Collection
    {
        id: 'T1114.001',
        name: 'Email Collection: Local Email Collection',
        description: 'Adversaries may collect email data from local systems.',
        mitre_link: 'https://attack.mitre.org/techniques/T1114/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/outlook.*\.pst|thunderbird.*profile/)) {
                    return true;
                }
                if (eid === '11' && (event.TargetFilename || '').toLowerCase().match(/\.pst|\.ost/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('local email collection');
        }
    },
    // T1114.002 - Remote Email Collection
    {
        id: 'T1114.002',
        name: 'Email Collection: Remote Email Collection',
        description: 'Adversaries may collect email data from remote servers.',
        mitre_link: 'https://attack.mitre.org/techniques/T1114/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/imap|pop3|smtp/)) {
                    return true;
                }
                if (eid === '3' && (event.DestinationPort || '').match(/143|110|25/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('remote email collection');
        }
    },
    // T1114.003 - Email Forwarding Rule
    {
        id: 'T1114.003',
        name: 'Email Collection: Email Forwarding Rule',
        description: 'Adversaries may create email forwarding rules to collect data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1114/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/new-inboxrule|set-inboxrule/)) {
                    return true;
                }
                if (eid === '3' && (event.DestinationHostname || '').toLowerCase().match(/outlook\.office|exchange/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('email forwarding rule');
        }
    },
    // T1115 - Clipboard Data
    {
        id: 'T1115',
        name: 'Clipboard Data',
        description: 'Adversaries may collect data stored in the clipboard.',
        mitre_link: 'https://attack.mitre.org/techniques/T1115/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/get-clipboard|clip.exe/)) {
                    return true;
                }
                if (eid === '7' && (event.ImageLoaded || '').toLowerCase().match(/ole32.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('clipboard data');
        }
    },
    // T1119 - Automated Collection
    {
        id: 'T1119',
        name: 'Automated Collection',
        description: 'Adversaries may use automated techniques for collection.',
        mitre_link: 'https://attack.mitre.org/techniques/T1119/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/for \/r|find . -type f|script collect/)) {
                    return true;
                }
                if (eid === '11' && (event.TargetFilename || '').toLowerCase().includes('collected')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('automated collection');
        }
    },
    // T1123 - Audio Capture
    {
        id: 'T1123',
        name: 'Audio Capture',
        description: 'Adversaries may capture audio using microphones.',
        mitre_link: 'https://attack.mitre.org/techniques/T1123/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/soundrecorder|arecord|ffmpeg -f audio/)) {
                    return true;
                }
                if (eid === '11' && (event.TargetFilename || '').toLowerCase().match(/\.wav|\.mp3/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('audio capture');
        }
    },
    // T1124 - System Time Discovery
    {
        id: 'T1124',
        name: 'System Time Discovery',
        description: 'Adversaries may collect system time information.',
        mitre_link: 'https://attack.mitre.org/techniques/T1124/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/date|time|w32tm \/query/)) {
                    return true;
                }
                if (eid === '7' && (event.ImageLoaded || '').toLowerCase().match(/kernel32.dll/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('system time discovery');
        }
    },
    // T1125 - Video Capture
    {
        id: 'T1125',
        name: 'Video Capture',
        description: 'Adversaries may capture video using cameras.',
        mitre_link: 'https://attack.mitre.org/techniques/T1125/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/ffmpeg -f video|cheese|webcam/)) {
                    return true;
                }
                if (eid === '11' && (event.TargetFilename || '').toLowerCase().match(/\.mp4|\.avi/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('video capture');
        }
    },
    // T1185 - Browser Session Hijacking
    {
        id: 'T1185',
        name: 'Browser Session Hijacking',
        description: 'Adversaries may hijack browser sessions.',
        mitre_link: 'https://attack.mitre.org/techniques/T1185/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/browser extension|man in browser/)) {
                    return true;
                }
                if (eid === '10' && image.match(/chrome|firefox|edge/) && (event.GrantedAccess || '').includes('0x1F3FFF')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('browser session hijacking');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/confluence|sharepoint|git/)) {
                    return true;
                }
                if (eid === '3' && (event.DestinationHostname || '').match(/confluence|sharepoint/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('information repositories');
        }
    },
    // T1213.001 - Confluence
    {
        id: 'T1213.001',
        name: 'Data from Information Repositories: Confluence',
        description: 'Adversaries may collect data from Confluence repositories.',
        mitre_link: 'https://attack.mitre.org/techniques/T1213/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.includes('confluence')) {
                    return true;
                }
                if (eid === '3' && (event.DestinationHostname || '').toLowerCase().includes('confluence')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('confluence');
        }
    },
    // T1213.002 - SharePoint
    {
        id: 'T1213.002',
        name: 'Data from Information Repositories: SharePoint',
        description: 'Adversaries may collect data from SharePoint repositories.',
        mitre_link: 'https://attack.mitre.org/techniques/T1213/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.includes('sharepoint')) {
                    return true;
                }
                if (eid === '3' && (event.DestinationHostname || '').toLowerCase().includes('sharepoint')) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('sharepoint');
        }
    },
    // T1213.003 - Code Repositories
    {
        id: 'T1213.003',
        name: 'Data from Information Repositories: Code Repositories',
        description: 'Adversaries may collect data from code repositories.',
        mitre_link: 'https://attack.mitre.org/techniques/T1213/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/git clone|svn checkout/)) {
                    return true;
                }
                if (eid === '3' && (event.DestinationHostname || '').toLowerCase().match(/github|bitbucket|gitlab/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('code repositories');
        }
    },
    // T1530 - Data from Cloud Storage
    {
        id: 'T1530',
        name: 'Data from Cloud Storage',
        description: 'Adversaries may collect data from cloud storage services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1530/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/aws s3 cp|gcloud storage cp/)) {
                    return true;
                }
                if (eid === '3' && (event.DestinationHostname || '').toLowerCase().match(/s3\.amazonaws\.com|storage\.googleapis\.com/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('cloud storage');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/zip|rar|7z|tar/)) {
                    return true;
                }
                if (eid === '11' && (event.TargetFilename || '').toLowerCase().match(/\.zip|\.rar|\.7z|\.tar/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('archive collected data');
        }
    },
    // T1560.001 - Archive via Utility
    {
        id: 'T1560.001',
        name: 'Archive Collected Data: Archive via Utility',
        description: 'Adversaries may use utilities to archive collected data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1560/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/winzip|7z|tar|zip|rar/)) {
                    return true;
                }
                if (eid === '11' && (event.TargetFilename || '').toLowerCase().match(/\.zip|\.rar|\.7z/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('archive via utility');
        }
    },
    // T1560.002 - Archive via Library
    {
        id: 'T1560.002',
        name: 'Archive Collected Data: Archive via Library',
        description: 'Adversaries may use libraries to archive collected data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1560/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/zlib|libzip/)) {
                    return true;
                }
                if (eid === '7' && (event.ImageLoaded || '').toLowerCase().match(/zlib|libzip/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('archive via library');
        }
    },
    // T1560.003 - Archive via Custom Method
    {
        id: 'T1560.003',
        name: 'Archive Collected Data: Archive via Custom Method',
        description: 'Adversaries may use custom methods to archive collected data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1560/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/archive.*custom|compress.*custom/)) {
                    return true;
                }
                if (eid === '11' && (event.TargetFilename || '').toLowerCase().match(/\.archive|\.compressed/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('archive via custom method');
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
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/snmpwalk|git clone/)) {
                    return true;
                }
                if (eid === '3' && (event.DestinationPort || '') === '161') {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('configuration repository');
        }
    },
    // T1602.001 - SNMP (MIB Dump)
    {
        id: 'T1602.001',
        name: 'Data from Configuration Repository: SNMP (MIB Dump)',
        description: 'Adversaries may collect SNMP Management Information Base (MIB) data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1602/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.includes('snmpwalk')) {
                    return true;
                }
                if (eid === '3' && (event.DestinationPort || '') === '161') {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('snmp');
        }
    },
    // T1602.002 - Network Device Configuration Dump
    {
        id: 'T1602.002',
        name: 'Data from Configuration Repository: Network Device Configuration Dump',
        description: 'Adversaries may collect network device configuration data.',
        mitre_link: 'https://attack.mitre.org/techniques/T1602/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toLowerCase();
            const commandLine = (event.CommandLine || event.Message || '').toLowerCase();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && commandLine.match(/show running-config|tftp/)) {
                    return true;
                }
                if (eid === '3' && (event.DestinationPort || '') === '69') {
                    return true;
                }
            }
            return typeof event === 'string' && event.toLowerCase().includes('network device configuration');
        }
    }
];
