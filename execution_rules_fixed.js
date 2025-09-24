const rules = [
    // T1059 - Command and Scripting Interpreter
    {
        id: 'T1059',
        name: 'Command and Scripting Interpreter',
        description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('cmd.exe') || 
                     image.toLowerCase().includes('powershell.exe') || 
                     image.toLowerCase().includes('bash') || 
                     image.toLowerCase().includes('python') || 
                     image.toLowerCase().includes('wscript.exe') || 
                     image.toLowerCase().includes('cscript.exe'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && 
                (event.toLowerCase().includes('cmd') || 
                 event.toLowerCase().includes('powershell') || 
                 event.toLowerCase().includes('bash') || 
                 event.toLowerCase().includes('python') || 
                 event.toLowerCase().includes('vbscript') || 
                 event.toLowerCase().includes('javascript'));
        }
    },
    {
        id: 'T1059.001',
        name: 'Command and Scripting Interpreter: PowerShell',
        description: 'Adversaries may abuse PowerShell to execute commands or scripts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('powershell.exe') || 
                     commandLine.toLowerCase().includes('powershell'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('powershell');
        }
    },
    {
        id: 'T1059.002',
        name: 'Command and Scripting Interpreter: AppleScript',
        description: 'Adversaries may abuse AppleScript to execute commands or scripts on macOS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('osascript') || 
                     commandLine.toLowerCase().includes('applescript'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('osascript');
        }
    },
    {
        id: 'T1059.003',
        name: 'Command and Scripting Interpreter: Windows Command Shell',
        description: 'Adversaries may abuse Windows Command Shell to execute commands.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('cmd.exe') || 
                     commandLine.toLowerCase().includes('cmd'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cmd');
        }
    },
    {
        id: 'T1059.004',
        name: 'Command and Scripting Interpreter: Unix Shell',
        description: 'Adversaries may abuse Unix shells to execute commands.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/004/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('bash') || 
                     image.toLowerCase().includes('sh') || 
                     image.toLowerCase().includes('zsh'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('bash');
        }
    },
    {
        id: 'T1059.005',
        name: 'Command and Scripting Interpreter: Visual Basic',
        description: 'Adversaries may abuse Visual Basic to execute commands or scripts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('wscript.exe') || 
                     image.toLowerCase().includes('cscript.exe') || 
                     commandLine.toLowerCase().includes('vba'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('vba');
        }
    },
    {
        id: 'T1059.006',
        name: 'Command and Scripting Interpreter: Python',
        description: 'Adversaries may abuse Python to execute commands or scripts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().includes('python')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('python');
        }
    },
    {
        id: 'T1059.007',
        name: 'Command and Scripting Interpreter: JavaScript',
        description: 'Adversaries may abuse JavaScript to execute commands or scripts.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('wscript.exe') || 
                     image.toLowerCase().includes('cscript.exe') || 
                     commandLine.toLowerCase().includes('javascript'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('javascript');
        }
    },
    // T1072 - Software Deployment Tools
    {
        id: 'T1072',
        name: 'Software Deployment Tools',
        description: 'Adversaries may gain execution and maintain persistence using software deployment tools.',
        mitre_link: 'https://attack.mitre.org/techniques/T1072/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('msiexec') || 
                     commandLine.toLowerCase().includes('sccm') || 
                     commandLine.toLowerCase().includes('psexec'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.msi')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('msiexec');
        }
    },
    // T1106 - Native API
    {
        id: 'T1106',
        name: 'Native API',
        description: 'Adversaries may interact with the native OS API to execute behaviors.',
        mitre_link: 'https://attack.mitre.org/techniques/T1106/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('createprocess') || 
                    commandLine.toLowerCase().includes('loadlibrary')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('native api');
        }
    },
    // T1127 - Trusted Developer Utilities
    {
        id: 'T1127',
        name: 'Trusted Developer Utilities',
        description: 'Adversaries may take advantage of trusted developer utilities to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1127/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('msbuild.exe') || 
                     image.toLowerCase().includes('csc.exe'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('msbuild');
        }
    },
    // T1129 - Shared Modules
    {
        id: 'T1129',
        name: 'Shared Modules',
        description: 'Adversaries may execute malicious payloads via loading shared modules.',
        mitre_link: 'https://attack.mitre.org/techniques/T1129/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('loadlibrary')) {
                    return true;
                }
                if (eid === '7' && event.ImageLoaded?.toLowerCase().includes('.dll')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('shared modules');
        }
    },
    // T1137 - Office Application Startup
    {
        id: 'T1137',
        name: 'Office Application Startup',
        description: 'Adversaries may abuse Office applications to execute malicious code.',
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
    // T1140 - Deobfuscate/Decode Files or Information
    {
        id: 'T1140',
        name: 'Deobfuscate/Decode Files or Information',
        description: 'Adversaries may decode or deobfuscate payloads to execute them.',
        mitre_link: 'https://attack.mitre.org/techniques/T1140/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('decode') || 
                     commandLine.toLowerCase().includes('deobfuscate'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('decode');
        }
    },
    // T1183 - Image Execution
    {
        id: 'T1183',
        name: 'Image Execution',
        description: 'Adversaries may execute malicious images to deliver malicious code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1183/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('mspaint.exe') || 
                     commandLine.toLowerCase().includes('image'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.jpg|\.png/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('image execution');
        }
    },
    // T1190 - Exploit Public-Facing Application
    {
        id: 'T1190',
        name: 'Exploit Public-Facing Application',
        description: 'Adversaries may exploit public-facing applications to gain access.',
        mitre_link: 'https://attack.mitre.org/techniques/T1190/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('cve')) {
                    return true;
                }
                if (eid === '1116' && event.Message?.toLowerCase().includes('exploit')) {
                    return true; // Microsoft Defender exploit detection
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('exploit');
        }
    },
    // T1559 - Inter-Process Communication
    {
        id: 'T1559',
        name: 'Inter-Process Communication',
        description: 'Adversaries may use inter-process communication to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1559/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('com') || 
                     commandLine.toLowerCase().includes('dde'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('com');
        }
    },
    {
        id: 'T1559.001',
        name: 'Inter-Process Communication: Component Object Model',
        description: 'Adversaries may use COM to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1559/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('mmc.exe') || 
                     commandLine.toLowerCase().includes('com'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('com');
        }
    },
    {
        id: 'T1559.002',
        name: 'Inter-Process Communication: Dynamic Data Exchange',
        description: 'Adversaries may use DDE to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1559/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('dde')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.docx')) {
                    return true; // DDE often used in Office documents
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('dde');
        }
    },
    // T1620 - Software Deployment Tools
    {
        id: 'T1620',
        name: 'Software Deployment Tools',
        description: 'Adversaries may use software deployment tools to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1620/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('msiexec') || 
                     commandLine.toLowerCase().includes('sccm'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.msi')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('msiexec');
        }
    }
    // Additional techniques and sub-techniques can be added for full coverage...
];
