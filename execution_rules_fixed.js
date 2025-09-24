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
        description: 'Adversaries may abuse Unix shell to execute commands.',
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
                     commandLine.toLowerCase().includes('bash'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('bash');
        }
    },
    {
        id: 'T1059.005',
        name: 'Command and Scripting Interpreter: Visual Basic',
        description: 'Adversaries may abuse Visual Basic scripts to execute malicious code.',
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
                     commandLine.toLowerCase().includes('vbscript'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.vbs')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('vbscript');
        }
    },
    {
        id: 'T1059.006',
        name: 'Command and Scripting Interpreter: Python',
        description: 'Adversaries may abuse Python to execute malicious code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('python') || 
                     commandLine.toLowerCase().includes('python'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.py')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('python');
        }
    },
    {
        id: 'T1059.007',
        name: 'Command and Scripting Interpreter: JavaScript',
        description: 'Adversaries may abuse JavaScript to execute malicious code.',
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
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.js')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('javascript');
        }
    },
    {
        id: 'T1059.008',
        name: 'Command and Scripting Interpreter: Network Device CLI',
        description: 'Adversaries may abuse network device CLI to execute commands.',
        mitre_link: 'https://attack.mitre.org/techniques/T1059/008/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('cli') || 
                     commandLine.toLowerCase().includes('router') || 
                     commandLine.toLowerCase().includes('switch'))) {
                    return true;
                }
                if (eid === '3' && event.DestinationPort?.toString().match(/22|23/)) {
                    return true; // SSH/Telnet connections
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('cli');
        }
    },
    // T1129 - Shared Modules
    {
        id: 'T1129',
        name: 'Shared Modules',
        description: 'Adversaries may execute malicious code via shared modules like DLLs.',
        mitre_link: 'https://attack.mitre.org/techniques/T1129/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('rundll32.exe')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.dll')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('rundll32');
        }
    },
    // T1053 - Scheduled Task/Job
    {
        id: 'T1053',
        name: 'Scheduled Task/Job',
        description: 'Adversaries may abuse scheduled tasks or jobs to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('schtasks.exe') || 
                     commandLine.toLowerCase().includes('schtasks'))) {
                    return true;
                }
                if (eid === '4698' && event.TaskName) {
                    return true; // Scheduled task creation
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('schtasks');
        }
    },
    {
        id: 'T1053.002',
        name: 'Scheduled Task/Job: At',
        description: 'Adversaries may use the at command to schedule tasks.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('at.exe') || 
                     commandLine.toLowerCase().includes('at '))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('at ');
        }
    },
    {
        id: 'T1053.005',
        name: 'Scheduled Task/Job: Scheduled Task',
        description: 'Adversaries may use scheduled tasks to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/005/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('schtasks.exe') || 
                     commandLine.toLowerCase().includes('schtasks'))) {
                    return true;
                }
                if (eid === '4698' && event.TaskName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('schtasks');
        }
    },
    {
        id: 'T1053.006',
        name: 'Scheduled Task/Job: Systemd Timers',
        description: 'Adversaries may use systemd timers to execute code on Linux.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/006/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('systemctl') && 
                    commandLine.toLowerCase().includes('timer')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.timer')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('systemctl timer');
        }
    },
    {
        id: 'T1053.007',
        name: 'Scheduled Task/Job: Container Orchestration Job',
        description: 'Adversaries may use container orchestration jobs to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1053/007/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('kubectl') || 
                     commandLine.toLowerCase().includes('cronjob'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('kubectl cronjob');
        }
    },
    // T1106 - Native API
    {
        id: 'T1106',
        name: 'Native API',
        description: 'Adversaries may use native APIs to execute malicious code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1106/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('createprocess') || 
                    commandLine.toLowerCase().includes('ntdll')) {
                    return true;
                }
                if (eid === '8' && event.TargetImage?.toLowerCase().includes('.exe')) {
                    return true; // Process creation via API
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('createprocess');
        }
    },
    // T1204 - User Execution
    {
        id: 'T1204',
        name: 'User Execution',
        description: 'Adversaries may rely on user execution to run malicious code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1204/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('malicious') || 
                    image.toLowerCase().match(/\.exe|\.docx|\.pdf/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.docx|\.pdf/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('malicious');
        }
    },
    {
        id: 'T1204.001',
        name: 'User Execution: Malicious Link',
        description: 'Adversaries may use malicious links to trick users into executing code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1204/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('url') && 
                    commandLine.toLowerCase().includes('malicious')) {
                    return true;
                }
                if (eid === '3' && event.DestinationHostname?.toString().includes('.')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('malicious url');
        }
    },
    {
        id: 'T1204.002',
        name: 'User Execution: Malicious File',
        description: 'Adversaries may use malicious files to trick users into executing code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1204/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    image.toLowerCase().match(/\.exe|\.docx|\.pdf/)) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().match(/\.exe|\.docx|\.pdf/)) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('malicious file');
        }
    },
    {
        id: 'T1204.003',
        name: 'User Execution: Malicious Image',
        description: 'Adversaries may use malicious container images to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1204/003/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('docker') || 
                    commandLine.toLowerCase().includes('container')) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('dockerfile')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('docker');
        }
    },
    // T1569 - System Services
    {
        id: 'T1569',
        name: 'System Services',
        description: 'Adversaries may abuse system services to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1569/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('sc.exe') || 
                     commandLine.toLowerCase().includes('sc create'))) {
                    return true;
                }
                if (eid === '7045' && event.ServiceName) {
                    return true; // Service creation
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('sc create');
        }
    },
    {
        id: 'T1569.001',
        name: 'System Services: Launchctl',
        description: 'Adversaries may use launchctl to execute code on macOS.',
        mitre_link: 'https://attack.mitre.org/techniques/T1569/001/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('launchctl') || 
                     commandLine.toLowerCase().includes('launchctl'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('.plist')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('launchctl');
        }
    },
    {
        id: 'T1569.002',
        name: 'System Services: Service Execution',
        description: 'Adversaries may execute code via system services.',
        mitre_link: 'https://attack.mitre.org/techniques/T1569/002/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('sc.exe') || 
                     commandLine.toLowerCase().includes('sc start'))) {
                    return true;
                }
                if (eid === '7045' && event.ServiceName) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('sc start');
        }
    },
    // T1047 - Windows Management Instrumentation
    {
        id: 'T1047',
        name: 'Windows Management Instrumentation',
        description: 'Adversaries may abuse WMI to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1047/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (image.toLowerCase().includes('wmiprvse.exe') || 
                     commandLine.toLowerCase().includes('wmic'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('wmic');
        }
    },
    // T1609 - Container Administration Command
    {
        id: 'T1609',
        name: 'Container Administration Command',
        description: 'Adversaries may abuse container administration commands to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1609/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('docker') || 
                     commandLine.toLowerCase().includes('kubectl'))) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('docker');
        }
    },
    // T1610 - Deploy Container
    {
        id: 'T1610',
        name: 'Deploy Container',
        description: 'Adversaries may deploy containers to execute malicious code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1610/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    (commandLine.toLowerCase().includes('docker run') || 
                     commandLine.toLowerCase().includes('kubectl apply'))) {
                    return true;
                }
                if (eid === '11' && event.TargetFilename?.toLowerCase().includes('dockerfile')) {
                    return true;
                }
            }
            return typeof event === 'string' && event && event.toLowerCase().includes('docker run');
        }
    },
    // T1203 - Exploitation for Client Execution
    {
        id: 'T1203',
        name: 'Exploitation for Client Execution',
        description: 'Adversaries may exploit software vulnerabilities to execute code.',
        mitre_link: 'https://attack.mitre.org/techniques/T1203/',
        detection: (event) => {
            if (!event) return false;
            const eid = event.EventID || event.EventId || '';
            const image = (event.Image || event.NewProcessName || event.TargetUserName || '').toString();
            const commandLine = (event.CommandLine || event.Message || '').toString();
            if (typeof event === 'object') {
                if ((eid === '1' || eid === '4688') && 
                    commandLine.toLowerCase().includes('exploit') || 
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
                    commandLine.toLowerCase().includes('com') || 
                    commandLine.toLowerCase().includes('dde')) {
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
];
