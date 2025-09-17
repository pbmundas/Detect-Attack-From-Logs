// Rules for threat hunting, mapped to MITRE techniques
        

        // Parse XML (for EVTX exported as XML)
        function parseXML(content) {
            const parser = new DOMParser();
            const xmlDoc = parser.parseFromString(content, 'text/xml');
            const events = [];
            const eventNodes = xmlDoc.getElementsByTagName('Event');
            for (let event of eventNodes) {
                const eventData = {};
                const system = event.getElementsByTagName('System')[0];
                if (system) {
                    const eventID = system.getElementsByTagName('EventID')[0];
                    eventData.EventID = eventID ? eventID.textContent : '';
                    const provider = system.getElementsByTagName('Provider')[0];
                    if (provider) {
                        eventData.Provider = provider.getAttribute('Name') || '';
                    }
                }
                const eventDataNode = event.getElementsByTagName('EventData')[0];
                if (eventDataNode) {
                    for (let data of eventDataNode.children) {
                        const name = data.getAttribute('Name');
                        eventData[name] = data.textContent;
                    }
                }
                eventData.Message = event.outerHTML;
                events.push(eventData);
            }
            return events;
        }

        // Parse CSV
        function parseCSV(content) {
            const lines = content.split('\n').filter(line => line.trim());
            const headers = lines[0].split(',').map(h => h.trim());
            const events = [];
            for (let i = 1; i < lines.length; i++) {
                const values = lines[i].split(',').map(v => v.trim());
                const event = {};
                headers.forEach((header, idx) => {
                    event[header] = values[idx] || '';
                });
                // Standardize EventID
                event.EventID = event.EventID || event.EventId || '';
                // If Payload exists, parse it to extract additional fields
                if (event.Payload) {
                    try {
                        const payload = JSON.parse(event.Payload);
                        const data = payload.EventData?.Data || [];
                        for (let item of data) {
                            const name = item['@Name'];
                            const text = item['#text'] || '';
                            if (name) {
                                event[name] = text;
                            }
                        }
                    } catch (e) {
                        console.error('Error parsing Payload:', e);
                    }
                }
                events.push(event);
            }
            return events;
        }

        // Parse LOG (plain text)
        function parseLog(content) {
            return content.split('\n').filter(line => line.trim());
        }

        // Handle EVTX (instruct user to convert to XML)
        function handleEVTX() {
            return '<p class="text-red-600 font-semibold">EVTX files are not directly supported in the browser. Please export the EVTX file to XML using Windows Event Viewer (File > Save As > XML) and upload the XML file.</p>';
        }

        // Hunt for threats
        function hunt(events, fileType) {
            const threats = [];
            for (let rule of rules) {
                const matches = events.filter(event => rule.detection(event));
                if (matches.length) {
                    threats.push({
                        technique: rule,
                        matches: matches.slice(0, 10) // Limit to 10 for brevity
                    });
                }
            }
            return threats;
        }

        // Generate HTML report
        function generateReport(threats) {
            let report = '<h2 class="text-2xl font-semibold text-gray-800 mb-4">Threat Hunt Report</h2>';
            if (!threats.length) {
                report += '<p class="text-gray-600">No threats detected based on current rules.</p>';
                return report;
            }
            for (let threat of threats) {
                const tech = threat.technique;
                report += `<div class="mb-6 p-4 bg-white rounded-lg shadow hover-scale">
                    <h3 class="text-xl font-bold text-blue-600">${tech.id} - ${tech.name}</h3>
                    <p class="text-gray-700">${tech.description}</p>
                    <p><a href="${tech.mitre_link}" target="_blank" class="text-blue-500 hover:underline">MITRE Link</a></p>
                    <h4 class="text-lg font-semibold text-gray-800 mt-2">Matches:</h4>
                    <ul class="list-disc ml-6 text-gray-700">`;
                for (let match of threat.matches) {
                    const formattedMatch = typeof match === 'object' ? JSON.stringify(match, null, 2).replace(/</g, '&lt;').replace(/>/g, '&gt;') : match;
                    report += `<li>${formattedMatch}</li>`;
                }
                report += '</ul></div>';
            }
            return report;
        }

        // Process uploaded file
        function processFile() {
            const fileInput = document.getElementById('fileInput');
            const file = fileInput.files[0];
            const reportDiv = document.getElementById('report');
            if (!file) {
                reportDiv.innerHTML = '<p class="text-red-600 font-semibold">Please select a file.</p>';
                return;
            }

            const ext = file.name.split('.').pop().toLowerCase();
            if (ext === 'evtx') {
                reportDiv.innerHTML = handleEVTX();
                return;
            }

            const reader = new FileReader();
            reader.onload = function(e) {
                const content = e.target.result;
                let events;
                try {
                    if (ext === 'xml') {
                        events = parseXML(content);
                    } else if (ext === 'csv') {
                        events = parseCSV(content);
                    } else if (ext === 'log') {
                        events = parseLog(content);
                    } else {
                        throw new Error('Unsupported file type. Please upload XML, CSV, or LOG files.');
                    }
                    const threats = hunt(events, ext);
                    const report = generateReport(threats);
                    reportDiv.innerHTML = report;
                    reportDiv.classList.add('fade-in');
                } catch (error) {
                    reportDiv.innerHTML = `<p class="text-red-600 font-semibold">Error: ${error.message}</p>`;
                }
            };
            reader.readAsText(file);
        }