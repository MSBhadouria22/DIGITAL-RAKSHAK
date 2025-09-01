// static/script.js (Final Dashboard Version)
document.getElementById('uploadForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const fileInput = document.getElementById('apkFile');
    const resultsDiv = document.getElementById('results');
    const loader = document.getElementById('loader');

    if (fileInput.files.length === 0) {
        alert("Please select a file to analyze.");
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    loader.style.display = 'block';
    resultsDiv.style.display = 'none';

    try {
        const response = await fetch('/analyze', { method: 'POST', body: formData });
        const data = await response.json();
        
        if (data.error) {
            alert(`Analysis Error: ${data.error}`);
            return;
        }

        // --- Populate Dashboard ---
        document.getElementById('report-filename').innerText = `Analysis Report for: ${data.filename}`;

        // Populate Score
        const scoreElement = document.getElementById('threat-score');
        scoreElement.innerText = data.threat_score;
        scoreElement.classList.remove('text-success', 'text-warning', 'text-danger');
        if (data.threat_score > 70) scoreElement.classList.add('text-danger');
        else if (data.threat_score > 40) scoreElement.classList.add('text-warning');
        else scoreElement.classList.add('text-success');

        // Populate Vulnerabilities and Behavior lists
        const vulnerabilitiesList = document.getElementById('vulnerabilities-list');
        const behaviorList = document.getElementById('behavior-list');
        vulnerabilitiesList.innerHTML = '';
        behaviorList.innerHTML = '';

        if (data.detailed_findings.length === 0) {
            vulnerabilitiesList.innerHTML = '<p class="text-success">✅ No significant vulnerabilities found.</p>';
        } else {
            data.detailed_findings.forEach(item => {
                let severityBadge = 'bg-secondary';
                if (item.severity === 'High') severityBadge = 'bg-danger';
                if (item.severity === 'Medium') severityBadge = 'bg-warning';

                const findingHTML = `
                    <div class="finding-item">
                        <strong>${item.finding}</strong> <span class="badge ${severityBadge}">${item.severity}</span>
                        <p class="text-muted small">${item.description}</p>
                    </div>`;

                if (item.type === 'Permission') {
                    vulnerabilitiesList.innerHTML += findingHTML;
                } else { // Behavior
                    behaviorList.innerHTML += findingHTML;
                }
            });
        }
        
        // Populate URLs
        const urlsList = document.getElementById('urls-list');
        urlsList.innerHTML = '';
        if (data.static_urls.length > 0) {
            data.static_urls.slice(0, 15).forEach(url => { // Show up to 15 URLs
                urlsList.innerHTML += `<div>${url}</div>`;
            });
        } else {
            urlsList.innerHTML = '<p class="text-success">✅ No embedded URLs found.</p>';
        }

        resultsDiv.style.display = 'block';

    } catch (error) {
        alert(`An unexpected error occurred: ${error.message}`);
        console.error('Error:', error);
    } finally {
        loader.style.display = 'none';
    }
});