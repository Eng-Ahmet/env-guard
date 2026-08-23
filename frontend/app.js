let selectedFiles = [];

const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const selectedFilesContainer = document.getElementById('selectedFilesContainer');
const fileChips = document.getElementById('fileChips');

// Drag and drop handlers
dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
        handleFilesSelected(Array.from(e.dataTransfer.files));
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFilesSelected(Array.from(e.target.files));
    }
});

function handleFilesSelected(files) {
    selectedFiles = files;
    fileChips.innerHTML = '';
    
    files.forEach(file => {
        const chip = document.createElement('div');
        chip.className = 'chip';
        chip.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        fileChips.appendChild(chip);
    });

    selectedFilesContainer.style.display = 'block';
}

function clearFiles() {
    selectedFiles = [];
    fileInput.value = '';
    selectedFilesContainer.style.display = 'none';
    document.getElementById('resultsContainer').style.display = 'none';
}

// Run audit request
async function runAudit() {
    if (selectedFiles.length === 0) return;

    const formData = new FormData();
    selectedFiles.forEach(file => {
        formData.append('files', file);
    });

    try {
        const res = await fetch('/api/v1/audit', {
            method: 'POST',
            body: formData
        });

        if (!res.ok) {
            const errData = await res.json();
            alert('Audit Error: ' + (errData.error || 'Server error'));
            return;
        }

        const data = await res.json();
        renderAuditResults(data);
    } catch (err) {
        alert('Audit failed: Could not connect to EnvGuard backend.');
    }
}

// Render audit output
function renderAuditResults(data) {
    document.getElementById('resultsContainer').style.display = 'block';
    
    // Metrics
    document.getElementById('metricFiles').textContent = data.total_files;
    document.getElementById('metricSecrets').textContent = data.total_secrets;
    document.getElementById('secretsCountBadge').textContent = data.total_secrets;
    document.getElementById('metricDrift').textContent = data.drift_matrix ? data.drift_matrix.length : 0;

    // Table 1: Secrets
    const secretsTbody = document.getElementById('secretsTableBody');
    secretsTbody.innerHTML = '';

    if (data.secret_detections && data.secret_detections.length > 0) {
        data.secret_detections.forEach(item => {
            const tr = document.createElement('tr');
            const sevClass = item.severity.toLowerCase();
            tr.innerHTML = `
                <td class="code-font">${escapeHtml(item.filename)}</td>
                <td class="code-font">${item.line_number}</td>
                <td class="code-font"><strong>${escapeHtml(item.key)}</strong></td>
                <td>${escapeHtml(item.secret_type)}</td>
                <td><span class="badge ${sevClass}">${item.severity}</span></td>
                <td class="code-font">${escapeHtml(item.masked_value)}</td>
            `;
            secretsTbody.appendChild(tr);
        });
    } else {
        secretsTbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: #10b981;">🎉 Zero secrets or credential leaks detected!</td></tr>`;
    }

    // Table 2: Drift Matrix
    renderDriftMatrix(data.files_parsed, data.drift_matrix);

    // Table 3: Syntax Errors
    const syntaxDiv = document.getElementById('syntaxList');
    syntaxDiv.innerHTML = '';
    let syntaxErrCount = 0;

    if (data.syntax_errors) {
        for (const [filename, errors] of Object.entries(data.syntax_errors)) {
            errors.forEach(err => {
                syntaxErrCount++;
                const item = document.createElement('div');
                item.className = 'syntax-item';
                item.style.padding = '0.5rem 0';
                item.innerHTML = `⚠️ <strong>${escapeHtml(filename)}</strong>: ${escapeHtml(err)}`;
                syntaxDiv.appendChild(item);
            });
        }
    }

    if (syntaxErrCount === 0) {
        syntaxDiv.innerHTML = `<p style="color: #10b981;">✅ All files parsed with 100% valid syntax!</p>`;
    }
}

// Render dynamic Drift Matrix Table
function renderDriftMatrix(files, rows) {
    const headerRow = document.getElementById('driftHeaderRow');
    headerRow.innerHTML = `<th>Environment Variable Key</th>`;

    files.forEach(f => {
        const th = document.createElement('th');
        th.textContent = f;
        headerRow.appendChild(th);
    });

    const tbody = document.getElementById('driftTableBody');
    tbody.innerHTML = '';

    if (!rows || rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="${files.length + 1}">No keys found.</td></tr>`;
        return;
    }

    rows.forEach(row => {
        const tr = document.createElement('tr');
        let html = `<td class="code-font"><strong>${escapeHtml(row.key)}</strong></td>`;

        files.forEach(f => {
            const exists = row.status[f];
            if (exists) {
                html += `<td><span style="color: #10b981; font-weight: bold;">✓ Present</span></td>`;
            } else {
                html += `<td><span style="color: #ef4444; font-weight: bold;">✗ Missing</span></td>`;
            }
        });

        tr.innerHTML = html;
        tbody.appendChild(tr);
    });
}

// Generate Sanitized .env.example
async function generateSanitized() {
    if (selectedFiles.length === 0) return;

    const formData = new FormData();
    formData.append('files', selectedFiles[0]); // Target primary file

    try {
        const res = await fetch('/api/v1/sanitize', {
            method: 'POST',
            body: formData
        });

        if (!res.ok) {
            alert('Failed to generate .env.example');
            return;
        }

        const data = await res.json();
        document.getElementById('sanitizedCodePreview').textContent = data.sanitized_content;
        document.getElementById('exampleModal').style.display = 'flex';
    } catch (err) {
        alert('Could not connect to backend.');
    }
}

function downloadSanitizedFile() {
    const text = document.getElementById('sanitizedCodePreview').textContent;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = '.env.example';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function closeModal() {
    document.getElementById('exampleModal').style.display = 'none';
}

function switchTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById(tabId).classList.add('active');
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
