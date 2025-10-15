// Dashboard-specific JavaScript functionality

class DashboardManager {
    constructor(dashboardId) {
        this.dashboardId = dashboardId;
        this.currentSessionId = null;
        this.currentCsvData = null;
        this.init();
    }

    init() {
        this.setupPdfProcessing();
        this.setupAiChat();
        this.setupTableEditors();
        this.setupEventListeners();
    }

    setupPdfProcessing() {
        const pdfFileInput = document.getElementById('pdfFile');
        if (pdfFileInput) {
            pdfFileInput.addEventListener('change', this.handlePdfUpload.bind(this));
        }

        // Setup Google Sheets paste functionality
        const processSheetsBtn = document.getElementById('processSheetsData');
        const sheetsPasteArea = document.getElementById('sheetsPasteArea');
        
        if (processSheetsBtn && sheetsPasteArea) {
            processSheetsBtn.addEventListener('click', this.handleSheetsPaste.bind(this));
            sheetsPasteArea.addEventListener('paste', this.handleSheetsPaste.bind(this));
        }
    }

    setupAiChat() {
        const sendMessageBtn = document.getElementById('sendMessage');
        const chatInput = document.getElementById('chatInput');
        
        if (sendMessageBtn && chatInput) {
            sendMessageBtn.addEventListener('click', this.sendAiMessage.bind(this));
            chatInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.sendAiMessage();
                }
            });
        }

        const startAiBtn = document.getElementById('startAiProcessing');
        if (startAiBtn) {
            startAiBtn.addEventListener('click', this.startAiProcessing.bind(this));
        }
    }

    async setupTableEditors() {
        // Setup month dropdown first and get the selected month
        const selectedMonth = await this.setupMonthDropdown();
        
        // Initialize Handsontable for monthly expenses with the selected month
        this.initMonthlyTable(selectedMonth);
        
        // Initialize DataTables for yearly view
        this.initYearlyTable();
    }

    setupEventListeners() {
        // Tab change events
        const tabs = document.querySelectorAll('#dashboardTabs button[data-bs-toggle="tab"]');
        tabs.forEach(tab => {
            tab.addEventListener('shown.bs.tab', (event) => {
                const target = event.target.getAttribute('data-bs-target');
                if (target === '#monthly') {
                    // Get the currently selected month from dropdown and load data for that month
                    const dropdownButton = document.getElementById('monthDropdown');
                    if (dropdownButton) {
                        const selectedMonth = this.getSelectedMonthFromDropdown();
                        if (selectedMonth) {
                            this.refreshMonthlyData(selectedMonth);
                        } else {
                            // If no month selected yet, load data for the default month
                            this.refreshMonthlyData();
                        }
                    }
                } else if (target === '#yearly') {
                    this.refreshYearlyData();
                }
            });
        });
    }

    getSelectedMonthFromDropdown() {
        const dropdownButton = document.getElementById('monthDropdown');
        if (!dropdownButton) return null;
        
        // Extract month from dropdown button text
        const buttonText = dropdownButton.textContent.trim();
        const monthMatch = buttonText.match(/(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}/);
        if (monthMatch) {
            // Convert month name to YYYY-MM format
            const [monthName, year] = monthMatch[0].split(' ');
            const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
            const monthNum = (monthNames.indexOf(monthName) + 1).toString().padStart(2, '0');
            return `${year}-${monthNum}`;
        }
        return null;
    }

    async handlePdfUpload(event) {
        const file = event.target.files[0];
        if (!file || file.type !== 'application/pdf') {
            Utils.showNotification('Please select a valid PDF file', 'warning');
            return;
        }

        const uploadArea = document.getElementById('pdfUploadArea');
        const processingArea = document.getElementById('processingArea');
        const progressBar = processingArea.querySelector('.progress-bar');

        // Show processing UI
        uploadArea.classList.add('d-none');
        processingArea.classList.remove('d-none');

        try {
            // Set PDF.js worker
            pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.4.120/pdf.worker.min.js';

            // Load PDF
            const arrayBuffer = await file.arrayBuffer();
            const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
            
            let extractedText = '';
            
            // Extract text from each page
            for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
                progressBar.style.width = `${(pageNum / pdf.numPages) * 100}%`;
                
                const page = await pdf.getPage(pageNum);
                const textContent = await page.getTextContent();
                const pageText = textContent.items.map(item => item.str).join(' ');
                extractedText += pageText + '\n';
            }

            // Process extracted text to CSV
            const csvData = this.extractTablesFromText(extractedText);
            this.currentCsvData = csvData;
            
            // Show CSV preview
            this.showCsvPreview(csvData);
            
        } catch (error) {
            console.error('PDF processing error:', error);
            Utils.showNotification('Error processing PDF file', 'danger');
            this.resetUploadUI();
        }
    }

    async handleSheetsPaste(event) {
        let pastedData = '';
        
        if (event.type === 'paste') {
            // Get pasted data from clipboard
            pastedData = (event.clipboardData || window.clipboardData).getData('text');
        } else {
            // Get data from textarea
            const sheetsPasteArea = document.getElementById('sheetsPasteArea');
            pastedData = sheetsPasteArea.value.trim();
        }
        
        if (!pastedData) {
            Utils.showNotification('Please paste some data first', 'warning');
            return;
        }

        try {
            // Process Google Sheets data (tab-separated values)
            const csvData = this.convertSheetsToCsv(pastedData);
            this.currentCsvData = csvData;
            
            // Show CSV preview
            this.showCsvPreview(csvData);
            
            Utils.showNotification('Google Sheets data processed successfully', 'success');
        } catch (error) {
            console.error('Error processing Google Sheets data:', error);
            Utils.showNotification('Error processing Google Sheets data', 'danger');
        }
    }

    convertSheetsToCsv(sheetsData) {
        // Google Sheets data is typically tab-separated
        const lines = sheetsData.split('\n').filter(line => line.trim());
        const csvRows = [];
        
        // Add headers
        csvRows.push('Date,Description,Amount,Category');
        
        // Process each line
        lines.forEach(line => {
            const cells = line.split('\t').map(cell => cell.trim());
            
            if (cells.length >= 4) {
                const date = cells[0] || '';
                // Handle the case where there's an empty column between date and description
                let description = '';
                let amount = '';
                let category = '';
                
                // Find the description (first non-empty cell after date)
                for (let i = 1; i < cells.length; i++) {
                    const cell = cells[i];
                    if (cell && !cell.replace('.', '').replace('-', '').match(/^\d+$/)) {
                        description = cell;
                        break;
                    }
                }
                
                // Find amount (numeric value)
                for (let i = 1; i < cells.length; i++) {
                    const cell = cells[i].replace('$', '');
                    if (cell && cell.replace('.', '').replace('-', '').match(/^\d+$/)) {
                        amount = cell;
                        break;
                    }
                }
                
                // Find category (last non-empty cell)
                for (let i = cells.length - 1; i > 0; i--) {
                    const cell = cells[i];
                    if (cell && cell !== description && cell !== amount) {
                        category = cell;
                        break;
                    }
                }
                
                // Only add if we have at least a description or amount
                if (description || amount) {
                    csvRows.push(`"${date}","${description}","${amount}","${category}"`);
                }
            } else if (cells.length >= 3) {
                // Format: date, description, amount (no category)
                const date = cells[0] || '';
                const description = cells[1] || '';
                let amount = cells[2] || '';
                
                // Clean up amount - remove $ sign if present
                amount = amount.replace('$', '');
                
                if (description || amount) {
                    csvRows.push(`"${date}","${description}","${amount}",""`);
                }
            }
        });
        
        return csvRows.join('\n');
    }

    extractTablesFromText(text) {
        // Simple table extraction logic
        // This is a basic implementation - in production, you'd want more sophisticated parsing
        
        const lines = text.split('\n').filter(line => line.trim());
        const potentialTableRows = [];
        
        // Look for lines that might be table rows (contain numbers and consistent patterns)
        lines.forEach(line => {
            // Check if line contains date patterns and amounts
            const hasDate = /\d{1,2}\/\d{1,2}\/\d{2,4}/.test(line);
            const hasAmount = /\$\d+\.?\d*|USD\s*\d+\.?\d*/.test(line);
            const hasMultipleWords = line.trim().split(/\s+/).length >= 3;
            
            if ((hasDate || hasAmount) && hasMultipleWords) {
                potentialTableRows.push(line.trim());
            }
        });

        // Convert to CSV format
        if (potentialTableRows.length > 0) {
            const csvRows = ['Date,Description,Amount,Category'];
            
            potentialTableRows.forEach(row => {
                // Simple parsing - extract date, description, amount
                const dateMatch = row.match(/(\d{1,2}\/\d{1,2}\/\d{2,4})/);
                const amountMatch = row.match(/(\$\d+\.?\d*|USD\s*\d+\.?\d*)/);
                
                const date = dateMatch ? dateMatch[1] : '';
                const amount = amountMatch ? amountMatch[1].replace('USD', '').trim() : '';
                const description = row.replace(date || '', '').replace(amount || '', '').trim();
                
                if (date && amount && description) {
                    csvRows.push(`"${date}","${description}","${amount}",""`);
                }
            });
            
            return csvRows.join('\n');
        }
        
        // Fallback: return text as single column CSV
        return 'Description\n' + lines.map(line => `"${line}"`).join('\n');
    }

    showCsvPreview(csvData) {
        const processingArea = document.getElementById('processingArea');
        const csvPreviewArea = document.getElementById('csvPreviewArea');
        const previewTable = document.getElementById('csvPreviewTable');
        
        processingArea.classList.add('d-none');
        csvPreviewArea.classList.remove('d-none');
        
        // Parse CSV and create table preview
        const rows = csvData.split('\n');
        let tableHtml = '';
        
        rows.forEach((row, index) => {
            const cells = row.split(',').map(cell => cell.replace(/^"|"$/g, ''));
            tableHtml += '<tr>';
            cells.forEach(cell => {
                if (index === 0) {
                    tableHtml += `<th>${cell}</th>`;
                } else {
                    tableHtml += `<td>${cell}</td>`;
                }
            });
            tableHtml += '</tr>';
        });
        
        previewTable.innerHTML = tableHtml;
        
        // Setup edit button
        const editBtn = document.getElementById('editCsv');
        if (editBtn) {
            editBtn.addEventListener('click', () => {
                this.showEditableCsvTable(csvData);
            });
        }

        // Setup save data button
        const saveBtn = document.getElementById('saveCsv');
        if (saveBtn) {
            saveBtn.addEventListener('click', () => {
                this.saveCsvDataDirectly(csvData);
            });
        }
    }

    async startAiProcessing() {
        if (!this.currentCsvData) {
            Utils.showNotification('No CSV data available', 'warning');
            return;
        }

        try {
            // Create AI session
            const response = await ApiClient.ai.createSession(this.dashboardId, this.currentCsvData);
            this.currentSessionId = response.session_id;
            
            // Show AI chat interface
            const aiChatCard = document.getElementById('aiChatCard');
            aiChatCard.classList.remove('d-none');
            
            // Add welcome message
            this.addChatMessage('assistant', 'Hello! I can help you process your expense data. Tell me what you\'d like to do - for example: "Filter only transactions above $50", "Categorize expenses", or "Remove duplicate entries".');
            
            Utils.showNotification('AI session started. You can now chat with the assistant.', 'success');
            
        } catch (error) {
            console.error('AI session creation error:', error);
            Utils.showNotification('Failed to start AI session. Please check your API key in settings.', 'danger');
        }
    }

    async sendAiMessage() {
        const chatInput = document.getElementById('chatInput');
        const message = chatInput.value.trim();
        
        if (!message) return;
        
        if (!this.currentSessionId) {
            Utils.showNotification('Please start AI processing first', 'warning');
            return;
        }

        // Add user message to chat
        this.addChatMessage('user', message);
        chatInput.value = '';
        
        // Show loading state
        const sendBtn = document.getElementById('sendMessage');
        Utils.showLoading(sendBtn);
        
        try {
            // Send to AI API with current CSV data
            const response = await ApiClient.ai.processCsv(
                this.dashboardId,
                this.currentSessionId,
                message,
                this.currentCsvData
            );
            
            // Add AI response
            this.addChatMessage('assistant', response.message);
            
            // Update CSV preview if new data is provided
            if (response.processed_csv) {
                this.currentCsvData = response.processed_csv;
                this.showCsvPreview(response.processed_csv);
                this.showEditableCsvTable(response.processed_csv);
            }
            
        } catch (error) {
            console.error('AI processing error:', error);
            this.addChatMessage('assistant', 'Sorry, I encountered an error processing your request. Please try again.');
        } finally {
            Utils.hideLoading(sendBtn);
        }
    }

    showEditableCsvTable(csvData) {
        const editableTableContainer = document.getElementById('editableCsvTable');
        if (!editableTableContainer) return;
        
        // Parse CSV data
        const rows = csvData.split('\n');
        const headers = rows[0].split(',').map(h => h.replace(/^"|"$/g, ''));
        const dataRows = rows.slice(1).map(row => {
            const cells = row.split(',').map(cell => cell.replace(/^"|"$/g, ''));
            return cells;
        });
        
        // Create Handsontable for editable CSV
        if (this.editableCsvTable) {
            this.editableCsvTable.destroy();
        }
        
        this.editableCsvTable = new Handsontable(editableTableContainer, {
            data: dataRows,
            columns: headers.map((header, index) => ({
                data: index,
                type: 'text'
            })),
            colHeaders: headers,
            rowHeaders: true,
            contextMenu: true,
            manualColumnResize: true,
            manualRowMove: true,
            licenseKey: 'non-commercial-and-evaluation',
            height: 300,
            afterChange: (changes, source) => {
                if (source === 'edit') {
                    this.updateCsvFromEditableTable();
                }
            }
        });
        
        // Show the editable table section
        const editableSection = document.getElementById('editableCsvSection');
        if (editableSection) {
            editableSection.classList.remove('d-none');
        }
        
        // Setup save and cancel buttons
        const saveBtn = document.getElementById('saveExpenses');
        const cancelBtn = document.getElementById('cancelEdit');
        
        if (saveBtn) {
            saveBtn.addEventListener('click', this.saveExpensesToDb.bind(this));
        }
        
        if (cancelBtn) {
            cancelBtn.addEventListener('click', this.cancelEdit.bind(this));
        }
    }
    
    async saveExpensesToDb() {
        if (!this.editableCsvTable) {
            Utils.showNotification('No data to save', 'warning');
            return;
        }
        
        const data = this.editableCsvTable.getData();
        const headers = this.editableCsvTable.getColHeader();
        
        try {
            // Convert table data to expense objects
            const expenses = [];
            
            data.forEach(row => {
                if (row.length >= 4) {
                    // Parse date from MM/DD/YYYY format to YYYY-MM-DD format
                    let date = row[0];
                    if (date && date.includes('/')) {
                        const parts = date.split('/');
                        if (parts.length === 3) {
                            const month = parts[0].padStart(2, '0');
                            const day = parts[1].padStart(2, '0');
                            const year = parts[2].length === 2 ? '20' + parts[2] : parts[2];
                            date = `${year}-${month}-${day}`;
                        }
                    }
                    
                    const expense = {
                        date: date,
                        description: row[1],
                        amount: parseFloat(row[2]) || 0,
                        category: row[3] || 'misc'
                    };
                    
                    // Only add if we have valid data
                    if (expense.date && expense.description && expense.amount > 0) {
                        expenses.push(expense);
                    }
                }
            });
            
            if (expenses.length === 0) {
                Utils.showNotification('No valid expenses to save', 'warning');
                return;
            }
            
            // Save each expense to the database
            let savedCount = 0;
            for (const expense of expenses) {
                try {
                    console.log('Attempting to save expense:', expense);
                    const result = await ApiClient.expenses.create(this.dashboardId, expense);
                    console.log('Save result:', result);
                    savedCount++;
                } catch (error) {
                    console.error('Error saving expense:', error);
                    console.error('Error details:', error.message);
                }
            }
            
            console.log(`Total expenses saved: ${savedCount}`);
            Utils.showNotification(`Successfully saved ${savedCount} expenses to the database`, 'success');
            
            // Hide the editable section
            const editableSection = document.getElementById('editableCsvSection');
            if (editableSection) {
                editableSection.classList.add('d-none');
            }
            
        } catch (error) {
            console.error('Error saving expenses:', error);
            Utils.showNotification('Error saving expenses to database', 'danger');
        }
    }
    
    async saveCsvDataDirectly(csvData) {
        try {
            // Parse CSV data directly
            const rows = csvData.split('\n');
            const headers = rows[0].split(',').map(h => h.replace(/^"|"$/g, ''));
            const dataRows = rows.slice(1).map(row => {
                const cells = row.split(',').map(cell => cell.replace(/^"|"$/g, ''));
                return cells;
            });
            
            // Convert to expense objects
            const expenses = [];
            
            dataRows.forEach(row => {
                if (row.length >= 3) {
                    // Parse date from MM/DD/YYYY format to YYYY-MM-DD format
                    let date = row[0];
                    if (date && date.includes('/')) {
                        const parts = date.split('/');
                        if (parts.length === 3) {
                            const month = parts[0].padStart(2, '0');
                            const day = parts[1].padStart(2, '0');
                            const year = parts[2].length === 2 ? '20' + parts[2] : parts[2];
                            date = `${year}-${month}-${day}`;
                        }
                    }
                    
                    const expense = {
                        date: date,
                        description: row[1],
                        amount: parseFloat(row[2]) || 0,
                        category: row[3] || 'misc'
                    };
                    
                    // More lenient validation - only require description and amount
                    if (expense.description && expense.amount > 0) {
                        expenses.push(expense);
                    }
                }
            });
            
            if (expenses.length === 0) {
                Utils.showNotification('No valid expenses to save. Please check if your data has descriptions and amounts.', 'warning');
                return;
            }
            
            // Save each expense to the database
            let savedCount = 0;
            for (const expense of expenses) {
                try {
                    console.log('Attempting to save expense (direct):', expense);
                    const result = await ApiClient.expenses.create(this.dashboardId, expense);
                    console.log('Save result (direct):', result);
                    savedCount++;
                } catch (error) {
                    console.error('Error saving expense (direct):', error);
                    console.error('Error details (direct):', error.message);
                }
            }
            
            console.log(`Total expenses saved (direct): ${savedCount}`);
            Utils.showNotification(`Successfully saved ${savedCount} expenses to the database`, 'success');
            
            // Refresh all components after data ingress
            await this.refreshAllComponents();
            
        } catch (error) {
            console.error('Error saving CSV data:', error);
            Utils.showNotification('Error saving data to database', 'danger');
        }
    }

    async refreshAllComponents() {
        console.log('Refreshing all dashboard components after data ingress');
        
        try {
            // 1. Refresh month dropdown
            await this.setupMonthDropdown();
            
            // 2. Refresh monthly table with current selected month
            const selectedMonth = this.getSelectedMonthFromDropdown();
            if (selectedMonth) {
                await this.refreshMonthlyData(selectedMonth);
            } else {
                // If no month selected, refresh with default month
                await this.refreshMonthlyData();
            }
            
            // 3. Refresh yearly table
            await this.initYearlyTable();
            
            Utils.showNotification('All dashboard components refreshed with new data', 'success');
            
        } catch (error) {
            console.error('Error refreshing components:', error);
            Utils.showNotification('Error refreshing dashboard components', 'danger');
        }
    }
    
    cancelEdit() {
        const editableSection = document.getElementById('editableCsvSection');
        if (editableSection) {
            editableSection.classList.add('d-none');
        }
        Utils.showNotification('Editing cancelled', 'info');
    }

    updateCsvFromEditableTable() {
        if (!this.editableCsvTable) return;
        
        const data = this.editableCsvTable.getData();
        const headers = this.editableCsvTable.getColHeader();
        
        // Convert back to CSV format
        const csvRows = [headers.join(',')];
        data.forEach(row => {
            const escapedRow = row.map(cell => `"${cell}"`);
            csvRows.push(escapedRow.join(','));
        });
        
        this.currentCsvData = csvRows.join('\n');
        
        // Update the preview as well
        this.showCsvPreview(this.currentCsvData);
        
        Utils.showNotification('CSV data updated. Your changes will be used in the next AI request.', 'info');
    }

    addChatMessage(role, content) {
        const chatMessages = document.getElementById('chatMessages');
        const messageDiv = document.createElement('div');
        messageDiv.className = `chat-message ${role}`;
        messageDiv.textContent = content;
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    initMonthlyTable(selectedMonth = null) {
        console.log('=== initMonthlyTable() called with selectedMonth:', selectedMonth, '===');
        const container = document.getElementById('monthlyExpensesTable');
        if (!container) {
            console.error('Monthly table container not found!');
            return;
        }

        // Initialize empty table - data will be loaded from API
        this.monthlyTable = new Handsontable(container, {
            data: [],
            columns: [
                {
                    data: 'date',
                    type: 'date',
                    dateFormat: 'YYYY-MM-DD',
                    correctFormat: true,
                    width: 120
                },
                {
                    data: 'category',
                    type: 'dropdown',
                    source: ['car', 'gas', 'grocery', 'home exp', 'home setup', 'gym', 'hospital', 'misc', 'rent', 'mortgage', 'restaurants', 'service', 'shopping', 'transport', 'utilities', 'vacation'],
                    width: 120,
                    filter: 'select'
                },
                {
                    data: 'amount',
                    type: 'numeric',
                    numericFormat: {
                        pattern: '$0,0.00'
                    },
                    width: 100
                },
                {
                    data: 'description',
                    type: 'text',
                    filter: 'text'
                },
                {
                    data: 'id',
                    type: 'numeric',
                    readOnly: true,
                    width: 80
                }
            ],
            colHeaders: ['Date', 'Category', 'Amount', 'Description', 'ID'],
            dropdownMenu: [
                'filter_by_condition',
                'filter_action_bar',
                'filter_by_value',
                'filter_operators'
            ],
            filters: true,
            rowHeaders: true,
            contextMenu: {
                items: {
                    'row_above': {
                        name: 'Insert row above',
                        callback: (key, selection) => {
                            console.log('Insert row above context menu triggered:', selection);
                            this.handleRowAddition(selection);
                        }
                    },
                    'row_below': {
                        name: 'Insert row below',
                        callback: (key, selection) => {
                            console.log('Insert row below context menu triggered:', selection);
                            this.handleRowAddition(selection);
                        }
                    },
                    'remove_row': {
                        name: 'Remove row',
                        callback: (key, selection) => {
                            console.log('Remove row context menu triggered:', selection);
                            this.handleRowRemoval(selection);
                        }
                    },
                    'sep1': '---------',
                    'alignment': {}
                }
            },
            manualColumnResize: true,
            manualRowMove: true,
            licenseKey: 'non-commercial-and-evaluation',
            height: 400, // Fixed height to prevent ResizeObserver issues
            afterChange: (changes, source) => {
                console.log('Handsontable afterChange called:', { 
                    changes: changes, 
                    source: source,
                    tableData: this.monthlyTable ? this.monthlyTable.getData() : 'No table'
                });
                
                // Only process user edits, ignore programmatic changes
                if (source === 'edit' && changes && changes.length > 0) {
                    console.log('Valid user edit detected, processing individual changes');
                    console.log('Changes details:', changes);
                    
                    // Process each change individually
                    changes.forEach(change => {
                        const [row, prop, oldValue, newValue] = change;
                        const rowData = this.monthlyTable.getDataAtRow(row);
                        const rowId = rowData[0]; // ID is in first column
                        
                        if (rowId) {
                            // Convert row data to object format
                            const expenseData = {
                                date: rowData[1],
                                description: rowData[2],
                                amount: rowData[3],
                                category: rowData[4]
                            };
                            
                            console.log('Calling updateMonthlyChanges for row ID:', rowId, 'with data:', expenseData);
                            this.updateMonthlyChanges(rowId, expenseData);
                        } else {
                            console.log('No row ID found for row:', row, 'skipping update');
                        }
                    });
                } else if (source !== 'loadData' && source !== 'autofill' && source !== 'empty') {
                    console.log('Ignoring non-edit change:', {
                        source: source,
                        changesCount: changes ? changes.length : 0,
                        changes: changes
                    });
                }
            },
            
            // Add additional event listeners for better change detection
            afterBeginEditing: (row, column) => {
                console.log('Cell editing started:', { row, column });
            },
            
            afterSelection: (row, column, row2, column2, preventScrolling) => {
                console.log('Cell selected:', { row, column });
            },
            
        });

        // If a month is selected, load data for that month
        if (selectedMonth) {
            console.log('Loading data for selected month:', selectedMonth);
            this.refreshMonthlyData(selectedMonth);
        } else {
            console.log('No month selected, table remains empty');
        }

    }

    async setupMonthDropdown() {
        console.log('=== setupMonthDropdown() called ===');
        const dropdownMenu = document.getElementById('monthDropdownMenu');
        const dropdownButton = document.getElementById('monthDropdown');
        
        if (!dropdownMenu || !dropdownButton) {
            console.error('Dropdown elements not found!');
            return null;
        }
        
        try {
            console.log('Setting up month dropdown from database...');
            const months = await this.getAvailableMonthsFromDb();
            console.log('Months from database:', months);
            
            let menuHtml = '';
            let selectedMonth = null;
            
            // If no months in database, keep dropdown blank
            if (months.length === 0) {
                console.log('No months found in database, keeping dropdown blank');
                menuHtml = '<li><a class="dropdown-item disabled" href="#">No data available</a></li>';
                dropdownButton.innerHTML = '<i class="fas fa-calendar me-1"></i>Select Month';
            } else {
                // Populate dropdown with months from database
                months.forEach(month => {
                    menuHtml += `
                        <li><a class="dropdown-item" href="#" data-month="${month.value}">${month.label}</a></li>
                    `;
                });
                
                // Set default to first available month
                selectedMonth = months[0].value;
                const defaultMonthLabel = months[0].label;
                console.log('Setting default month to:', selectedMonth, 'label:', defaultMonthLabel);
                dropdownButton.innerHTML = `<i class="fas fa-calendar me-1"></i>${defaultMonthLabel}`;
            }
            
            dropdownMenu.innerHTML = menuHtml;
            
            // Add event listeners to dropdown items
            const dropdownItems = dropdownMenu.querySelectorAll('.dropdown-item:not(.disabled)');
            dropdownItems.forEach(item => {
                item.addEventListener('click', (e) => {
                    e.preventDefault();
                    const selectedMonth = e.target.getAttribute('data-month');
                    console.log('Month selected from dropdown:', selectedMonth);
                    this.handleMonthChange(selectedMonth);
                    dropdownButton.innerHTML = `<i class="fas fa-calendar me-1"></i>${e.target.textContent}`;
                });
            });
            
            return selectedMonth;
            
        } catch (error) {
            console.error('Error setting up month dropdown:', error);
            // On error, keep dropdown blank
            dropdownMenu.innerHTML = '<li><a class="dropdown-item disabled" href="#">Error loading months</a></li>';
            dropdownButton.innerHTML = '<i class="fas fa-calendar me-1"></i>Select Month';
            return null;
        }
    }


    async getAvailableMonthsFromDb() {
        try {
            console.log('Fetching expenses from API for dashboard:', this.dashboardId);
            const expenses = await ApiClient.expenses.get(this.dashboardId);
            console.log('Raw expenses from API:', expenses);
            
            // Extract unique months from expenses
            const availableMonths = new Set();
            expenses.forEach(expense => {
                console.log('Processing expense:', expense);
                if (expense.date) {
                    const month = expense.date.substring(0, 7); // YYYY-MM
                    console.log('Extracted month:', month, 'from date:', expense.date);
                    availableMonths.add(month);
                }
            });
            
            console.log('Available months set:', availableMonths);
            
            // Convert to array and sort (newest first)
            const months = Array.from(availableMonths)
                .sort()
                .reverse()
                .map(month => {
                    // Parse the month string correctly (YYYY-MM format)
                    const [year, monthNum] = month.split('-');
                    // Use UTC to avoid timezone issues
                    const date = new Date(Date.UTC(parseInt(year), parseInt(monthNum) - 1, 1));
                    const label = date.toLocaleDateString('en-US', { 
                        year: 'numeric', 
                        month: 'long',
                        timeZone: 'UTC' 
                    });
                    console.log('Month object:', { value: month, label, year, monthNum, date: date.toString() });
                    return { value: month, label };
                });
            
            console.log('Final months array:', months);
            return months;
        } catch (error) {
            console.error('Error getting months from database:', error);
            return [];
        }
    }

    generateMonthOptions() {
        const months = [];
        const currentDate = new Date();
        
        for (let i = 0; i < 12; i++) {
            const date = new Date(currentDate.getFullYear(), currentDate.getMonth() - i, 1);
            const value = date.toISOString().substring(0, 7);
            const label = date.toLocaleDateString('en-US', { year: 'numeric', month: 'long' });
            months.push({ value, label });
        }
        
        return months;
    }

    handleMonthChange(selectedMonth) {
        console.log('Selected month:', selectedMonth);
        // Clear the current table and reload with data for the selected month
        if (this.monthlyTable) {
            // Clear the table first - use loadData with empty array
            this.monthlyTable.loadData([]);
            console.log('clearing monthly table - loadData([]) called');
        }
        
        // Load data for the selected month
        this.refreshMonthlyData(selectedMonth);
        Utils.showNotification(`Showing data for ${selectedMonth}`, 'info');
    }

    async handleRowRemoval(selection) {
        console.log('handleRowRemoval called with selection:', selection);
        
        try {
            const selectedMonth = this.getSelectedMonthFromDropdown();
            if (!selectedMonth) {
                Utils.showNotification('No month selected', 'warning');
                return;
            }
            
            // Get current expenses for the selected month
            const currentExpenses = await ApiClient.expenses.get(this.dashboardId);
            const monthExpenses = currentExpenses.filter(expense => {
                const expenseMonth = expense.date.substring(0, 7);
                return expenseMonth === selectedMonth;
            });
            
            // Get the row index that was removed
            const removedRowIndex = selection[0].start.row;
            console.log('Removing row at index:', removedRowIndex);
            
            // Find the expense at that position
            if (removedRowIndex < monthExpenses.length) {
                const expenseToDelete = monthExpenses[removedRowIndex];
                if (expenseToDelete && expenseToDelete.id) {
                    console.log('Deleting expense:', expenseToDelete);
                    await ApiClient.expenses.delete(this.dashboardId, expenseToDelete.id);
                    Utils.showNotification('Expense deleted successfully', 'success');
                    
                    // Remove the row from the table directly without full refresh
                    // This prevents the afterChange event from firing with loadData source
                    if (this.monthlyTable) {
                        this.monthlyTable.alter('remove_row', removedRowIndex);
                        
                        // Update category breakdown from current table data
                        const currentTableData = this.monthlyTable.getData();
                        this.updateCategoryBreakdownFromTableData(currentTableData);
                    }
                }
            }
        } catch (error) {
            console.error('Error handling row removal:', error);
            Utils.showNotification('Error deleting expense', 'danger');
        }
    }

    async refreshMonthlyData(month = null) {
        try {
            console.log('refreshMonthlyData called with month:', month);
            const expenses = await ApiClient.expenses.get(this.dashboardId);
            console.log('Fetched expenses from API:', expenses);
            
            // Filter by month if specified
            let filteredExpenses = expenses;
            if (month) {
                console.log('Filtering for month:', month);
                filteredExpenses = expenses.filter(expense => {
                    const expenseMonth = expense.date.substring(0, 7); // YYYY-MM
                    //console.log('Checking expense date:', expense.date, 'month:', expenseMonth, 'matches:', expenseMonth === month);
                    return expenseMonth === month;
                });
            }
            
            console.log('Filtered expenses for month', month, ':', filteredExpenses);
            
            // Update Handsontable with new data
            if (this.monthlyTable) {
                // Convert to object format that Handsontable expects
                const tableData = filteredExpenses.map(expense => ({
                    id: expense.id,
                    date: expense.date,
                    description: expense.description,
                    amount: expense.amount,
                    category: expense.category
                }));
                console.log('Loading table data into Handsontable:', tableData);
                this.monthlyTable.loadData(tableData);
            }

            // Update category breakdown
            this.updateCategoryBreakdown(filteredExpenses);
        } catch (error) {
            console.error('Error refreshing monthly data:', error);
        }
    }

    updateCategoryBreakdown(expenses) {
        const pivotContainer = document.getElementById('categoryPivotTable');
        if (!pivotContainer) return;

        // Calculate category totals
        const categoryTotals = {};
        let totalAmount = 0;
        
        expenses.forEach(expense => {
            if (!categoryTotals[expense.category]) {
                categoryTotals[expense.category] = 0;
            }
            categoryTotals[expense.category] += expense.amount;
            totalAmount += expense.amount;
        });

        // Create HTML for category breakdown
        let html = '<div class="list-group list-group-flush">';
        
        // Add category rows
        Object.entries(categoryTotals)
            .sort(([,a], [,b]) => b - a)
            .forEach(([category, total]) => {
                html += `
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                        <span class="text-capitalize">${category}</span>
                        <span class="badge bg-primary rounded-pill">${Utils.formatCurrency(total)}</span>
                    </div>
                `;
            });
        
        // Add total row
        html += `
            <div class="list-group-item category-total d-flex justify-content-between align-items-center">
                <span class="fw-bold">Total</span>
                <span class="badge bg-primary rounded-pill">${Utils.formatCurrency(totalAmount)}</span>
            </div>
        `;
        
        html += '</div>';

        pivotContainer.innerHTML = html;
    }

    updateCategoryBreakdownFromTableData(tableData) {
        const pivotContainer = document.getElementById('categoryPivotTable');
        if (!pivotContainer) return;

        // Calculate category totals from table data (not database)
        const categoryTotals = {};
        let totalAmount = 0;
        
        tableData.forEach(row => {
            if (row && row.category && row.amount) {
                if (!categoryTotals[row.category]) {
                    categoryTotals[row.category] = 0;
                }
                categoryTotals[row.category] += parseFloat(row.amount) || 0;
                totalAmount += parseFloat(row.amount) || 0;
            }
        });

        // Create HTML for category breakdown
        let html = '<div class="list-group list-group-flush">';
        
        // Add category rows
        Object.entries(categoryTotals)
            .sort(([,a], [,b]) => b - a)
            .forEach(([category, total]) => {
                html += `
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                        <span class="text-capitalize">${category}</span>
                        <span class="badge bg-primary rounded-pill">${Utils.formatCurrency(total)}</span>
                    </div>
                `;
            });
        
        // Add total row
        html += `
            <div class="list-group-item category-total d-flex justify-content-between align-items-center">
                <span class="fw-bold">Total</span>
                <span class="badge bg-primary rounded-pill">${Utils.formatCurrency(totalAmount)}</span>
            </div>
        `;
        
        html += '</div>';

        pivotContainer.innerHTML = html;
    }

    async initYearlyTable() {
        const table = document.getElementById('yearlyTable');
        if (!table) return;

        try {
            // Fetch all expenses from the API
            const expenses = await ApiClient.expenses.get(this.dashboardId);
            
            // Process data into yearly pivot format
            const yearlyData = this.processYearlyPivotData(expenses);
            
            // Generate HTML for the yearly table
            this.renderYearlyTable(yearlyData);
            
        } catch (error) {
            console.error('Error initializing yearly table:', error);
            // Fallback to sample data if API fails
            this.renderYearlyTable(this.getSampleYearlyData());
        }
    }

    processYearlyPivotData(expenses) {
        const yearlyData = {};
        
        // Define all months for consistent columns
        const monthNames = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
        
        // Process each expense
        expenses.forEach(expense => {
            if (!expense.date || !expense.category || !expense.amount) return;
            
            const date = new Date(expense.date);
            const year = date.getFullYear();
            const month = date.getMonth(); // 0-11
            const monthName = monthNames[month];
            const category = expense.category.toLowerCase();
            
            // Initialize year if not exists
            if (!yearlyData[year]) {
                yearlyData[year] = {};
                // Initialize all categories with all months set to 0
                const categories = ['car', 'gas', 'grocery', 'home exp', 'home setup', 'gym', 'hospital', 'misc', 'rent', 'mortgage', 'restaurants', 'service', 'shopping', 'transport', 'utilities', 'vacation'];
                categories.forEach(cat => {
                    yearlyData[year][cat] = {};
                    monthNames.forEach(month => {
                        yearlyData[year][cat][month] = 0;
                    });
                });
            }
            
            // Add amount to the appropriate category and month
            if (yearlyData[year][category] && yearlyData[year][category][monthName] !== undefined) {
                yearlyData[year][category][monthName] += expense.amount;
            }
        });
        
        return yearlyData;
    }

    renderYearlyTable(yearlyData) {
        const table = document.getElementById('yearlyTable');
        if (!table) return;
        
        const monthNames = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
        const monthHeaders = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const categories = ['car', 'gas', 'grocery', 'home exp', 'home setup', 'gym', 'hospital', 'misc', 'rent', 'mortgage', 'restaurants', 'service', 'shopping', 'transport', 'utilities', 'vacation'];
        
        let html = '';
        
        // Sort years in descending order
        const years = Object.keys(yearlyData).sort((a, b) => b - a);
        
        years.forEach(year => {
            // Calculate totals for each month and overall
            const monthlyTotals = {};
            let yearlyTotal = 0;
            
            monthNames.forEach(month => {
                monthlyTotals[month] = 0;
                categories.forEach(category => {
                    if (yearlyData[year][category] && yearlyData[year][category][month]) {
                        monthlyTotals[month] += yearlyData[year][category][month];
                    }
                });
                yearlyTotal += monthlyTotals[month];
            });
            
            // Year header
            html += `
                <div class="year-section mb-4">
                    <h5 class="text-primary mb-3">${year}</h5>
                    <div class="table-responsive">
                        <table class="table table-bordered table-sm">
                            <thead class="table-light">
                                <tr>
                                    <th>Category</th>
                                    ${monthHeaders.map(month => `<th>${month}</th>`).join('')}
                                    <th class="table-primary">Total</th>
                                </tr>
                            </thead>
                            <tbody>
            `;
            
            // Category rows
            categories.forEach(category => {
                const rowData = yearlyData[year][category];
                if (rowData) {
                    let categoryTotal = 0;
                    const monthCells = monthNames.map(month => {
                        const amount = rowData[month] || 0;
                        categoryTotal += amount;
                        return `<td class="text-end">${amount > 0 ? Utils.formatCurrency(amount) : '-'}</td>`;
                    }).join('');
                    
                    html += `
                        <tr>
                            <td class="fw-bold text-capitalize">${category}</td>
                            ${monthCells}
                            <td class="text-end fw-bold table-primary">${categoryTotal > 0 ? Utils.formatCurrency(categoryTotal) : '-'}</td>
                        </tr>
                    `;
                }
            });
            
            // Monthly totals row
            html += `
                        <tr class="table-secondary">
                            <td class="fw-bold">Monthly Total</td>
                            ${monthNames.map(month => {
                                const amount = monthlyTotals[month] || 0;
                                return `<td class="text-end fw-bold">${amount > 0 ? Utils.formatCurrency(amount) : '-'}</td>`;
                            }).join('')}
                            <td class="text-end fw-bold table-primary">${yearlyTotal > 0 ? Utils.formatCurrency(yearlyTotal) : '-'}</td>
                        </tr>
            `;
            
            html += `
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        });
        
        table.innerHTML = html;
        
        // If no data, show message
        if (years.length === 0) {
            table.innerHTML = `
                <div class="alert alert-info">
                    <i class="fas fa-info-circle me-2"></i>
                    No expense data available for yearly overview.
                </div>
            `;
        }
    }

    getSampleYearlyData() {
        // Sample data for testing when API is not available
        return {
            2024: {
                car: { jan: 100, feb: 100, mar: 100, apr: 100, may: 100, jun: 100, jul: 100, aug: 100, sep: 100, oct: 100, nov: 100, dec: 100 },
                gas: { jan: 50, feb: 200, mar: 300, apr: 150, may: 100, jun: 75, jul: 80, aug: 90, sep: 120, oct: 110, nov: 95, dec: 50 },
                grocery: { jan: 500, feb: 250, mar: 50, apr: 300, may: 400, jun: 350, jul: 320, aug: 280, sep: 310, oct: 290, nov: 330, dec: 600 },
                restaurants: { jan: 265, feb: 180, mar: 220, apr: 190, may: 210, jun: 195, jul: 205, aug: 215, sep: 225, oct: 235, nov: 245, dec: 255 },
                utilities: { jan: 150, feb: 145, mar: 160, apr: 155, may: 165, jun: 170, jul: 175, aug: 180, sep: 185, oct: 190, nov: 195, dec: 200 },
                misc: { jan: 75, feb: 80, mar: 65, apr: 90, may: 85, jun: 95, jul: 100, aug: 110, sep: 105, oct: 115, nov: 125, dec: 135 }
            },
            2025: {
                car: { jan: 120, feb: 120, mar: 120, apr: 120, may: 120, jun: 120, jul: 120, aug: 120, sep: 120, oct: 120, nov: 120, dec: 120 },
                gas: { jan: 60, feb: 220, mar: 320, apr: 160, may: 110, jun: 85, jul: 90, aug: 100, sep: 130, oct: 120, nov: 105, dec: 60 },
                grocery: { jan: 520, feb: 270, mar: 60, apr: 320, may: 420, jun: 370, jul: 340, aug: 300, sep: 330, oct: 310, nov: 350, dec: 620 },
                restaurants: { jan: 275, feb: 190, mar: 230, apr: 200, may: 220, jun: 205, jul: 215, aug: 225, sep: 235, oct: 245, nov: 255, dec: 265 },
                utilities: { jan: 160, feb: 155, mar: 170, apr: 165, may: 175, jun: 180, jul: 185, aug: 190, sep: 195, oct: 200, nov: 205, dec: 210 },
                misc: { jan: 85, feb: 90, mar: 75, apr: 100, may: 95, jun: 105, jul: 110, aug: 120, sep: 115, oct: 125, nov: 135, dec: 145 }
            }
        };
    }

    async updateMonthlyChanges(rowId, rowData) {
        try {
            if (!rowId) {
                console.error('No row ID provided for update');
                return;
            }
            
            if (!rowData || !rowData.date || !rowData.description || !rowData.amount) {
                console.error('Invalid row data for update:', rowData);
                return;
            }
            
            const updatedExpense = {
                date: rowData.date,
                description: rowData.description,
                amount: parseFloat(rowData.amount),
                category: rowData.category || 'misc'
            };
            
            // Update the expense using PUT
            await ApiClient.expenses.update(this.dashboardId, rowId, updatedExpense);
            
            // Update the category breakdown immediately from the current table data
            const currentTableData = this.monthlyTable.getData();
            this.updateCategoryBreakdownFromTableData(currentTableData);
            
            // Add a small delay to ensure database has time to update
            await new Promise(resolve => setTimeout(resolve, 200));
            
            // Refresh the table to show the updated data from database
            const selectedMonth = this.getSelectedMonthFromDropdown();
            if (selectedMonth) {
                await this.refreshMonthlyData(selectedMonth);
            }
            
            Utils.showNotification('Expense updated successfully', 'success');
            
        } catch (error) {
            console.error('Error updating monthly changes:', error);
            Utils.showNotification('Error updating expense: ' + error.message, 'danger');
        }
    }
    
    async handleRowAddition(selection) {
        console.log('handleRowAddition called with selection:', selection);
        
        try {
            const selectedMonth = this.getSelectedMonthFromDropdown();
            if (!selectedMonth) {
                Utils.showNotification('No month selected', 'warning');
                return;
            }
            
            // Get the row index where the new row should be added
            const rowIndex = selection[0].start.row;
            console.log('Adding new row at index:', rowIndex);
            
            // Create a new expense with default values
            const newExpense = {
                date: new Date().toISOString().split('T')[0], // Today's date
                description: 'New Expense',
                amount: 0.00,
                category: 'misc'
            };
            
            console.log('Creating new expense:', newExpense);
            const result = await ApiClient.expenses.create(this.dashboardId, newExpense);
            
            // Refresh the table to show the new expense with its ID
            await this.refreshMonthlyData(selectedMonth);
            
            Utils.showNotification('New expense added successfully', 'success');
            
        } catch (error) {
            console.error('Error handling row addition:', error);
            Utils.showNotification('Error adding new expense', 'danger');
        }
    }
    
    async saveMonthlyChanges() {
        // This function is now deprecated - individual operations are handled separately
        console.log('saveMonthlyChanges is deprecated - use individual update/delete/add functions');
        Utils.showNotification('Individual row operations are now handled separately', 'info');
    }


    async refreshYearlyData() {
        try {
            // In production, this would fetch aggregated yearly data
            console.log('Refreshing yearly data');
        } catch (error) {
            console.error('Error refreshing yearly data:', error);
        }
    }

    addManualSaveButton() {
        // Create a manual save button for testing
        const container = document.getElementById('monthlyExpensesTable');
        if (!container) return;
        
        const saveButton = document.createElement('button');
        saveButton.className = 'btn btn-primary mt-3';
        saveButton.innerHTML = '<i class="fas fa-save me-1"></i>Save Changes Manually';
        saveButton.addEventListener('click', () => {
            console.log('Manual save button clicked');
            this.saveMonthlyChanges();
        });
        
        container.parentNode.insertBefore(saveButton, container.nextSibling);
    }

    resetUploadUI() {
        const uploadArea = document.getElementById('pdfUploadArea');
        const processingArea = document.getElementById('processingArea');
        const csvPreviewArea = document.getElementById('csvPreviewArea');
        const pdfFileInput = document.getElementById('pdfFile');
        
        uploadArea.classList.remove('d-none');
        processingArea.classList.add('d-none');
        csvPreviewArea.classList.add('d-none');
        
        if (pdfFileInput) {
            pdfFileInput.value = '';
        }
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Extract dashboard ID from URL or data attribute
    const dashboardId = window.location.pathname.split('/').pop();
    if (dashboardId && !isNaN(dashboardId)) {
        window.dashboardManager = new DashboardManager(dashboardId);
    }
});
