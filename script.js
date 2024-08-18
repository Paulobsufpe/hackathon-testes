// script.js

document.addEventListener("DOMContentLoaded", () => {
    const apiUrl = 'http://localhost:8000/api';
    const loadDataButton = document.getElementById('ip-button');
    const tableBody = document.querySelector("#data-table tbody");

    loadDataButton.addEventListener('click', () => {
        // Grab the text from the input field
        const inputText = document.getElementById('ip').value;

        // Include the input text in the API request (e.g., as a query parameter)
        const fullUrl = `${apiUrl}?addr=${encodeURIComponent(inputText)}`;

        fetch(fullUrl)
            .then(response => response.json())
            .then(data => {
                // Clear existing table data
                tableBody.innerHTML = '';

                data.forEach(item => {
                    const row = document.createElement("tr");

                    const data = document.createElement("td");
                    data.textContent = item.date;
                    row.appendChild(data);

                    const ip = document.createElement("td");
                    ip.textContent = item.addr;
                    row.appendChild(ip);

                    const porta = document.createElement("td");
                    porta.textContent = item.port;
                    row.appendChild(porta);

                    const desc = document.createElement("td");
                    desc.textContent = item.report;
                    row.appendChild(porta);

                    tableBody.appendChild(row);
                });
            })
            .catch(error => {
                console.error('Error fetching data:', error);
            });
    });
});

