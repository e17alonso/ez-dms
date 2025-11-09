let currentMessageId = "";  // Store the current message ID for reference
let currentEncryptedMessage = "";  // Store the encrypted message
let isEncrypted = false;  // Flag to track if the message is encrypted

// Function to create a new message
async function createMessage() {
    let content = document.getElementById('messageContent').value;
    let response = await fetch('http://127.0.0.1:5000/create', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `content=${encodeURIComponent(content)}`
    });
    let result = await response.json();
    if (result.id) {
        document.getElementById('message').innerHTML = `New Message Created with ID: <b>${result.id}</b>`;
        document.getElementById('messageContent').value = '';  // Clear the textarea
    } else {
        document.getElementById('message').innerHTML = `<span style="color: red;">Error: ${result.error}</span>`;
    }
}

// Function to search for a message using its ID
async function searchMessage() {
    let searchId = document.getElementById('searchId').value;
    let response = await fetch(`http://127.0.0.1:5000/message/${searchId}`, {
        method: 'GET',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'}
    });
    let result = await response.json();

    if (result.content) {
        // Message found: Display content and show relevant buttons
        currentMessageId = searchId;
        document.getElementById('messageContent').value = result.content;  // Display the message content
        document.getElementById('message').innerHTML = `Message ID: <b>${searchId}</b> loaded successfully.`;

        if (result.is_encrypted == 1) {
            // If the message is encrypted
            document.getElementById('panicButton').style.display = 'none';     // Hide Panic Button
            document.getElementById('saveButton').style.display = 'none';      // Hide Save Changes Button
            document.getElementById('deleteButton').style.display = 'none';    // Hide Delete Button
            document.getElementById('createButton').style.display = 'none';    // Hide Create Message Button
            document.getElementById('decryptButton').style.display = 'inline'; // Show Decrypt Button
        } else {
            // If the message is not encrypted
            document.getElementById('panicButton').style.display = 'inline';   // Show Panic Button
            document.getElementById('saveButton').style.display = 'inline';    // Show Save Changes Button
            document.getElementById('deleteButton').style.display = 'inline';  // Show Delete Button
            document.getElementById('decryptButton').style.display = 'none';   // Hide Decrypt Button
            document.getElementById('createButton').style.display = 'none';    // Hide Create Message Button
        }
    } else {
        // No message found: Show error message, clear the textbox, and reset buttons
        document.getElementById('message').innerHTML = `<span style="color: red;">Error: ${result.error}</span>`;
        document.getElementById('messageContent').value = '';  // Clear the message content textbox
        resetButtons();  // Reset to default state if no message is found
    }
}

// Function to save changes to the current message
async function saveMessage() {
    let content = document.getElementById('messageContent').value;
    if (currentMessageId === "") {
        document.getElementById('message').innerHTML = `<span style="color: red;">No message to save. Please search for a message first.</span>`;
        return;
    }
    let response = await fetch(`http://127.0.0.1:5000/message/${currentMessageId}`, {
        method: 'PUT',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `content=${encodeURIComponent(content)}`
    });
    let result = await response.json();
    if (result.message) {
        document.getElementById('message').innerHTML = `<span style="color: green;">${result.message}</span>`;
    } else {
        document.getElementById('message').innerHTML = `<span style="color: red;">Error: ${result.error}</span>`;
    }
}

// Function to delete the current message
async function deleteMessage() {
    if (currentMessageId === "") {
        document.getElementById('message').innerHTML = `<span style="color: red;">No message to delete. Please search for a message first.</span>`;
        return;
    }
    let response = await fetch(`http://127.0.0.1:5000/message/${currentMessageId}`, {
        method: 'DELETE',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'}
    });
    let result = await response.json();
    if (result.message) {
        document.getElementById('message').innerHTML = `<span style="color: green;">${result.message}</span>`;
        document.getElementById('messageContent').value = '';  // Clear the textarea
        document.getElementById('searchId').value = '';     // Clear the search bar
        currentMessageId = "";  // Reset the current message ID
        resetButtons();  // Revert button visibility to show 'Create Message'
    } else {
        document.getElementById('message').innerHTML = `<span style="color: red;">Error: ${result.error}</span>`;
    }
}

// Function to reset the buttons when no message is found or after deletion
function resetButtons() {
    document.getElementById('panicButton').style.display = 'none';  // Hide Panic Button
    document.getElementById('decryptButton').style.display = 'none';  // Hide Decrypt Button
    document.getElementById('saveButton').style.display = 'none';  // Hide Save Changes button
    document.getElementById('deleteButton').style.display = 'none';  // Hide Delete Message button
    document.getElementById('createButton').style.display = 'inline';  // Show Create Message button
}

// Function to encrypt the message using a public key
async function encryptMessage() {
    let messageContent = document.getElementById('messageContent').value;
    let publicKey = prompt("Enter the public key:");

    let response = await fetch('http://127.0.0.1:5000/encrypt_message', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `message=${encodeURIComponent(messageContent)}&public_key=${encodeURIComponent(publicKey)}&message_id=${encodeURIComponent(currentMessageId)}`
    });

    let result = await response.json();
    if (result.encrypted_message) {
        document.getElementById('messageContent').value = result.encrypted_message;  // Display encrypted content

        // Hide all buttons except Decrypt when the message is encrypted
        document.getElementById('panicButton').style.display = 'none';
        document.getElementById('saveButton').style.display = 'none';
        document.getElementById('deleteButton').style.display = 'none';
        document.getElementById('createButton').style.display = 'none';
        document.getElementById('decryptButton').style.display = 'inline';
    } else {
        alert("Encryption failed: " + result.error);
    }
}

// Function to decrypt the message using a private key
async function decryptMessage() {
    let privateKey = prompt("Enter your private key:");
    let encryptedMessage = document.getElementById('messageContent').value;  // Encrypted message content in the textbox

    let response = await fetch('http://127.0.0.1:5000/decrypt_message', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `encrypted_message=${encodeURIComponent(encryptedMessage)}&private_key=${encodeURIComponent(privateKey)}&message_id=${encodeURIComponent(currentMessageId)}`
    });

    let result = await response.json();
    if (result.decrypted_message) {
        document.getElementById('messageContent').value = result.decrypted_message;  // Display decrypted content

        // Show Panic Button, Save Changes, and Delete Message buttons when the message is decrypted
        document.getElementById('panicButton').style.display = 'inline';
        document.getElementById('saveButton').style.display = 'inline';
        document.getElementById('deleteButton').style.display = 'inline';
        document.getElementById('decryptButton').style.display = 'none';
        document.getElementById('createButton').style.display = 'none';
    } else {
        alert("Decryption failed: " + result.error);
    }
}
