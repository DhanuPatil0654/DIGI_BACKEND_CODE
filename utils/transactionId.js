// utils/transactionId.js

let currentTxnId = null;

const generateTxnId = () => {
    if (!currentTxnId) {
        const datePart = new Date().toISOString().split('T')[0].replace(/-/g, ''); // Format as YYYYMMDD
        const uniquePart = new Date().getTime().toString(); // Use timestamp for uniqueness
        currentTxnId = `TXN-${datePart}-${uniquePart}`;
    }
    return currentTxnId;
};

module.exports = { generateTxnId };
