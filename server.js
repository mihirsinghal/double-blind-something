const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Example endpoint for signing
app.post('/api/sign', (req, res) => {
  const { message } = req.body;
  fs.appendFileSync('messages.txt', message + '\n');
  res.json({ signature: 'fake-signature\n' + message });
});

// Circuit generation endpoint
app.post('/api/generate-circuit', (req, res) => {
  const { input } = req.body;
  const timestamp = new Date().toISOString();
  const output = `Input: ${input}\nTimestamp: ${timestamp}\n`;
  
  fs.appendFileSync('circ_out.txt', output + '\n');
  res.json({ success: true, message: 'Circuit output written to circ_out.txt' });
});

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 