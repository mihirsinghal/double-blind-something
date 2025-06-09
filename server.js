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

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
}); 