require('dotenv').config();
const express = require('express');
const AWS = require('aws-sdk');
const multer = require('multer');
const path = require('path');

const app = express();
const port = 3000;

// Serve frontend
app.use(express.static('public'));

// Multer config: store file in memory
const upload = multer({ storage: multer.memoryStorage() });

const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET,
    region: process.env.AWS_REGION,
    signatureVersion: 'v4', 
});
  

// Secure download route with pre-signed URL
app.get('/download', (req, res) => {
    const fileKey = req.query.key;
  
    if (!fileKey) return res.status(400).send('Missing file key');
  
    const params = {
      Bucket: process.env.S3_BUCKET,
      Key: fileKey,
      Expires: 60, 
    };
  
    // Generate pre-signed URL
    const url = s3.getSignedUrl('getObject', params);
  
    // Redirect to the secure link
    res.redirect(url);
  });
  

// Upload route
app.post('/upload', upload.single('file'), (req, res) => {
  const file = req.file;

  const params = {
    Bucket: process.env.S3_BUCKET,
    Key: `${Date.now()}_${file.originalname}`,
    Body: file.buffer,
    ContentType: file.mimetype,
    ServerSideEncryption: 'AES256',
  };

  s3.upload(params, (err, data) => {
    if (err) {
      console.error('Upload error:', err);
      return res.status(500).send('Upload failed');
    }

    res.send(`
        ✅ File uploaded!<br>
        🔗 <a href="/download?key=${params.Key}">Download file securely</a>
      `);
      
  });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
