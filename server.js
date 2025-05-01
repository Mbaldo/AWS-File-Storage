require('dotenv').config();
const express = require('express');
const AWS = require('aws-sdk');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const fs = require('fs');
const app = express();
const port = 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Multer setup
const upload = multer({ storage: multer.memoryStorage() });

// S3 setup
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET,
    region: process.env.AWS_REGION,
    signatureVersion: 'v4',
});

// JWT Auth Helpers
const users = JSON.parse(fs.readFileSync('users.json', 'utf-8'));

function generateToken(user) {
  return jwt.sign({ userId: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.sendStatus(403);
    next();
  };
}

// Auth Routes
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  if (users.find(u => u.username === username)) return res.status(409).send('User already exists');
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword, role });
  fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
  res.send('User registered');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).send('Cannot find user');

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(403).send('Incorrect password');

  const token = generateToken(user);
  res.json({ token });
});

// File Upload
app.post('/upload', authenticateToken, upload.single('file'), (req, res) => {
  const file = req.file;

  const params = {
    Bucket: process.env.S3_BUCKET,
    Key: `${Date.now()}_${file.originalname}`,
    Body: file.buffer,
    ContentType: file.mimetype,
    ServerSideEncryption: 'AES256',
    Metadata: {
      uploader: req.user.userId  // 🧠 This adds user info to the object
    }
  };
  

  s3.upload(params, (err, data) => {
    if (err) {
      console.error('Upload error:', err);
      return res.status(500).send('Upload failed');
    }

    res.status(200).send('Upload successful');

  });
});

app.get('/files', authenticateToken, async (req, res) => {
  try {
    const data = await s3.listObjectsV2({ Bucket: process.env.S3_BUCKET }).promise();

    // For each object, fetch metadata
    const filteredFiles = await Promise.all(
      data.Contents.map(async (item) => {
        const head = await s3.headObject({ Bucket: process.env.S3_BUCKET, Key: item.Key }).promise();
        const uploader = head.Metadata?.uploader || 'unknown';

        // Admins see all files, others only their own
        if (req.user.role !== 'admin' && uploader !== req.user.userId) return null;

        const url = s3.getSignedUrl('getObject', {
          Bucket: process.env.S3_BUCKET,
          Key: item.Key,
          Expires: 300,
        });

        return {
          key: item.Key,
          url,
          uploader,
        };
      })
    );

    const fileItems = filteredFiles.filter(Boolean); // Remove nulls
    res.json(fileItems);
  } catch (err) {
    console.error('Error listing files:', err);
    res.status(500).json({ error: 'Failed to list files' });
  }
});



app.delete('/delete', authenticateToken, authorizeRoles('admin'), async (req, res) => {
  const fileKey = req.query.key;
  if (!fileKey) return res.status(400).send('Missing file key');

  try {
    await s3.deleteObject({ Bucket: process.env.S3_BUCKET, Key: fileKey }).promise();
    res.status(200).send('Deleted');
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).send('Delete failed');
  }
});


// Secure File Download
app.get('/download', authenticateToken, (req, res) => {
  const fileKey = req.query.key;
  if (!fileKey) return res.status(400).send('Missing file key');

  const url = s3.getSignedUrl('getObject', {
    Bucket: process.env.S3_BUCKET,
    Key: fileKey,
    Expires: 60,
  });

  res.redirect(url);
});

app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
