const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect('mongodb+srv://kirubakaran003k2:tecD4fxD9k1ESxLo@cluster0.ma7vh.mongodb.net/ar_vr_assets?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('MongoDB connected');
}).catch((err) => {
  console.error('MongoDB connection error:', err.message);
});

// JWT Secret Key
const JWT_SECRET = 'your_jwt_secret_key';

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  email: { type: String, unique: true, sparse: true } 
});

const User = mongoose.model('User', userSchema);

// Asset Schema
const assetSchema = new mongoose.Schema({
  name: String,
  type: String,
  category: String, // 3D Model, Texture, Animation, Sound
  version: Number,
  md5: String,
  base64Data: String, // Store the Base64-encoded data
  uploadDate: { type: Date, default: Date.now },
  isPublic: { type: Boolean, default: false },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  privateLink: { type: String, unique: true },
});

const Asset = mongoose.model('Asset', assetSchema);

// Create folders if not exist
const storageDir = path.join(__dirname, 'uploads');
const categories = ['models', 'textures', 'animations', 'sounds'];

categories.forEach(category => {
  const dirPath = path.join(storageDir, category);
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
});

// Multer Storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    let folder = 'models'; // Default
    if (['.obj', '.fbx', '.gltf', '.dae', '.stl'].includes(ext)) folder = 'models';
    if (['.png', '.jpg', '.jpeg', '.tga'].includes(ext)) folder = 'textures';
    if (['.mp4', '.mov', '.avi'].includes(ext)) folder = 'animations';
    if (['.mp3', '.wav'].includes(ext)) folder = 'sounds';

    cb(null, path.join(storageDir, folder));
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});

const upload = multer({ storage });

// Middleware to verify JWT
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token.' });
  }
};

// Signup Route
app.post('/signup', async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ message: 'Username, password, and email are required.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, email });
    await newUser.save();
    res.status(201).json({ message: 'User created successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user.', error: error.message });
  }
});

// Login Route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in.', error: error.message });
  }
});

// Upload Route
app.post('/upload', authenticateJWT, upload.single('file'), async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }
  
    try {
      console.log("File uploaded:", req.file);
      const fileBuffer = fs.readFileSync(req.file.path);
      const md5Hash = crypto.createHash('md5').update(fileBuffer).digest('hex');
      const base64Data = fileBuffer.toString('base64'); // Convert to Base64
  
      let existingAsset = await Asset.findOne({ name: req.file.originalname, owner: req.user.userId });
  
      if (existingAsset) {
        console.log("Existing asset found:", existingAsset);
        if (existingAsset.md5 === md5Hash) {
          return res.json({ message: 'File already exists with the same version' });
        }
  
        existingAsset.version += 1;
        existingAsset.md5 = md5Hash;
        existingAsset.base64Data = base64Data;
        existingAsset.uploadDate = Date.now();
  
        await existingAsset.save();
        fs.unlinkSync(req.file.path); // Delete file after storing
  
        return res.json({ message: `File updated to version ${existingAsset.version}`, asset: existingAsset });
      }
  
      const newAsset = new Asset({
        name: req.file.originalname,
        type: req.file.mimetype,
        category: req.file.destination.split('/').pop(),
        version: 1,
        md5: md5Hash,
        base64Data,
        isPublic: req.body.isPublic || false,
        owner: req.user.userId,
        privateLink: uuidv4(),
      });
  
      await newAsset.save();
      fs.unlinkSync(req.file.path);
  
      console.log("New asset created:", newAsset);
      res.json({ message: 'File uploaded successfully', asset: newAsset });
  
    } catch (error) {
      console.error("Error uploading file:", error);
      res.status(500).json({ message: 'Server error', error: error.message });
    }
  });

// Serve static files (Uploaded files)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Get Assets Route (Public and Private)
app.get('/assets', authenticateJWT, async (req, res) => {
    try {
      console.log("Fetching assets for user:", req.user.userId);
      const assets = await Asset.find({ $or: [{ isPublic: true }, { owner: req.user.userId }] });
      console.log("Assets found:", assets);
      res.json(assets);
    } catch (error) {
      console.error("Error fetching assets:", error);
      res.status(500).json({ message: 'Error fetching assets', error: error.message });
    }
  });

// Delete Asset Route
app.delete('/assets/:id', authenticateJWT, async (req, res) => {
  try {
    const asset = await Asset.findOne({ _id: req.params.id, owner: req.user.userId });
    if (!asset) {
      return res.status(404).json({ message: 'Asset not found or unauthorized' });
    }
    await Asset.findByIdAndDelete(req.params.id);
    res.json({ message: 'Asset deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting asset', error: error.message });
  }
});

// Public Link Route
app.get('/assets/public/:privateLink', async (req, res) => {
  try {
    const asset = await Asset.findOne({ privateLink: req.params.privateLink });
    if (!asset) {
      return res.status(404).json({ message: 'Asset not found' });
    }
    res.json(asset);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching asset', error: error.message });
  }
});
app.get('/download/:assetId', authenticateJWT, async (req, res) => {
  try {
    const assetId = req.params.assetId;

    // Find the asset in the database
    const asset = await Asset.findById(assetId);
    if (!asset) {
      return res.status(404).json({ message: 'Asset not found' });
    }

    // Check if the user is authorized to download the asset
    if (!asset.isPublic && asset.owner.toString() !== req.user.userId) {
      return res.status(403).json({ message: 'Unauthorized to download this asset' });
    }

    // Construct the file path
    const category = path.basename(asset.category); // Extract the last segment of the category path
    const filePath = path.join(__dirname, 'uploads', category, asset.name);

    // Check if the file exists
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: 'File not found on server' });
    }

    // Stream the file to the client
    res.download(filePath, asset.name, (err) => {
      if (err) {
        console.error("Error downloading file:", err);
        res.status(500).json({ message: 'Error downloading file', error: err.message });
      }
    });
  } catch (error) {
    console.error("Error in download route:", error);
    res.status(500).json({ message: 'Error downloading file', error: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));