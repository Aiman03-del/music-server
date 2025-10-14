require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");
const http = require("http");
const { Server } = require("socket.io");
const mongoose = require("mongoose");
const app = express();
const PORT = process.env.PORT || 5000;
const multer = require("multer");
const upload = multer({ storage: multer.memoryStorage() });
const ImageKit = require("imagekit");

// ✅ Add firebase-admin import and initialization
const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccountKey.json");
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

// Initialize ImageKit
const imagekit = new ImageKit({
  publicKey: process.env.IMAGEKIT_PUBLIC_KEY,
  privateKey: process.env.IMAGEKIT_PRIVATE_KEY,
  urlEndpoint: process.env.IMAGEKIT_URL_ENDPOINT,
});

// ✅ Define allowedOrigins before using in CORS middleware
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5173",
  "https://healers1.netlify.app",
  "https://audiovibe-21bd8.firebaseapp.com",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      } else {
        return callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true, // ✅ VERY IMPORTANT
  })
);
app.use(express.json());
app.use(cookieParser());
app.use(morgan("dev"));

// MongoDB Client
const client = new MongoClient(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverApi: ServerApiVersion.v1,
});
client
  .connect()
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// --- Always use "healers" DB for mongoose ---
mongoose.connection.on("connected", () => {
  // Switch to "healers" DB if not already
  if (mongoose.connection.name !== "healers") {
    mongoose.connection.useDb("healers");
  }
});
mongoose.set("strictQuery", false);
mongoose.connect(process.env.MONGO_URI + "/healers"); // force DB

// JWT secret
const jwtSecret = process.env.JWT_SECRET || "your_jwt_secret_here";

// ✅ Define verifyToken middleware before all routes
const verifyToken = async (req, res, next) => {
  const token = req.cookies?.token;
  console.log("Token received:", token);

  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      console.log("Token verification error:", err);
      return res.status(401).send({ message: "unauthorized access" });
    }
    console.log("✅ JWT decoded:", decoded);
    req.user = decoded;
    next();
  });
};

// Socket.IO setup
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    allowedHeaders: ["my-custom-header"],
    credentials: true,
  },
});

// Socket.IO connection handler
io.on("connection", (socket) => {
  console.log("🔌 User connected:", socket.id);
  
  // Join user's personal room for notifications
  socket.on("join:user", (userId) => {
    socket.join(userId);
    console.log(`✅ User ${userId} joined their room`);
  });
  
  // Leave user room
  socket.on("leave:user", (userId) => {
    socket.leave(userId);
    console.log(`👋 User ${userId} left their room`);
  });
  
  socket.on("disconnect", () => {
    console.log("❌ User disconnected:", socket.id);
  });
});

// --- SOCKET.IO REALTIME EVENTS ---
// Emit to all clients when a song is added, updated, or deleted
function emitSongsUpdate() {
  Song.find()
    .sort({ _id: -1 })
    .then((songs) => {
      io.emit("songs:update", songs);
    });
}

// Emit to all clients when users are updated (role change, etc)
function emitUsersUpdate() {
  const db = mongoose.connection.useDb("healers");
  const UserModel = db.models.User || db.model("User", userSchema);
  UserModel.find().then((users) => {
    io.emit("users:update", users);
  });
}

// Routes
app.get("/", (req, res) => {
  res.send("🎵 Audio Stream Server is Running!");
});

// User model with preferences
const userSchema = new mongoose.Schema({
  uid: String,
  email: String,
  name: String,
  image: String,
  type: String,
  createdAt: Date,
  provider: String,
  preferences: {
    favoriteGenres: [String],
    favoriteArtists: [String],
    moods: [String],
    listeningHabits: String,
    onboardingCompleted: { type: Boolean, default: false },
  },
});
const User = mongoose.models.User || mongoose.model("User", userSchema);

// User routes
app.post("/api/users", verifyToken, async (req, res) => {
  try {
    const { uid, email, name, image, type, createdAt, provider } = req.body;
    // Only allow user to create/update their own data
    if (!uid || !email)
      return res.status(400).json({ error: "uid and email required" });
    if (req.user?.uid !== uid) {
      return res
        .status(403)
        .json({ error: "Forbidden: Cannot modify another user's data" });
    }
    // Always use "healers" DB
    const user = await client
      .db("healers")
      .collection("users")
      .findOneAndUpdate(
        { uid },
        { $set: { uid, email, name, image, type, createdAt, provider } },
        { upsert: true, returnDocument: "after" }
      );
    res.status(201).json({ message: "User saved", user: user.value });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to save user", details: err.message });
  }
});

app.get("/api/users/:uid", verifyToken, async (req, res) => {
  try {
    if (req.user?.uid !== req.params.uid) {
      return res
        .status(403)
        .json({ error: "Forbidden: Cannot access another user's data" });
    }
    // Always use "healers" DB
    const db = mongoose.connection.useDb("healers");
    const UserModel = db.models.User || db.model("User", userSchema);
    const user = await UserModel.findOne({ uid: req.params.uid });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    return res.json({ user });
  } catch (err) {
    console.error("Error in GET /api/users/:uid:", err);
    res
      .status(500)
      .json({ error: "Internal server error", details: err.message });
  }
});

// Song model with playCount
const songSchema = new mongoose.Schema({
  title: String,
  artist: String,
  genre: [String],
  cover: String,
  audio: String,
  playCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});
const Song =
  mongoose.connection.useDb("healers").models.Song ||
  mongoose.connection.useDb("healers").model("Song", songSchema);

// API route to add a song (protected)
app.post("/api/songs", verifyToken, async (req, res) => {
  try {
    const { title, artist, genre, cover, audio } = req.body; // remove duration

    // Improved validation
    const errors = [];
    if (!title?.trim()) errors.push("Title is required");
    if (!artist?.trim()) errors.push("Artist is required");
    if (!genre || !Array.isArray(genre)) errors.push("Genre must be an array");
    if (!cover?.trim()) errors.push("Cover URL is required");
    if (!audio?.trim()) errors.push("Audio URL is required");

    if (errors.length > 0) {
      return res.status(400).json({ error: errors.join(", ") });
    }

    const song = new Song({
      title: title.trim(),
      artist: artist.trim(),
      genre: Array.isArray(genre) ? genre : [genre],
      cover,
      audio,
      // duration: req.body.duration, // Remove duration from model
    });

    await song.save();

    // Log activity
    await logActivity({
      uid: req.user.uid,
      action: "Added song",
      meta: { songId: song._id, title },
    });
    emitSongsUpdate(); // <-- realtime update
    res.status(201).json({ message: "Song added", song });
  } catch (err) {
    console.error("Server error in /api/songs:", err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// API route to get all songs (public) - sorted by playCount descending
app.get("/api/songs", async (req, res) => {
  try {
    const { q } = req.query;
    let filter = {};
    if (q && q.trim()) {
      const regex = new RegExp(q.trim(), "i");
      filter = {
        $or: [
          { title: regex },
          { artist: regex },
          { genre: { $elemMatch: { $regex: regex } } },
        ],
      };
    }
    const songs = await Song.find(filter).sort({ playCount: -1, _id: -1 });
    res.json({ songs });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch songs" });
  }
});

// Get single song details by ID
app.get("/api/songs/:id", async (req, res) => {
  try {
    const song = await Song.findById(req.params.id);
    if (!song) return res.status(404).json({ error: "Song not found" });
    
    // Get similar songs (same genre or artist)
    const similarSongs = await Song.find({
      $or: [
        { genre: { $in: song.genre } },
        { artist: song.artist }
      ],
      _id: { $ne: song._id } // Exclude current song
    })
      .sort({ playCount: -1 })
      .limit(6);
    
    res.json({ song, similarSongs });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch song details" });
  }
});

// API route to get trending songs (most played)
app.get("/api/songs/trending", async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 6;
    // Get songs with highest playCount, minimum 1 play
    const songs = await Song.find({ playCount: { $gte: 1 } })
      .sort({ playCount: -1, _id: -1 })
      .limit(limit);
    
    // If not enough songs with plays, fill with recent songs
    if (songs.length < limit) {
      const remaining = limit - songs.length;
      const recentSongs = await Song.find({ 
        _id: { $nin: songs.map(s => s._id) } 
      })
        .sort({ createdAt: -1 })
        .limit(remaining);
      songs.push(...recentSongs);
    }
    
    res.json({ songs });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch trending songs" });
  }
});

// API route to get new releases
app.get("/api/songs/new-releases", async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 6;
    const songs = await Song.find()
      .sort({ createdAt: -1, _id: -1 })
      .limit(limit);
    res.json({ songs });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch new releases" });
  }
});

// Update a song (protected)
app.put("/api/songs/:id", verifyToken, async (req, res) => {
  try {
    // Remove duration from update
    const { title, artist, genre, cover, audio } = req.body;
    const updateData = {
      title,
      artist,
      genre,
      cover,
      audio,
    };
    const updated = await Song.findByIdAndUpdate(req.params.id, updateData, {
      new: true,
    });
    if (!updated) return res.status(404).json({ error: "Song not found" });
    emitSongsUpdate(); // <-- realtime update
    // Log activity
    if (req.user?.uid) {
      await logActivity({
        uid: req.user.uid,
        action: "Updated song",
        meta: { songId: req.params.id },
      });
    }
    res.json({ message: "Song updated", song: updated });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to update song", details: err.message });
  }
});

// Delete a song (protected)
app.delete("/api/songs/:id", verifyToken, async (req, res) => {
  try {
    const deleted = await Song.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: "Song not found" });
    emitSongsUpdate(); // <-- realtime update
    res.json({ message: "Song deleted" });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to delete song", details: err.message });
  }
});

// Image upload route
app.post("/api/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    // Only allow image files
    if (!req.file.mimetype.startsWith("image/")) {
      return res.status(400).json({ error: "Only image files are allowed" });
    }

    // Use imagekit instance here
    const uploadResponse = await imagekit.upload({
      file: req.file.buffer,
      fileName: req.file.originalname,
    });

    res.json({ url: uploadResponse.url });
  } catch (err) {
    // Improved error logging
    console.error("ImageKit upload error:", err && (err.message || err));
    if (err && err.response && err.response.data) {
      console.error("ImageKit response data:", err.response.data);
    }
    res
      .status(500)
      .json({ error: "Image upload failed", details: err && err.message });
  }
});

// Audio upload route
app.post("/api/upload-audio", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    // Only allow audio files
    if (!req.file.mimetype.startsWith("audio/")) {
      return res.status(400).json({ error: "Only audio files are allowed" });
    }

    // Use imagekit instance here
    const uploadResponse = await imagekit.upload({
      file: req.file.buffer,
      fileName: req.file.originalname,
      folder: "audio",
    });

    res.json({ url: uploadResponse.url });
  } catch (err) {
    console.error("Audio upload error:", err && (err.message || err));
    res
      .status(500)
      .json({ error: "Audio upload failed", details: err && err.message });
  }
});

const playlistSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: "" },
  userId: { type: String, required: true },
  songs: [{ type: mongoose.Schema.Types.ObjectId, ref: "Song" }],
  createdAt: { type: Date, default: Date.now },
  playCount: { type: Number, default: 0 },
  isPublic: { type: Boolean, default: false },
  sharedWith: [{ type: String }], // Array of user IDs who have access
});

const db = mongoose.connection.useDb("healers");
const Playlist = db.models.Playlist || db.model("Playlist", playlistSchema);

// Invitation Schema
const invitationSchema = new mongoose.Schema({
  playlistId: { type: mongoose.Schema.Types.ObjectId, ref: "Playlist", required: true },
  fromUserId: { type: String, required: true }, // Who sent the invitation
  toUserId: { type: String, required: true }, // Who receives the invitation
  status: { type: String, enum: ["pending", "accepted", "rejected"], default: "pending" },
  createdAt: { type: Date, default: Date.now },
});
const Invitation = db.models.Invitation || db.model("Invitation", invitationSchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
  userId: { type: String, required: true }, // Who receives this notification
  type: { type: String, required: true }, // "playlist_invitation", "invitation_accepted", etc.
  title: { type: String, required: true },
  message: { type: String, required: true },
  isRead: { type: Boolean, default: false },
  metadata: { type: Object, default: {} }, // Extra data (playlistId, fromUser, etc.)
  createdAt: { type: Date, default: Date.now },
});
const Notification = db.models.Notification || db.model("Notification", notificationSchema);

// Create Playlist (protected)
app.post("/api/playlists", verifyToken, async (req, res) => {
  try {
    const { name, description, userId } = req.body;
    if (!name || !userId)
      return res.status(400).json({ error: "name and userId required" });
    const playlist = new Playlist({ name, description, userId, songs: [] });
    await playlist.save();
    res.status(201).json({ message: "Playlist created", id: playlist._id });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to create playlist", details: err.message });
  }
});

// Add Song to Playlist
app.post("/api/playlists/:playlistId/add-song", async (req, res) => {
  try {
    const { songId } = req.body;
    const { playlistId } = req.params;
    if (!songId) return res.status(400).json({ error: "songId required" });
    const playlist = await Playlist.findByIdAndUpdate(
      playlistId,
      { $addToSet: { songs: songId } },
      { new: true }
    ).populate("songs");
    if (!playlist) return res.status(404).json({ error: "Playlist not found" });
    // Log activity
    await logActivity({
      uid: playlist.userId,
      action: "Added song to playlist",
      meta: { playlistId, songId },
    });
    res.json({ message: "Song added to playlist", playlist });
  } catch (err) {
    res.status(400).json({ error: "Failed to add song", details: err.message });
  }
});

// Remove Song from Playlist
app.post("/api/playlists/:playlistId/remove-song", async (req, res) => {
  try {
    const { songId } = req.body;
    const { playlistId } = req.params;
    if (!songId) return res.status(400).json({ error: "songId required" });
    const playlist = await Playlist.findByIdAndUpdate(
      playlistId,
      { $pull: { songs: songId } },
      { new: true }
    ).populate("songs");
    if (!playlist) return res.status(404).json({ error: "Playlist not found" });
    // Log activity
    await logActivity({
      uid: playlist.userId,
      action: "Removed song from playlist",
      meta: { playlistId, songId },
    });
    res.json({ message: "Song removed from playlist", playlist });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to remove song", details: err.message });
  }
});

// Get Playlists by User (by userId)
app.get("/api/playlists/user/:userId", async (req, res) => {
  try {
    const playlists = await Playlist.find({ userId: req.params.userId });
    res.json(playlists);
  } catch (err) {
    res.status(500).json({ error: "Failed to get playlists" });
  }
});

// Get Playlist Details (with songs populated)
app.get("/api/playlists/:playlistId", async (req, res) => {
  try {
    const playlist = await Playlist.findById(req.params.playlistId).lean();
    if (!playlist) return res.status(404).json({ error: "Playlist not found" });
    // Populate songs array with song documents
    const songIds = (playlist.songs || []).map((id) => id.toString());
    const songs = await Song.find({ _id: { $in: songIds } });
    res.json({ ...playlist, songs });
  } catch (err) {
    res.status(500).json({ error: "Failed to load playlist" });
  }
});

// Remove Song from Playlist (PUT)
app.put("/api/playlists/:playlistId/remove", async (req, res) => {
  try {
    const { songId } = req.body;
    const playlist = await Playlist.findByIdAndUpdate(req.params.playlistId, {
      $pull: { songs: songId },
    });
    // Log activity
    if (playlist) {
      await logActivity({
        uid: playlist.userId,
        action: "Removed song from playlist",
        meta: { playlistId: req.params.playlistId, songId },
      });
    }
    res.json({ message: "Song removed from playlist" });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to remove song", details: err.message });
  }
});

// Add Song to Playlist (PUT, prevents duplicates)
app.put("/api/playlists/:playlistId/add", async (req, res) => {
  try {
    const { songId } = req.body;
    const playlist = await Playlist.findById(req.params.playlistId);
    const result = await Playlist.updateOne(
      { _id: req.params.playlistId },
      { $addToSet: { songs: songId } }
    );
    if (result.modifiedCount === 0) {
      return res.json({ message: "Already added" });
    } else {
      // Log activity
      if (playlist) {
        const isLiked = playlist.name === "Liked Songs";
        await logActivity({
          uid: playlist.userId,
          action: isLiked ? "Liked a song" : "Added song to playlist",
          meta: {
            playlistId: req.params.playlistId,
            songId,
            ...(isLiked && { liked: true }),
          },
        });
      }
      return res.json({ message: "Added successfully" });
    }
  } catch (err) {
    res.status(400).json({ error: "Failed to add song", details: err.message });
  }
});

// Remove Song from Playlist (PUT)
app.put("/api/playlists/:playlistId/remove", async (req, res) => {
  try {
    const { songId } = req.body;
    const playlist = await Playlist.findById(req.params.playlistId);
    await Playlist.findByIdAndUpdate(req.params.playlistId, {
      $pull: { songs: songId },
    });
    // Log activity
    if (playlist) {
      const isLiked = playlist.name === "Liked Songs";
      await logActivity({
        uid: playlist.userId,
        action: isLiked ? "Unliked a song" : "Removed song from playlist",
        meta: {
          playlistId: req.params.playlistId,
          songId,
          ...(isLiked && { liked: true }),
        },
      });
    }
    res.json({ message: "Song removed from playlist" });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to remove song", details: err.message });
  }
});

// Firebase Auth to Backend JWT bridge
app.post("/api/auth/login", async (req, res) => {
  try {
    const idToken = req.body.idToken;
    const decoded = await admin.auth().verifyIdToken(idToken);

    const token = jwt.sign(
      {
        uid: decoded.uid,
        email: decoded.email,
      },
      process.env.JWT_SECRET || "dev_secret",
      { expiresIn: "7d" }
    );

    // Save or update user in DB
    // You may want to extract more fields from decoded or request if available
    const userData = {
      uid: decoded.uid,
      email: decoded.email,
      name: decoded.name || "",
      image: decoded.picture || "",
      type: "user",
      createdAt: new Date(),
      provider: decoded.firebase?.sign_in_provider || "google",
    };

    // Upsert user in MongoDB
    const user = await mongoose.models.User.findOneAndUpdate(
      { uid: userData.uid },
      userData,
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    // Set JWT in cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // Return JWT and user data
    return res.json({
      message: "JWT set in cookie",
      token,
      user,
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(401).json({ error: "Unauthorized" });
  }
});

app.post("/jwt", (req, res) => {
  const { email, uid } = req.body;
  const token = jwt.sign({ email, uid }, jwtSecret, { expiresIn: "365d" });

  res
    .cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 365 * 24 * 60 * 60 * 1000,
    })
    .send({ success: true, token });
});

// Activity model
const activitySchema = new mongoose.Schema({
  uid: { type: String, required: true },
  action: { type: String, required: true },
  meta: { type: Object, default: {} },
  createdAt: { type: Date, default: Date.now },
});

// Helper to always get Activity model from the correct db context
function getActivityModel() {
  const db = mongoose.connection.useDb("healers");
  return db.models.Activity || db.model("Activity", activitySchema);
}

// Helper to log activity
async function logActivity({ uid, action, meta }) {
  if (!uid || !action) return;
  const Activity = getActivityModel();
  await Activity.create({ uid, action, meta });
}

// Activity API endpoints
app.post("/api/activity", async (req, res) => {
  try {
    const { uid, action, meta } = req.body;
    if (!uid || !action)
      return res.status(400).json({ error: "uid and action required" });
    const Activity = getActivityModel();
    const activity = await Activity.create({ uid, action, meta });
    res.status(201).json({ message: "Activity logged", activity });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to log activity", details: err.message });
  }
});

app.get("/api/activity/user/:uid", async (req, res) => {
  try {
    const Activity = getActivityModel();
    const activities = await Activity.find({ uid: req.params.uid })
      .sort({ createdAt: -1 })
      .limit(100);
    res.json({ activities });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch activities" });
  }
});

// --- Add activity logging to relevant routes ---

// Profile update (user save)
app.post("/api/users", async (req, res) => {
  try {
    const { uid, email, name, image, type, createdAt, provider } = req.body;
    if (!uid || !email)
      return res.status(400).json({ error: "uid and email required" });

    // Upsert user (update if exists, insert if not)
    const user = await User.findOneAndUpdate(
      { uid },
      { uid, email, name, image, type, createdAt, provider },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    // Log activity
    await logActivity({
      uid,
      action: "Profile updated",
      meta: { name, image },
    });
    res.status(201).json({ message: "User saved", user });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to save user", details: err.message });
  }
});

// Playlist create
app.post("/api/playlists", verifyToken, async (req, res) => {
  try {
    const { name, description, userId } = req.body;
    if (!name || !userId)
      return res.status(400).json({ error: "name and userId required" });
    const playlist = new Playlist({ name, description, userId, songs: [] });
    await playlist.save();
    // Log activity
    await logActivity({
      uid: userId,
      action: "Created playlist",
      meta: { name, playlistId: playlist._id },
    });
    res.status(201).json({ message: "Playlist created", id: playlist._id });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to create playlist", details: err.message });
  }
});

// Add Song to Playlist
app.post("/api/playlists/:playlistId/add-song", async (req, res) => {
  try {
    const { songId } = req.body;
    const { playlistId } = req.params;
    if (!songId) return res.status(400).json({ error: "songId required" });
    const playlist = await Playlist.findByIdAndUpdate(
      playlistId,
      { $addToSet: { songs: songId } },
      { new: true }
    ).populate("songs");
    if (!playlist) return res.status(404).json({ error: "Playlist not found" });
    // Log activity
    await logActivity({
      uid: playlist.userId,
      action: "Added song to playlist",
      meta: { playlistId, songId },
    });
    res.json({ message: "Song added to playlist", playlist });
  } catch (err) {
    res.status(400).json({ error: "Failed to add song", details: err.message });
  }
});

// Remove Song from Playlist
app.post("/api/playlists/:playlistId/remove-song", async (req, res) => {
  try {
    const { songId } = req.body;
    const { playlistId } = req.params;
    if (!songId) return res.status(400).json({ error: "songId required" });
    const playlist = await Playlist.findByIdAndUpdate(
      playlistId,
      { $pull: { songs: songId } },
      { new: true }
    ).populate("songs");
    if (!playlist) return res.status(404).json({ error: "Playlist not found" });
    // Log activity
    await logActivity({
      uid: playlist.userId,
      action: "Removed song from playlist",
      meta: { playlistId, songId },
    });
    res.json({ message: "Song removed from playlist", playlist });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to remove song", details: err.message });
  }
});

// Remove Song from Playlist (PUT)
app.put("/api/playlists/:playlistId/remove", async (req, res) => {
  try {
    const { songId } = req.body;
    const playlist = await Playlist.findByIdAndUpdate(req.params.playlistId, {
      $pull: { songs: songId },
    });
    // Log activity
    if (playlist) {
      await logActivity({
        uid: playlist.userId,
        action: "Removed song from playlist",
        meta: { playlistId: req.params.playlistId, songId },
      });
    }
    res.json({ message: "Song removed from playlist" });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to remove song", details: err.message });
  }
});

// Add Song to Playlist (PUT, prevents duplicates)
app.put("/api/playlists/:playlistId/add", async (req, res) => {
  try {
    const { songId } = req.body;
    const playlist = await Playlist.findById(req.params.playlistId);
    const result = await Playlist.updateOne(
      { _id: req.params.playlistId },
      { $addToSet: { songs: songId } }
    );
    if (result.modifiedCount === 0) {
      return res.json({ message: "Already added" });
    } else {
      // Log activity
      if (playlist) {
        const isLiked = playlist.name === "Liked Songs";
        await logActivity({
          uid: playlist.userId,
          action: isLiked ? "Liked a song" : "Added song to playlist",
          meta: {
            playlistId: req.params.playlistId,
            songId,
            ...(isLiked && { liked: true }),
          },
        });
      }
      return res.json({ message: "Added successfully" });
    }
  } catch (err) {
    res.status(400).json({ error: "Failed to add song", details: err.message });
  }
});

// Playlist delete
app.delete("/api/playlists/:playlistId", verifyToken, async (req, res) => {
  try {
    const playlistId = req.params.playlistId;
    const userId = req.query.uid;
    const playlist = await Playlist.findById(playlistId);
    if (!playlist) return res.status(404).json({ error: "Playlist not found" });
    if (playlist.userId !== userId) {
      return res
        .status(403)
        .json({ error: "Not authorized to delete this playlist" });
    }
    await Playlist.deleteOne({ _id: playlistId });
    // Log activity
    await logActivity({
      uid: userId,
      action: "Deleted playlist",
      meta: { playlistId },
    });
    res.json({ message: "Playlist deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete playlist" });
  }
});

// Like/Unlike (handled as add/remove song from "Liked Songs" playlist)
// Already covered above with add/remove song from playlist

// Update user preferences
app.put("/api/users/:uid/preferences", async (req, res) => {
  try {
    const { uid } = req.params;
    const { favoriteGenres, favoriteArtists, moods, listeningHabits } = req.body;
    
    const db = mongoose.connection.useDb("healers");
    const UserModel = db.models.User || db.model("User", userSchema);
    
    const user = await UserModel.findOneAndUpdate(
      { uid },
      {
        $set: {
          preferences: {
            favoriteGenres: favoriteGenres || [],
            favoriteArtists: favoriteArtists || [],
            moods: moods || [],
            listeningHabits: listeningHabits || "",
            onboardingCompleted: true,
          },
        },
      },
      { new: true }
    );
    
    if (!user) return res.status(404).json({ error: "User not found" });
    
    await logActivity({
      uid,
      action: "Completed onboarding",
      meta: { preferences: { favoriteGenres, favoriteArtists, moods, listeningHabits } },
    });
    
    res.json({ message: "Preferences saved", user });
  } catch (err) {
    res.status(400).json({ error: "Failed to save preferences", details: err.message });
  }
});

// Get personalized recommendations for user
app.get("/api/recommendations/:uid", async (req, res) => {
  try {
    const { uid } = req.params;
    const limit = parseInt(req.query.limit) || 10;
    
    const db = mongoose.connection.useDb("healers");
    const UserModel = db.models.User || db.model("User", userSchema);
    const user = await UserModel.findOne({ uid });
    
    if (!user || !user.preferences || !user.preferences.onboardingCompleted) {
      // Return trending songs if no preferences
      const songs = await Song.find()
        .sort({ playCount: -1, createdAt: -1 })
        .limit(limit);
      return res.json({ songs, personalized: false });
    }
    
    const { favoriteGenres, favoriteArtists } = user.preferences;
    
    // Build query based on preferences
    let query = {};
    const conditions = [];
    
    if (favoriteGenres && favoriteGenres.length > 0) {
      conditions.push({ genre: { $in: favoriteGenres } });
    }
    
    if (favoriteArtists && favoriteArtists.length > 0) {
      conditions.push({ artist: { $in: favoriteArtists } });
    }
    
    if (conditions.length > 0) {
      query = { $or: conditions };
    }
    
    // Get songs matching preferences, sorted by playCount
    const songs = await Song.find(query)
      .sort({ playCount: -1, createdAt: -1 })
      .limit(limit);
    
    // If not enough songs, fill with popular songs from preferred genres
    if (songs.length < limit && favoriteGenres && favoriteGenres.length > 0) {
      const remaining = limit - songs.length;
      const additionalSongs = await Song.find({
        genre: { $in: favoriteGenres },
        _id: { $nin: songs.map(s => s._id) },
      })
        .sort({ playCount: -1 })
        .limit(remaining);
      songs.push(...additionalSongs);
    }
    
    res.json({ songs, personalized: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to get recommendations" });
  }
});

// Admin: Update user role
app.put("/api/users/:uid/role", async (req, res) => {
  try {
    const { type } = req.body;
    const { uid } = req.params;
    if (!["user", "staff", "admin"].includes(type)) {
      return res.status(400).json({ error: "Invalid role" });
    }
    // Always use "healers" DB for user update
    const db = mongoose.connection.useDb("healers");
    const UserModel = db.models.User || db.model("User", userSchema);
    const user = await UserModel.findOneAndUpdate(
      { uid },
      { type },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: "User not found" });
    await logActivity({ uid, action: "Role updated", meta: { newRole: type } });
    emitUsersUpdate();
    console.log("User role updated in DB:", user);
    res.json({
      message: "Role updated",
      user,
      info: {
        uid: user.uid,
        name: user.name,
        email: user.email,
        type: user.type,
        image: user.image,
        provider: user.provider,
        createdAt: user.createdAt,
      },
    });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to update role", details: err.message });
  }
});

// Song add/update
app.post("/api/songs", verifyToken, async (req, res) => {
  try {
    const { title, artist, genre, cover, audio } = req.body;
    const song = new Song({
      title,
      artist,
      genre:
        typeof genre === "string"
          ? genre.split(",").map((g) => g.trim())
          : genre,
      cover,
      audio,
    });
    await song.save();
    // Log activity
    if (req.user?.uid) {
      await logActivity({
        uid: req.user.uid,
        action: "Added song",
        meta: { songId: song._id, title },
      });
    }
    emitSongsUpdate(); // <-- realtime update
    res.status(201).json({ message: "Song added", song });
  } catch (err) {
    res.status(400).json({ error: "Failed to add song", details: err.message });
  }
});

app.put("/api/songs/:id", verifyToken, async (req, res) => {
  try {
    // Remove duration from update
    const { title, artist, genre, cover, audio } = req.body;
    const updateData = {
      title,
      artist,
      genre,
      cover,
      audio,
    };
    const updated = await Song.findByIdAndUpdate(req.params.id, updateData, {
      new: true,
    });
    if (!updated) return res.status(404).json({ error: "Song not found" });
    emitSongsUpdate(); // <-- realtime update
    // Log activity
    if (req.user?.uid) {
      await logActivity({
        uid: req.user.uid,
        action: "Updated song",
        meta: { songId: req.params.id },
      });
    }
    res.json({ message: "Song updated", song: updated });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to update song", details: err.message });
  }
});

// Increment playCount
app.post("/api/songs/:id/play", async (req, res) => {
  try {
    const { id } = req.params;
    const song = await Song.findByIdAndUpdate(
      id,
      { $inc: { playCount: 1 } },
      { new: true }
    );
    if (!song) return res.status(404).json({ error: "Song not found" });
    res.json({ message: "Play count updated", song });
  } catch (err) {
    res
      .status(500)
      .json({ error: "Failed to update play count", details: err.message });
  }
});

// Add this route to return all users
app.get("/api/users", async (req, res) => {
  try {
    // Always use "healers" DB
    const db = mongoose.connection.useDb("healers");
    const UserModel = db.models.User || db.model("User", userSchema);
    const users = await UserModel.find();
    res.json({ users });
  } catch (err) {
    console.error("Failed to fetch users:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch users", details: err.message });
  }
});

// Fetch multiple songs by IDs (for "Songs For You" suggestions)
app.post("/api/songs/by-ids", async (req, res) => {
  try {
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: "ids array required" });
    }
    // Convert string IDs to ObjectId
    const objectIds = ids.map((id) => mongoose.Types.ObjectId(id));
    const songs = await Song.find({ _id: { $in: objectIds } });
    res.json({ songs });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch songs by ids" });
  }
});

// Increment playlist playCount
app.put("/api/playlists/:playlistId/increment-play", async (req, res) => {
  try {
    const { playlistId } = req.params;
    const playlist = await Playlist.findByIdAndUpdate(
      playlistId,
      { $inc: { playCount: 1 } },
      { new: true }
    );
    if (!playlist) return res.status(404).json({ error: "Playlist not found" });
    res.json({ message: "Play count updated", playlist });
  } catch (err) {
    res
      .status(500)
      .json({ error: "Failed to increment play count", details: err.message });
  }
});

// ========== PLAYLIST SHARING SYSTEM ==========

// Toggle playlist public/private
app.put("/api/playlists/:playlistId/toggle-public", verifyToken, async (req, res) => {
  try {
    const { playlistId } = req.params;
    const playlist = await Playlist.findById(playlistId);
    
    if (!playlist) return res.status(404).json({ error: "Playlist not found" });
    
    // Check if user owns this playlist
    if (playlist.userId !== req.user.uid) {
      return res.status(403).json({ error: "Not authorized" });
    }
    
    playlist.isPublic = !playlist.isPublic;
    await playlist.save();
    
    await logActivity({
      uid: req.user.uid,
      action: playlist.isPublic ? "Made playlist public" : "Made playlist private",
      meta: { playlistId, name: playlist.name },
    });
    
    res.json({ 
      message: `Playlist is now ${playlist.isPublic ? 'public' : 'private'}`, 
      isPublic: playlist.isPublic 
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to toggle visibility" });
  }
});

// Send playlist invitation to a user
app.post("/api/playlists/:playlistId/invite", verifyToken, async (req, res) => {
  try {
    const { playlistId } = req.params;
    const { toUserEmail } = req.body;
    
    if (!toUserEmail) {
      return res.status(400).json({ error: "User email is required" });
    }
    
    const playlist = await Playlist.findById(playlistId);
    if (!playlist) return res.status(404).json({ error: "Playlist not found" });
    
    // Check if sender owns this playlist
    if (playlist.userId !== req.user.uid) {
      return res.status(403).json({ error: "Not authorized" });
    }
    
    // Find the user to invite
    const db = mongoose.connection.useDb("healers");
    const UserModel = db.models.User || db.model("User", userSchema);
    const toUser = await UserModel.findOne({ email: toUserEmail });
    
    if (!toUser) {
      return res.status(404).json({ error: "User not found" });
    }
    
    // Check if already shared
    if (playlist.sharedWith.includes(toUser.uid)) {
      return res.status(400).json({ error: "Playlist already shared with this user" });
    }
    
    // Check if invitation already exists
    const existingInvite = await Invitation.findOne({
      playlistId,
      toUserId: toUser.uid,
      status: "pending",
    });
    
    if (existingInvite) {
      return res.status(400).json({ error: "Invitation already sent" });
    }
    
    // Create invitation
    const invitation = await Invitation.create({
      playlistId,
      fromUserId: req.user.uid,
      toUserId: toUser.uid,
    });
    
    // Create notification for the recipient
    const fromUser = await UserModel.findOne({ uid: req.user.uid });
    const notification = await Notification.create({
      userId: toUser.uid,
      type: "playlist_invitation",
      title: "New Playlist Invitation",
      message: `${fromUser.name || fromUser.email} invited you to "${playlist.name}"`,
      metadata: {
        invitationId: invitation._id,
        playlistId,
        playlistName: playlist.name,
        fromUserId: req.user.uid,
        fromUserName: fromUser.name || fromUser.email,
      },
    });
    
    // Emit real-time notification via Socket.io
    io.to(toUser.uid).emit("notification:new", notification);
    
    res.json({ 
      message: "Invitation sent successfully", 
      invitation,
      notification 
    });
  } catch (err) {
    console.error("Invitation error:", err);
    res.status(500).json({ error: "Failed to send invitation" });
  }
});

// Accept playlist invitation
app.put("/api/invitations/:invitationId/accept", verifyToken, async (req, res) => {
  try {
    const { invitationId } = req.params;
    const invitation = await Invitation.findById(invitationId);
    
    if (!invitation) {
      return res.status(404).json({ error: "Invitation not found" });
    }
    
    // Check if user is the recipient
    if (invitation.toUserId !== req.user.uid) {
      return res.status(403).json({ error: "Not authorized" });
    }
    
    if (invitation.status !== "pending") {
      return res.status(400).json({ error: "Invitation already processed" });
    }
    
    // Update invitation status
    invitation.status = "accepted";
    await invitation.save();
    
    // Add user to playlist's sharedWith array
    await Playlist.findByIdAndUpdate(invitation.playlistId, {
      $addToSet: { sharedWith: req.user.uid },
    });
    
    // Create notification for playlist owner
    const playlist = await Playlist.findById(invitation.playlistId);
    const db = mongoose.connection.useDb("healers");
    const UserModel = db.models.User || db.model("User", userSchema);
    const acceptedUser = await UserModel.findOne({ uid: req.user.uid });
    
    const notification = await Notification.create({
      userId: invitation.fromUserId,
      type: "invitation_accepted",
      title: "Invitation Accepted",
      message: `${acceptedUser.name || acceptedUser.email} accepted your playlist invitation`,
      metadata: {
        playlistId: invitation.playlistId,
        playlistName: playlist.name,
        acceptedByUserId: req.user.uid,
        acceptedByUserName: acceptedUser.name || acceptedUser.email,
      },
    });
    
    // Emit real-time notification
    io.to(invitation.fromUserId).emit("notification:new", notification);
    
    // Mark the invitation notification as read
    await Notification.updateMany(
      { 
        userId: req.user.uid,
        "metadata.invitationId": invitationId 
      },
      { isRead: true }
    );
    
    res.json({ message: "Invitation accepted", invitation });
  } catch (err) {
    console.error("Accept invitation error:", err);
    res.status(500).json({ error: "Failed to accept invitation" });
  }
});

// Reject playlist invitation
app.put("/api/invitations/:invitationId/reject", verifyToken, async (req, res) => {
  try {
    const { invitationId } = req.params;
    const invitation = await Invitation.findById(invitationId);
    
    if (!invitation) {
      return res.status(404).json({ error: "Invitation not found" });
    }
    
    if (invitation.toUserId !== req.user.uid) {
      return res.status(403).json({ error: "Not authorized" });
    }
    
    invitation.status = "rejected";
    await invitation.save();
    
    // Mark notification as read
    await Notification.updateMany(
      { 
        userId: req.user.uid,
        "metadata.invitationId": invitationId 
      },
      { isRead: true }
    );
    
    res.json({ message: "Invitation rejected", invitation });
  } catch (err) {
    res.status(500).json({ error: "Failed to reject invitation" });
  }
});

// Get user's notifications
app.get("/api/notifications/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const notifications = await Notification.find({ userId })
      .sort({ createdAt: -1 })
      .limit(50);
    
    const unreadCount = await Notification.countDocuments({ 
      userId, 
      isRead: false 
    });
    
    res.json({ notifications, unreadCount });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch notifications" });
  }
});

// Mark notification as read
app.put("/api/notifications/:notificationId/read", async (req, res) => {
  try {
    const { notificationId } = req.params;
    await Notification.findByIdAndUpdate(notificationId, { isRead: true });
    res.json({ message: "Notification marked as read" });
  } catch (err) {
    res.status(500).json({ error: "Failed to mark notification as read" });
  }
});

// Mark all notifications as read for a user
app.put("/api/notifications/user/:userId/read-all", async (req, res) => {
  try {
    const { userId } = req.params;
    await Notification.updateMany({ userId }, { isRead: true });
    res.json({ message: "All notifications marked as read" });
  } catch (err) {
    res.status(500).json({ error: "Failed to mark all as read" });
  }
});

// Get playlists shared with user
app.get("/api/playlists/shared/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const sharedPlaylists = await Playlist.find({ 
      sharedWith: userId 
    });
    res.json(sharedPlaylists);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch shared playlists" });
  }
});

// Get public playlists (for discovery)
app.get("/api/playlists/public/all", async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    const publicPlaylists = await Playlist.find({ isPublic: true })
      .sort({ playCount: -1, createdAt: -1 })
      .limit(limit);
    res.json(publicPlaylists);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch public playlists" });
  }
});

// Get trending public playlists (most played)
app.get("/api/playlists/public/trending", async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 6;
    // Get public playlists with highest playCount, with at least 1 song
    const playlists = await Playlist.find({ 
      isPublic: true,
      $expr: { $gt: [{ $size: "$songs" }, 0] } // At least 1 song
    })
      .sort({ playCount: -1, createdAt: -1 })
      .limit(limit);
    
    // Populate first song for each playlist (for cover image)
    const playlistsWithCovers = await Promise.all(
      playlists.map(async (pl) => {
        const playlistObj = pl.toObject();
        if (playlistObj.songs && playlistObj.songs.length > 0) {
          const firstSong = await Song.findById(playlistObj.songs[0]);
          playlistObj.firstSongCover = firstSong?.cover || null;
        }
        return playlistObj;
      })
    );
    
    res.json({ playlists: playlistsWithCovers });
  } catch (err) {
    console.error("Failed to fetch trending playlists:", err);
    res.status(500).json({ error: "Failed to fetch trending playlists" });
  }
});

// Delete user from Firebase and MongoDB
app.delete("/api/users/:uid", async (req, res) => {
  const { uid } = req.params;
  try {
    // Delete from Firebase
    await admin.auth().deleteUser(uid);

    // Delete from MongoDB
    const db = mongoose.connection.useDb("healers");
    const UserModel = db.models.User || db.model("User", userSchema);
    const user = await UserModel.findOneAndDelete({ uid });

    // Log activity
    await logActivity({
      uid,
      action: "Deleted user",
      meta: { deletedBy: req.user?.uid || "admin" },
    });

    emitUsersUpdate();

    res.json({ message: "User deleted from Firebase and DB", user });
  } catch (err) {
    console.error("Failed to delete user:", err);
    res
      .status(500)
      .json({ error: "Failed to delete user", details: err.message });
  }
});

// Start server
server.listen(PORT, () => {
  console.log(`🔥 Server is running on port ${PORT}`);
});
// 🔌 Connect DB
mongoose
  .connect(process.env.MONGO_URI + "/healers")
  .catch((err) => console.error("❌ DB Connection Error:", err));
