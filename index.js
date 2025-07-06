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

// ✅ Add firebase-admin import and initialization
const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccountKey.json");
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

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

// Routes
app.get("/", (req, res) => {
  res.send("🎵 Audio Stream Server is Running!");
});

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
    const user = await client
      .db("music")
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
    // Only allow user to access their own data
    if (req.user?.uid !== req.params.uid) {
      return res
        .status(403)
        .json({ error: "Forbidden: Cannot access another user's data" });
    }
    const user = await client
      .db("music")
      .collection("users")
      .findOne({ uid: req.params.uid });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ user });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to fetch user", details: err.message });
  }
});

// Song model (minimal, for demo)
const songSchema = new mongoose.Schema({
  title: String,
  artist: String,
  genre: [String],
  cover: String,
  audio: String,
  duration: Number,
});
const Song = mongoose.models.Song || mongoose.model("Song", songSchema);

// API route to add a song (protected)
app.post("/api/songs", verifyToken, async (req, res) => {
  try {
    if (!req.user || !req.user.uid) {
      return res
        .status(401)
        .json({ error: "Unauthorized: No user in request" });
    }
    const { title, artist, genre, cover, audio, duration } = req.body;
    const song = new Song({
      title,
      artist,
      genre:
        typeof genre === "string"
          ? genre.split(",").map((g) => g.trim())
          : genre,
      cover,
      audio,
      duration: Number(duration),
    });
    await song.save();
    // Log activity for the user who added the song
    await logActivity({
      uid: req.user.uid,
      action: "Added song",
      meta: { songId: song._id, title },
    });
    res.status(201).json({ message: "Song added", song });
  } catch (err) {
    res.status(400).json({ error: "Failed to add song", details: err.message });
  }
});

// API route to get all songs (public)
app.get("/api/songs", async (req, res) => {
  try {
    const songs = await Song.find().sort({ _id: -1 });
    res.json({ songs });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch songs" });
  }
});

// Update a song (protected)
app.put("/api/songs/:id", verifyToken, async (req, res) => {
  try {
    const updated = await Song.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });
    if (!updated) return res.status(404).json({ error: "Song not found" });
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

// Playlist model (update structure)
const playlistSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, default: "" },
  userId: { type: String, required: true },
  songs: [{ type: mongoose.Schema.Types.ObjectId, ref: "Song" }],
  createdAt: { type: Date, default: Date.now },
  playCount: { type: Number, default: 0 },
});
const Playlist =
  mongoose.models.Playlist || mongoose.model("Playlist", playlistSchema);

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

// Get Top Played Playlists
app.get("/api/playlists/top", async (req, res) => {
  try {
    const playlists = await Playlist.find().sort({ playCount: -1 }).limit(5);
    res.json(playlists);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch top playlists" });
  }
});

// Firebase Auth to Backend JWT bridge
app.post("/api/auth/login", async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ error: "No idToken provided" });

    const decoded = await admin.auth().verifyIdToken(idToken);

    const payload = { uid: decoded.uid, email: decoded.email };
    const token = jwt.sign(payload, jwtSecret, { expiresIn: "7d" });

    // ✅ Set cookie for cross-origin (Render/production)
    res.cookie("token", token, {
      httpOnly: true,
      secure: true, // ✅ Render এ HTTPS, তাই secure:true দরকার
      sameSite: "None", // ✅ Cross-site cookie allow করার জন্য
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 দিন
    });

    res.json({ message: "JWT set", uid: decoded.uid });
  } catch (err) {
    console.error("JWT bridge error:", err);
    res.status(401).json({ error: "Invalid Firebase token" });
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
const Activity =
  mongoose.models.Activity || mongoose.model("Activity", activitySchema);

// Helper to log activity
async function logActivity({ uid, action, meta }) {
  if (!uid || !action) return;
  await Activity.create({ uid, action, meta });
}

// Activity API endpoints
app.post("/api/activity", async (req, res) => {
  try {
    const { uid, action, meta } = req.body;
    if (!uid || !action)
      return res.status(400).json({ error: "uid and action required" });
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

// Admin: Update user role
app.put("/api/users/:uid/role", async (req, res) => {
  try {
    const { type } = req.body;
    const { uid } = req.params;
    if (!["user", "staff", "admin"].includes(type)) {
      return res.status(400).json({ error: "Invalid role" });
    }
    const user = await User.findOneAndUpdate({ uid }, { type }, { new: true });
    if (!user) return res.status(404).json({ error: "User not found" });
    // Log activity (admin action)
    await logActivity({ uid, action: "Role updated", meta: { newRole: type } });
    res.json({ message: "Role updated", user });
  } catch (err) {
    res
      .status(400)
      .json({ error: "Failed to update role", details: err.message });
  }
});

// Song add/update
app.post("/api/songs", verifyToken, async (req, res) => {
  try {
    const { title, artist, genre, cover, audio, duration } = req.body;
    const song = new Song({
      title,
      artist,
      genre:
        typeof genre === "string"
          ? genre.split(",").map((g) => g.trim())
          : genre,
      cover,
      audio,
      duration: Number(duration),
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
    res.status(201).json({ message: "Song added", song });
  } catch (err) {
    res.status(400).json({ error: "Failed to add song", details: err.message });
  }
});

app.put("/api/songs/:id", verifyToken, async (req, res) => {
  try {
    const updated = await Song.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });
    if (!updated) return res.status(404).json({ error: "Song not found" });
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

// Start server
server.listen(PORT, () => {
  console.log(`🔥 Server is running on port ${PORT}`);
});
// 🔌 Connect DB
mongoose
  .connect(process.env.MONGO_URI)
  .catch((err) => console.error("❌ DB Connection Error:", err));

// All secrets are loaded from process.env, nothing to change here.
// All secrets are loaded from process.env, nothing to change here.
// All secrets are loaded from process.env, nothing to change here.
// All secrets are loaded from process.env, nothing to change here.
// All secrets are loaded from process.env, nothing to change here.
// All secrets are loaded from process.env, nothing to change here.
// All secrets are loaded from process.env, nothing to change here.
// All secrets are loaded from process.env, nothing to change here.
