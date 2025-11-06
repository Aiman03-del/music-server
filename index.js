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
  
  jwt.verify(token, jwtSecret, async (err, decoded) => {
    if (err) {
      console.log("Token verification error:", err);
      return res.status(401).send({ message: "unauthorized access" });
    }
    console.log("✅ JWT decoded:", decoded);
    
    // If type is not in JWT, fetch from database
    if (!decoded.type && decoded.uid) {
      try {
        const db = mongoose.connection.useDb("healers");
        const UserModel = db.models.User || db.model("User", userSchema);
        const dbUser = await UserModel.findOne({ uid: decoded.uid }).lean();
        if (dbUser) {
          decoded.type = dbUser.type || "user";
          console.log(`✅ User type fetched from DB: ${decoded.type}`);
        } else {
          decoded.type = "user"; // Default
        }
      } catch (dbErr) {
        console.error("Error fetching user type from DB:", dbErr);
        decoded.type = decoded.type || "user"; // Fallback
      }
    }
    
    req.user = decoded;
    next();
  });
};

// Socket.IO setup
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: function (origin, callback) {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      } else {
        return callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST"],
    allowedHeaders: ["my-custom-header"],
    credentials: true,
  },
});

// Socket.IO connection handler
io.on("connection", (socket) => {
  console.log("🔌 User connected:", socket.id);
  
  // Join user's personal room for notifications and chat
  socket.on("join:user", async (userId) => {
    // Check if user is admin and join admin room
    try {
      const db = mongoose.connection.useDb("healers");
      const UserModel = db.models.User || db.model("User", userSchema);
      const user = await UserModel.findOne({ uid: userId }).lean();
      if (user && user.type === "admin") {
        socket.join("admin:all"); // Join admin room for receiving all messages
        console.log(`👑 Admin ${userId} joined admin room`);
      }
    } catch (err) {
      console.error("Error checking user type:", err);
    }
    socket.join(userId);
    console.log(`✅ User ${userId} joined their room`);
  });
  
  // Join chat room
  socket.on("join:chat", (chatId) => {
    socket.join(chatId);
    console.log(`✅ Socket ${socket.id} joined chat ${chatId}`);
  });
  
  // Leave chat room
  socket.on("leave:chat", (chatId) => {
    socket.leave(chatId);
    console.log(`👋 Socket ${socket.id} left chat ${chatId}`);
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

// API route to get trending songs (most played)
// ⚠️ IMPORTANT: Must be BEFORE /api/songs/:id to avoid route conflict
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
    console.error("Error fetching trending songs:", err);
    res.status(500).json({ error: "Failed to fetch trending songs", details: err.message });
  }
});

// API route to get new releases
// ⚠️ IMPORTANT: Must be BEFORE /api/songs/:id to avoid route conflict
app.get("/api/songs/new-releases", async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 6;
    const songs = await Song.find()
      .sort({ createdAt: -1, _id: -1 })
      .limit(limit);
    res.json({ songs });
  } catch (err) {
    console.error("Error fetching new releases:", err);
    res.status(500).json({ error: "Failed to fetch new releases", details: err.message });
  }
});

// Get single song details by ID
// ⚠️ IMPORTANT: Must be AFTER specific routes like /trending and /new-releases
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
    console.error("Error fetching song details:", err);
    res.status(500).json({ error: "Failed to fetch song details", details: err.message });
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

// Chat Schema - Represents a conversation between a user/staff and admin
const chatSchema = new mongoose.Schema({
  userId: { type: String, required: true }, // User or staff who initiated the chat
  adminId: { type: String, default: null }, // Admin who is handling the chat
  lastMessage: { type: String, default: "" },
  lastMessageAt: { type: Date, default: Date.now },
  unreadCount: { type: Number, default: 0 }, // Unread messages for admin
  status: { type: String, enum: ["active", "closed"], default: "active" },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});
const Chat = db.models.Chat || db.model("Chat", chatSchema);

// Message Schema - Individual messages in a chat
const messageSchema = new mongoose.Schema({
  chatId: { type: mongoose.Schema.Types.ObjectId, ref: "Chat", required: true },
  senderId: { type: String, required: true }, // User ID who sent the message
  senderType: { type: String, enum: ["user", "staff", "admin"], required: true },
  message: { type: String, default: "" },
  // Music request fields
  isRequest: { type: Boolean, default: false }, // Is this a music addition request?
  requestData: {
    songName: { type: String, default: "" },
    artistName: { type: String, default: "" },
    movieName: { type: String, default: "" },
    youtubeLink: { type: String, default: "" },
    status: { type: String, enum: ["pending", "approved", "rejected", "added"], default: "pending" },
  },
  isRead: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});
const Message = db.models.Message || db.model("Message", messageSchema);

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

    // Check if user exists in DB first to preserve their type
    const db = mongoose.connection.useDb("healers");
    const UserModel = db.models.User || db.model("User", userSchema);
    const existingUser = await UserModel.findOne({ uid: decoded.uid }).lean();

    // If user exists, preserve their type; otherwise default to "user"
    const userType = existingUser?.type || "user";

    // Update user data - preserve existing type for existing users
    const updateData = {
      email: decoded.email,
      name: decoded.name || existingUser?.name || "",
      image: decoded.picture || existingUser?.image || "",
      provider: decoded.firebase?.sign_in_provider || existingUser?.provider || "google",
    };

    // Upsert user in MongoDB
    // For existing users: only update email, name, image, provider (preserve type)
    // For new users: set type to "user" and createdAt
    const user = await UserModel.findOneAndUpdate(
      { uid: decoded.uid },
      {
        $set: updateData,
        $setOnInsert: {
          type: "user", // Only set type to "user" if user is new
          createdAt: new Date(),
        },
      },
      { upsert: true, new: true }
    );

    // Ensure type is preserved for existing users (in case $setOnInsert didn't work)
    if (existingUser && existingUser.type && user.type !== existingUser.type) {
      user.type = existingUser.type;
      await user.save();
    }

    // Create JWT with user type from database
    const token = jwt.sign(
      {
        uid: decoded.uid,
        email: decoded.email,
        type: user.type || "user",
      },
      process.env.JWT_SECRET || "dev_secret",
      { expiresIn: "7d" }
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

app.post("/jwt", async (req, res) => {
  const { email, uid } = req.body;
  
  // Get user type from database
  const db = mongoose.connection.useDb("healers");
  const UserModel = db.models.User || db.model("User", userSchema);
  const user = await UserModel.findOne({ uid }).lean();
  
  const token = jwt.sign(
    { email, uid, type: user?.type || "user" },
    jwtSecret,
    { expiresIn: "365d" }
  );

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

// Get all admins
app.get("/api/admins", async (req, res) => {
  try {
    // Always use "healers" DB
    const db = mongoose.connection.useDb("healers");
    const UserModel = db.models.User || db.model("User", userSchema);
    const admins = await UserModel.find({ type: "admin" }).lean();
    
    console.log(`📋 Found ${admins.length} admins`);
    
    // Return only necessary fields
    const adminList = admins.map(admin => ({
      uid: admin.uid,
      name: admin.name || "",
      email: admin.email || "",
      image: admin.image || "",
      type: admin.type || "admin",
      createdAt: admin.createdAt,
      updatedAt: admin.updatedAt,
    }));
    
    res.json({ 
      success: true,
      count: adminList.length,
      admins: adminList 
    });
  } catch (err) {
    console.error("Failed to fetch admins:", err);
    res
      .status(500)
      .json({ error: "Failed to fetch admins", details: err.message });
  }
});

// Search users and staff (for admin to start chat)
// Search all logged-in users/staff (users who exist in database)
app.get("/api/users/search", verifyToken, async (req, res) => {
  try {
    // Only admin can search users
    if (req.user.type !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }
    
    const { q } = req.query; // Search query
    console.log(`🔍 Search request received: "${q}"`);
    
    if (!q || q.trim().length < 2) {
      return res.json({ success: true, count: 0, users: [] });
    }
    
    const db = mongoose.connection.useDb("healers");
    const UserModel = db.models.User || db.model("User", userSchema);
    
    const searchTerm = q.trim().toLowerCase();
    console.log(`🔍 Searching for: "${searchTerm}"`);
    
    // Get all logged-in users/staff (all users who exist in database)
    const allUsers = await UserModel.find({
      type: { $in: ["user", "staff"] }
    }).lean();
    
    console.log(`📊 Total users/staff in database: ${allUsers.length}`);
    
    // Filter by search term - search in name or email (case-insensitive partial match)
    const matchingUsers = allUsers.filter(user => {
      const name = (user.name || "").toLowerCase().trim();
      const email = (user.email || "").toLowerCase().trim();
      
      const nameMatch = name.includes(searchTerm);
      const emailMatch = email.includes(searchTerm);
      
      if (nameMatch || emailMatch) {
        console.log(`✅ Match found: ${user.name || user.email} (name: ${nameMatch}, email: ${emailMatch})`);
      }
      
      return nameMatch || emailMatch;
    });
    
    console.log(`📋 Found ${matchingUsers.length} matching users`);
    
    // Limit results
    const limitedUsers = matchingUsers.slice(0, 20);
    
    const userList = limitedUsers.map(user => ({
      uid: user.uid,
      name: user.name || user.email || "",
      email: user.email || "",
      image: user.image || "",
      type: user.type || "user",
    }));
    
    console.log(`🔍 Search "${q}" returning ${userList.length} users`);
    
    res.json({ 
      success: true,
      count: userList.length,
      users: userList 
    });
  } catch (err) {
    console.error("❌ Failed to search users:", err);
    res
      .status(500)
      .json({ error: "Failed to search users", details: err.message });
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

// ========== CHAT SYSTEM ==========

// Create or get chat for user/staff (they can only have one active chat with admin)
// Admin can also create chat with specific user by passing userId in body
app.post("/api/chat/create", verifyToken, async (req, res) => {
  try {
    const userType = req.user.type || "user";
    let userId = req.user.uid;
    
    // If admin is creating chat, use userId from body
    if (userType === "admin" && req.body.userId) {
      userId = req.body.userId;
    }
    
    if (!userId) {
      return res.status(400).json({ error: "userId is required" });
    }
    
    // Check if user already has an active chat
    let chat = await Chat.findOne({ userId, status: "active" });
    
    if (!chat) {
      // Get first available admin
      const db = mongoose.connection.useDb("healers");
      const UserModel = db.models.User || db.model("User", userSchema);
      const firstAdmin = await UserModel.findOne({ type: "admin" }).lean();
      const adminId = firstAdmin ? firstAdmin.uid : null;
      
      // Create new chat with adminId if admin exists
      chat = await Chat.create({
        userId,
        adminId: adminId,
        status: "active",
      });
      
      console.log(`✅ Created new chat ${chat._id} with adminId: ${adminId} for userId: ${userId}`);
    } else if (!chat.adminId) {
      // If chat exists but adminId is null, assign first admin
      const db = mongoose.connection.useDb("healers");
      const UserModel = db.models.User || db.model("User", userSchema);
      const firstAdmin = await UserModel.findOne({ type: "admin" }).lean();
      if (firstAdmin) {
        chat.adminId = firstAdmin.uid;
        await chat.save();
        console.log(`✅ Assigned admin ${firstAdmin.uid} to existing chat ${chat._id}`);
      }
    }
    
    res.json({ chat });
  } catch (err) {
    console.error("Create chat error:", err);
    res.status(500).json({ error: "Failed to create chat", details: err.message });
  }
});

// Send message (user/staff can send requests, admin can send regular messages)
app.post("/api/chat/message", verifyToken, async (req, res) => {
  try {
    const { chatId, message, isRequest, requestData } = req.body;
    const senderId = req.user.uid;
    const senderType = req.user.type === "admin" ? "admin" : (req.user.type === "staff" ? "staff" : "user");
    
    console.log(`💬 Message send request - Sender: ${senderId} (${senderType}), ChatId: ${chatId}`);
    
    if (!chatId) {
      return res.status(400).json({ error: "chatId is required" });
    }
    
    // Verify chat exists
    const chat = await Chat.findById(chatId);
    if (!chat) {
      console.error(`❌ Chat not found: ${chatId}`);
      return res.status(404).json({ error: "Chat not found" });
    }
    
    console.log(`✅ Chat found: ${chat._id}, UserId: ${chat.userId}, Status: ${chat.status}`);
    
    // If user/staff sending, ensure it's their chat
    if (senderType !== "admin" && chat.userId !== senderId) {
      return res.status(403).json({ error: "Not authorized" });
    }
    
    // If adminId is null, assign first available admin
    if (!chat.adminId) {
      const db = mongoose.connection.useDb("healers");
    const UserModel = db.models.User || db.model("User", userSchema);
      const firstAdmin = await UserModel.findOne({ type: "admin" }).lean();
      if (firstAdmin) {
        chat.adminId = firstAdmin.uid;
        await chat.save();
        console.log(`✅ Assigned admin ${firstAdmin.uid} to chat ${chat._id}`);
      }
    }
    
    // If admin sending, set adminId if not set (use current admin)
    if (senderType === "admin" && !chat.adminId) {
      chat.adminId = senderId;
      await chat.save();
    }
    
    // Validate request data if it's a request
    if (isRequest && requestData) {
      if (!requestData.songName?.trim() || !requestData.artistName?.trim()) {
        return res.status(400).json({ 
          error: "Song name and artist name are required for music requests" 
        });
      }
    }

    // Create message
    const newMessage = await Message.create({
      chatId,
      senderId,
      senderType,
      message: message || "",
      isRequest: isRequest || false,
      requestData: isRequest && requestData ? {
        songName: requestData.songName?.trim() || "",
        artistName: requestData.artistName?.trim() || "",
        movieName: requestData.movieName?.trim() || "", // Optional
        youtubeLink: requestData.youtubeLink?.trim() || "", // Optional
        status: "pending",
      } : undefined,
      isRead: senderType === "admin" ? true : false, // Admin messages are auto-read
    });
    
    // Update chat last message
    const messageText = isRequest 
      ? `Music Request: ${requestData?.songName || "New request"}`
      : message || "";
    
    chat.lastMessage = messageText;
    chat.lastMessageAt = new Date();
    chat.updatedAt = new Date();
    
    // Increment unread count if message is from user/staff
    if (senderType !== "admin") {
      chat.unreadCount = (chat.unreadCount || 0) + 1;
      console.log(`📊 Updated unread count: ${chat.unreadCount} for chat ${chat._id}`);
    } else {
      // If admin replied, reset unread count for user
      chat.unreadCount = 0;
    }
    
    await chat.save();
    console.log(`✅ Chat updated - Last message: "${messageText}", Unread: ${chat.unreadCount}`);
    
    // Emit real-time message via Socket.IO
    const populatedMessage = await Message.findById(newMessage._id).lean();
    // Convert chatId to string for consistency
    const chatIdStr = chatId.toString();
    const chatIdObjStr = chat._id.toString();
    
    // Ensure chatId in message is string
    populatedMessage.chatId = chatIdStr;
    
    // Emit to chat room
    io.to(chatIdStr).emit("chat:message", populatedMessage);
    // Also emit to user room
    io.to(chat.userId).emit("chat:message", populatedMessage);
    // Emit to all admins via admin room (all admins receive messages)
    io.to("admin:all").emit("chat:message:admin", populatedMessage);
    // Also emit globally for backward compatibility
    io.emit("chat:message:admin", populatedMessage);
    // Emit to all admins for new chats
    io.to("admin:all").emit("chat:new", { chatId: chatIdObjStr, userId: chat.userId });
    io.emit("chat:new", { chatId: chatIdObjStr, userId: chat.userId });
    
    res.json({ message: populatedMessage, chat });
  } catch (err) {
    console.error("Send message error:", err);
    res.status(500).json({ error: "Failed to send message", details: err.message });
  }
});

// Get all chats for admin (conversations list)
app.get("/api/chat/admin/conversations", verifyToken, async (req, res) => {
  try {
    console.log("📋 Admin conversations request - User:", req.user);
    console.log("📋 User type:", req.user.type);
    
    if (req.user.type !== "admin") {
      console.error("❌ Access denied - User type is not admin:", req.user.type);
      return res.status(403).json({ error: "Admin access required" });
    }
    
    console.log("📋 Admin requesting conversations list");
    
    const chats = await Chat.find({ status: "active" })
      .sort({ lastMessageAt: -1 })
      .limit(100);
    
    console.log(`📋 Found ${chats.length} active chats`);
    
    if (chats.length === 0) {
      console.log("⚠️ No active chats found in database");
    }
    
    // Populate user info for each chat
    const UserModel = db.models.User || db.model("User", userSchema);
    const conversations = await Promise.all(
      chats.map(async (chat) => {
        const user = await UserModel.findOne({ uid: chat.userId }).lean();
        console.log(`📋 Chat ${chat._id} - User: ${chat.userId}, Last message: ${chat.lastMessage}`);
        return {
          ...chat.toObject(),
          user: user ? {
            uid: user.uid,
            name: user.name,
            email: user.email,
            image: user.image,
            type: user.type,
          } : null,
        };
      })
    );

    console.log(`📋 Returning ${conversations.length} conversations`);
    res.json({ conversations });
  } catch (err) {
    console.error("Get conversations error:", err);
    res.status(500).json({ error: "Failed to get conversations", details: err.message });
  }
});

// Get messages for a specific chat
app.get("/api/chat/:chatId/messages", verifyToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const userId = req.user.uid;
    const userType = req.user.type;
    
    const chat = await Chat.findById(chatId);
    if (!chat) {
      return res.status(404).json({ error: "Chat not found" });
    }
    
    // Verify access
    if (userType !== "admin" && chat.userId !== userId) {
      return res.status(403).json({ error: "Not authorized" });
    }

    // Get messages
    const messages = await Message.find({ chatId })
      .sort({ createdAt: 1 })
      .limit(200);
    
    // Mark messages as read if admin is viewing
    if (userType === "admin") {
      await Message.updateMany(
        { chatId, isRead: false, senderType: { $ne: "admin" } },
      { isRead: true }
    );
      // Reset unread count
      chat.unreadCount = 0;
      await chat.save();
    }

    res.json({ messages });
  } catch (err) {
    console.error("Get messages error:", err);
    res.status(500).json({ error: "Failed to get messages", details: err.message });
  }
});

// Get user's chat (for user/staff)
app.get("/api/chat/user", verifyToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    console.log(`💬 User requesting chat - UserId: ${userId}`);
    
    let chat = await Chat.findOne({ userId, status: "active" });
    
    if (!chat) {
      console.log(`📝 Creating new chat for user: ${userId}`);
      // Get first available admin
      const db = mongoose.connection.useDb("healers");
    const UserModel = db.models.User || db.model("User", userSchema);
      const firstAdmin = await UserModel.findOne({ type: "admin" }).lean();
      const adminId = firstAdmin ? firstAdmin.uid : null;
      
      // Create new chat if doesn't exist
      chat = await Chat.create({
        userId,
        adminId: adminId,
        status: "active",
      });
      console.log(`✅ Chat created: ${chat._id} with adminId: ${adminId}`);
    } else {
      console.log(`✅ Existing chat found: ${chat._id}`);
      
      // If chat exists but adminId is null, assign first admin
      if (!chat.adminId) {
        const db = mongoose.connection.useDb("healers");
        const UserModel = db.models.User || db.model("User", userSchema);
        const firstAdmin = await UserModel.findOne({ type: "admin" }).lean();
        if (firstAdmin) {
          chat.adminId = firstAdmin.uid;
          await chat.save();
          console.log(`✅ Assigned admin ${firstAdmin.uid} to existing chat ${chat._id}`);
        }
      }
    }

    // Get messages
    const messages = await Message.find({ chatId: chat._id })
      .sort({ createdAt: 1 })
      .limit(200);
    
    console.log(`📨 Found ${messages.length} messages for chat ${chat._id}`);
    res.json({ chat, messages });
  } catch (err) {
    console.error("Get user chat error:", err);
    res.status(500).json({ error: "Failed to get chat", details: err.message });
  }
});

// Update request status (admin only)
app.put("/api/chat/request/:messageId/status", verifyToken, async (req, res) => {
  try {
    if (req.user.type !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }
    
    const { messageId } = req.params;
    const { status } = req.body; // "approved", "rejected", or "added"
    
    if (!["approved", "rejected", "added"].includes(status)) {
      return res.status(400).json({ error: "Invalid status. Must be 'approved', 'rejected', or 'added'" });
    }
    
    const message = await Message.findById(messageId);
    if (!message || !message.isRequest) {
      return res.status(404).json({ error: "Request not found" });
    }
    
    // Get chat to find userId
    const chat = await Chat.findById(message.chatId);
    if (!chat) {
      return res.status(404).json({ error: "Chat not found" });
    }
    
    // Update status
    message.requestData.status = status;
    await message.save();
    
    // If status is "added", send notification message to user and create notification
    if (status === "added") {
      const songName = message.requestData?.songName || "your requested song";
      const artistName = message.requestData?.artistName || "";
      const songInfo = artistName ? `${songName} by ${artistName}` : songName;
      const notificationMessageText = `Your song "${songInfo}" is added please check`;
      
      const notificationMessage = await Message.create({
        chatId: message.chatId,
        senderId: req.user.uid,
        senderType: "admin",
        message: notificationMessageText,
        isRequest: false,
        isRead: false,
      });
      
      // Update chat last message
      chat.lastMessage = notificationMessageText;
      chat.lastMessageAt = new Date();
      chat.updatedAt = new Date();
      await chat.save();
      
      // Emit notification message to user
      const populatedNotification = await Message.findById(notificationMessage._id).lean();
      const chatIdStr = chat._id.toString();
      populatedNotification.chatId = chatIdStr;
      
      // Emit to chat room and user room
      io.to(chatIdStr).emit("chat:message", populatedNotification);
      io.to(chat.userId).emit("chat:message", populatedNotification);
      
      // Create notification for navbar notification center
      const notification = await Notification.create({
        userId: chat.userId,
        type: "song_added",
        title: "Song Added Successfully",
        message: `Your song "${songInfo}" has been added. Please check!`,
        metadata: {
          chatId: chatIdStr,
          messageId: message._id.toString(),
          songName: songName,
          artistName: artistName,
        },
      });
      
      // Emit real-time notification via Socket.io
      io.to(chat.userId).emit("notification:new", notification);
      
      console.log(`✅ Sent notification message and notification to user ${chat.userId} about added song`);
    }
    
    // Emit status update
    io.to(message.chatId.toString()).emit("chat:request:updated", {
      messageId: message._id,
      status,
    });
    
    // Also emit to user's room
    io.to(chat.userId).emit("chat:request:updated", {
      messageId: message._id,
      status,
    });
    
    res.json({ message: "Request status updated", message });
  } catch (err) {
    console.error("Update request status error:", err);
    res.status(500).json({ error: "Failed to update status", details: err.message });
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
