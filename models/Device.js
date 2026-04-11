const mongoose = require('mongoose');

const DeviceSchema = new mongoose.Schema({
  deviceId: { type: String, unique: true, required: true }, // Expo Unique ID
  deviceName: String,
  assignedPlaylist: { type: mongoose.Schema.Types.ObjectId, ref: 'Playlist', default: null },
  status: { type: String, enum: ['online', 'offline'], default: 'offline' },
  lastSeen: { type: Date, default: Date.now },
  ipAddress: { type: String, default: '0.0.0.0' }, // Naya Field
  playCount: { type: Number, default: 0 }
});

module.exports = mongoose.model('Device', DeviceSchema);