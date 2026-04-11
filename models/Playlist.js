const mongoose = require('mongoose');

const PlaylistSchema = new mongoose.Schema({
  name: { type: String, required: true },
  items: [{
    fileUrl: { type: String, required: true },
    fileType: { type: String, enum: ['video', 'image'], default: 'video' },
    duration: { type: Number, default: 10 }, // seconds
    order: { type: Number },
    rotation: { 
    type: Number, 
    default: 0, 
    enum: [0, 90, 180, 270] // Sirf yehi values allowed hain
  }
  }],
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Playlist', PlaylistSchema);