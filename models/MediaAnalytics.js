const mongoose = require('mongoose')

const MediaAnalyticsSchema = new mongoose.Schema(
  {
    playlistId: { type: mongoose.Schema.Types.ObjectId, ref: 'Playlist', required: true, index: true },
    itemId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
    fileUrl: { type: String, required: true },
    fileType: { type: String, enum: ['video', 'image'], required: true },
    rotation: { type: Number, default: 0 },
    duration: { type: Number, default: 10 },
    totalPlays: { type: Number, default: 0 },
    perDevicePlays: { type: Map, of: Number, default: {} },
    lastPlayedAt: { type: Date, default: null }
  },
  { timestamps: true }
)

MediaAnalyticsSchema.index({ playlistId: 1, itemId: 1 }, { unique: true })

module.exports = mongoose.model('MediaAnalytics', MediaAnalyticsSchema)

