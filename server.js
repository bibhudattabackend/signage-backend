const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const multer = require('multer')
const path = require('path')
const fs = require('fs')
const http = require('http')
const { Server } = require('socket.io')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const cloudinary = require('cloudinary').v2
require('dotenv').config()

function initCloudinary() {
  const n = process.env.CLOUDINARY_CLOUD_NAME
  const k = process.env.CLOUDINARY_API_KEY
  const s = process.env.CLOUDINARY_API_SECRET
  if (n && k && s) {
    cloudinary.config({ cloud_name: n, api_key: k, api_secret: s })
    console.log('✅ Cloudinary configured')
    return true
  }
  console.warn('⚠️  Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET — playlist uploads will fail until then')
  return false
}
const cloudinaryReady = initCloudinary()

const Playlist = require('./models/Playlist')
const Device = require('./models/Device')
const Admin = require('./models/Admin')
const MediaAnalytics = require('./models/MediaAnalytics')

const app = express()
const server = http.createServer(app)

const CORS_ORIGIN = process.env.CORS_ORIGIN
const corsOrigins = CORS_ORIGIN ? CORS_ORIGIN.split(',').map((s) => s.trim()) : null

const io = new Server(server, {
  cors: { origin: corsOrigins || '*' }
})

if (corsOrigins) {
  app.use(cors({ origin: corsOrigins }))
} else {
  app.use(cors())
}
app.use(express.json())
app.use('/uploads', express.static('uploads'))

const PORT = process.env.PORT || 3000
const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET) throw new Error('JWT_SECRET must be set in .env')
// const BASE_URL = process.env.BASE_URL || `http://192.168.31.73:${PORT}`

function requirePlayerJwt() {
  const v = process.env.REQUIRE_PLAYER_JWT
  return v === 'true' || v === '1'
}

function playerJwtSecret() {
  return process.env.PLAYER_JWT_SECRET || JWT_SECRET
}

function signPlayerJwt(deviceId) {
  const exp = process.env.PLAYER_JWT_EXPIRES || '365d'
  return jwt.sign({ typ: 'player', deviceId }, playerJwtSecret(), { expiresIn: exp })
}

function verifyPlayerJwtPayload(token) {
  const p = jwt.verify(token, playerJwtSecret())
  if (p.typ !== 'player' || !p.deviceId) throw new Error('invalid_player')
  return p
}

function deviceRoom(deviceId) {
  return `device:${deviceId}`
}

function getOnlineDeviceIds() {
  const ids = []
  for (const [name, room] of io.sockets.adapter.rooms) {
    if (name.startsWith('device:') && room.size > 0) ids.push(name.slice(7))
  }
  return ids
}

function broadcastActiveDevices() {
  io.emit('active-devices-list', getOnlineDeviceIds())
}

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).json({ message: 'Unauthorized' })
  try {
    req.admin = jwt.verify(token, JWT_SECRET)
    next()
  } catch {
    res.status(403).json({ message: 'Invalid token' })
  }
}

function verifyPlayerRequest(req, res, next) {
  if (!requirePlayerJwt()) return next()
  const auth = req.headers.authorization
  const bearer = auth?.startsWith('Bearer ') ? auth.slice(7).trim() : null
  if (!bearer) {
    return res.status(401).json({ message: 'Player JWT required (Authorization: Bearer …)' })
  }
  try {
    const p = verifyPlayerJwtPayload(bearer)
    if (p.deviceId !== req.params.deviceId) {
      return res.status(403).json({ message: 'JWT is for a different device' })
    }
    next()
  } catch {
    return res.status(401).json({ message: 'Invalid or expired player JWT' })
  }
}

mongoose
  .connect(process.env.MONGO_URI || 'mongodb://localhost:27017/signage_db')
  .then(() => console.log('✅ MongoDB Connected'))
  .catch((err) => console.log('❌ DB Error:', err))

const tmpUploadDir = path.join('uploads', 'tmp')
fs.mkdirSync(tmpUploadDir, { recursive: true })

const storage = multer.diskStorage({
  destination: tmpUploadDir,
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${Math.random().toString(16).slice(2)}${path.extname(file.originalname || '')}`)
  }
})

/** Video extensions we treat as playlist video (incl. octet-stream uploads) */
const PLAYER_VIDEO_EXT = new Set([
  '.mp4',
  '.m4v',
  '.mov',
  '.webm',
  '.mkv',
  '.avi',
  '.wmv',
  '.flv',
  '.3gp',
  '.3g2',
  '.ogv',
  '.mpeg',
  '.mpg',
  '.ts',
  '.m2ts',
  '.f4v',
  '.asf'
])

/** Image extensions when browser sends octet-stream or empty MIME */
const PLAYER_IMAGE_EXT = new Set([
  '.jpg',
  '.jpeg',
  '.png',
  '.gif',
  '.webp',
  '.bmp',
  '.svg',
  '.ico',
  '.heic',
  '.heif',
  '.avif',
  '.tif',
  '.tiff'
])

function isAllowedPlayerUpload(file) {
  const ext = path.extname(file.originalname || '').toLowerCase()
  const mime = (file.mimetype || '').toLowerCase()

  if (mime.startsWith('image/')) return { ok: true }
  if (mime.startsWith('video/')) return { ok: true }

  if (mime === 'application/octet-stream' || mime === '') {
    if (PLAYER_VIDEO_EXT.has(ext)) return { ok: true }
    if (PLAYER_IMAGE_EXT.has(ext)) return { ok: true }
    if (!ext || ext === '.') {
      return {
        ok: false,
        msg: 'Unknown file: use a normal extension (.mp4, .jpg, etc.) so the server can detect image vs video.'
      }
    }
    return {
      ok: false,
      msg: `Unrecognized extension "${ext}". Rename to a known image or video type, or upload from a browser that sends Content-Type.`
    }
  }

  return { ok: false, msg: `Unsupported type "${mime || 'empty'}". Use an image or video file.` }
}

function resolvePlaylistFileType(file) {
  const mime = (file.mimetype || '').toLowerCase()
  const ext = path.extname(file.originalname || '').toLowerCase()
  if (mime.startsWith('video')) return 'video'
  if (PLAYER_VIDEO_EXT.has(ext)) return 'video'
  if (mime.startsWith('image')) return 'image'
  if (PLAYER_IMAGE_EXT.has(ext)) return 'image'
  return 'image'
}

/** Upload temp disk file to Cloudinary; deletes local file always */
async function uploadLocalFileToCloudinary(file) {
  const fileType = resolvePlaylistFileType(file)
  const resourceType = fileType === 'video' ? 'video' : 'image'
  const folder = (process.env.CLOUDINARY_FOLDER || 'nexus-signage').replace(/^\/+|\/+$/g, '')
  const opts = {
    folder,
    resource_type: resourceType,
    use_filename: true,
    unique_filename: true,
    overwrite: false
  }
  let result
  try {
    const stat = await fs.promises.stat(file.path)
    const largeVideo = resourceType === 'video' && stat.size > 90 * 1024 * 1024
    if (largeVideo) {
      result = await new Promise((resolve, reject) => {
        cloudinary.uploader.upload_large(
          file.path,
          (err, r) => (err ? reject(err) : resolve(r)),
          { ...opts, chunk_size: 6 * 1024 * 1024 }
        )
      })
    } else {
      result = await cloudinary.uploader.upload(file.path, opts)
    }
  } finally {
    await fs.promises.unlink(file.path).catch(() => { })
  }
  if (!result?.secure_url) throw new Error('Cloudinary did not return secure_url')
  return result.secure_url
}

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const r = isAllowedPlayerUpload(file)
    if (r.ok) return cb(null, true)
    cb(new Error(r.msg))
  }
})

if (requirePlayerJwt()) {
  io.use((socket, next) => {
    const t = socket.handshake.auth?.playerToken || socket.handshake.query?.playerToken
    if (!t) return next(new Error('player_jwt_required'))
    try {
      const p = verifyPlayerJwtPayload(t)
      socket.playerJwtDeviceId = p.deviceId
      return next()
    } catch {
      return next(new Error('invalid_player_jwt'))
    }
  })
}

io.on('connection', (socket) => {
  socket.on('device-online', async ({ deviceId }) => {
    if (!deviceId) return
    if (requirePlayerJwt() && socket.playerJwtDeviceId && socket.playerJwtDeviceId !== deviceId) {
      console.warn('⚠️ device-online deviceId mismatch vs JWT')
      return
    }

    const nextRoom = deviceRoom(deviceId)
    if (socket.deviceRoom !== nextRoom) {
      if (socket.deviceRoom) socket.leave(socket.deviceRoom)
      socket.join(nextRoom)
      socket.deviceRoom = nextRoom
    }
    socket.deviceId = deviceId

    const clientIp = (socket.handshake.address || '').replace('::ffff:', '')

    try {
      const updated = await Device.findOneAndUpdate(
        { deviceId },
        {
          status: 'online',
          lastSeen: new Date(),
          ipAddress: clientIp || '0.0.0.0'
        },
        { new: true }
      )
      if (!updated) {
        console.warn('⚠️ Heartbeat ignored (device not registered):', deviceId)
      }
      broadcastActiveDevices()
    } catch (err) {
      console.error('❌ Heartbeat Sync Error:', err)
    }
  })

  socket.on('track-play', async ({ deviceId }) => {
    if (requirePlayerJwt() && socket.playerJwtDeviceId && socket.playerJwtDeviceId !== deviceId) return
    try {
      await Device.findOneAndUpdate({ deviceId }, { $inc: { playCount: 1 } })
      console.log(`📊 Analytics: Device ${deviceId} played a media item.`)
    } catch (err) {
      console.error('❌ Play Count Error:', err)
    }
  })

  socket.on('track-media-play', async ({ deviceId, playlistId, itemId, fileUrl, fileType, rotation, duration }) => {
    if (requirePlayerJwt() && socket.playerJwtDeviceId && socket.playerJwtDeviceId !== deviceId) return
    if (!deviceId || !playlistId || !itemId || !fileUrl || !fileType) return
    if (!mongoose.Types.ObjectId.isValid(String(playlistId))) return
    try {
      const key = `perDevicePlays.${deviceId}`
      await MediaAnalytics.findOneAndUpdate(
        { playlistId, itemId },
        {
          // Don't set the same path in $setOnInsert and $set (Mongo throws ConflictingUpdateOperators)
          $setOnInsert: { playlistId, itemId },
          $set: {
            fileUrl,
            fileType,
            rotation: Number(rotation) || 0,
            duration: Number(duration) || 10,
            lastPlayedAt: new Date()
          },
          $inc: { totalPlays: 1, [key]: 1 }
        },
        { upsert: true, new: true }
      )
    } catch (err) {
      console.error('❌ Media analytics update failed:', err)
    }
  })

  socket.on('disconnect', async () => {
    if (!socket.deviceId) return
    const dId = socket.deviceId
    const roomKey = deviceRoom(dId)
    const room = io.sockets.adapter.rooms.get(roomKey)
    if (room && room.size > 0) return

    console.log(`❌ Device ${dId} went OFFLINE`)
    try {
      await Device.findOneAndUpdate({ deviceId: dId }, { status: 'offline' })
      broadcastActiveDevices()
    } catch (err) {
      console.error('❌ Offline Status Update Error:', err)
    }
  })

  socket.on('admin-update-playlist', (data) => {
    const { deviceId, playlist } = data
    io.to(deviceRoom(deviceId)).emit(`update-${deviceId}`, { playlist })
    console.log(`🚀 Update pushed to Device: ${deviceId}`)
  })
})

const seedAdmin = async () => {
  const adminExists = await Admin.findOne({ username: 'superadmin' })
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash('admin123', 10)
    await Admin.create({ username: 'superadmin', password: hashedPassword })
    console.log('🔐 SuperAdmin Created')
  }
}
seedAdmin()

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body
  const admin = await Admin.findOne({ username })
  if (admin && (await bcrypt.compare(password, admin.password))) {
    const token = jwt.sign({ id: admin._id }, JWT_SECRET, { expiresIn: '24h' })
    res.json({ success: true, token })
  } else {
    res.status(401).json({ success: false, message: 'Invalid Credentials' })
  }
})

app.post('/api/playlists', verifyToken, upload.array('files'), async (req, res) => {
  if (!cloudinaryReady) {
    return res.status(503).json({
      error: 'Cloudinary is not configured. Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET on the server.'
    })
  }
  try {
    const { name, durations, rotations } = req.body
    const parsedDurations = JSON.parse(durations || '[]')
    const parsedRotations = JSON.parse(rotations || '[]')

    const files = req.files || []
    const items = []
    for (let index = 0; index < files.length; index++) {
      const file = files[index]
      const secureUrl = await uploadLocalFileToCloudinary(file)
      items.push({
        fileUrl: secureUrl,
        fileType: resolvePlaylistFileType(file),
        duration: parsedDurations[index] || 10,
        rotation: Number(parsedRotations[index]) || 0,
        order: index
      })
    }

    const newPlaylist = new Playlist({ name, items })
    await newPlaylist.save()
    res.status(201).json(newPlaylist)
  } catch (err) {
    for (const f of req.files || []) {
      await fs.promises.unlink(f.path).catch(() => { })
    }
    res.status(500).json({ error: err.message || 'Upload failed' })
  }
})

app.get('/api/playlists', verifyToken, async (req, res) => {
  try {
    const playlists = await Playlist.find()
    res.json(playlists)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/playlists/from-library', verifyToken, async (req, res) => {
  try {
    const { name, items } = req.body || {}
    if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name is required' })
    if (!Array.isArray(items) || items.length === 0) return res.status(400).json({ error: 'items must be a non-empty array' })
    const normalized = items
      .filter((x) => x && typeof x.fileUrl === 'string' && x.fileUrl.trim())
      .map((x, i) => ({
        fileUrl: String(x.fileUrl).trim(),
        fileType: x.fileType === 'image' ? 'image' : 'video',
        duration: Number(x.duration) > 0 ? Math.min(3600, Math.floor(Number(x.duration))) : 10,
        rotation: [0, 90, 180, 270].includes(Number(x.rotation)) ? Number(x.rotation) : 0,
        order: i
      }))
    if (normalized.length === 0) return res.status(400).json({ error: 'No valid items' })
    const newPlaylist = new Playlist({ name, items: normalized })
    await newPlaylist.save()
    res.status(201).json(newPlaylist)
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to create playlist' })
  }
})

app.patch('/api/playlists/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid id' })
    const { name, items } = req.body || {}

    const update = {}
    if (typeof name === 'string' && name.trim()) update.name = name.trim()

    if (Array.isArray(items)) {
      update.items = items.map((x, i) => ({
        _id: x._id, // allow preserving subdoc IDs when present
        fileUrl: String(x.fileUrl || '').trim(),
        fileType: x.fileType === 'image' ? 'image' : 'video',
        duration: Number(x.duration) > 0 ? Math.min(3600, Math.floor(Number(x.duration))) : 10,
        rotation: [0, 90, 180, 270].includes(Number(x.rotation)) ? Number(x.rotation) : 0,
        order: i
      }))
    }

    const updated = await Playlist.findByIdAndUpdate(id, update, { new: true })
    if (!updated) return res.status(404).json({ error: 'Playlist not found' })

    if (Array.isArray(items)) {
      const keepIds = (updated.items || [])
        .map((it) => String(it._id))
        .filter((x) => mongoose.Types.ObjectId.isValid(x))
        .map((x) => new mongoose.Types.ObjectId(x))
      await MediaAnalytics.deleteMany({ playlistId: id, itemId: { $nin: keepIds } }).catch(() => {})
    }

    res.json(updated)
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to update playlist' })
  }
})

app.get('/api/devices', verifyToken, async (req, res) => {
  try {
    const devices = await Device.find().populate('assignedPlaylist')
    res.json(devices)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/devices/register', verifyToken, async (req, res) => {
  const { deviceId, deviceName } = req.body
  try {
    let device = await Device.findOne({ deviceId })
    if (!device) {
      device = new Device({
        deviceId,
        deviceName,
        status: 'offline',
        lastSeen: new Date(),
        playCount: 0
      })
    } else {
      device.deviceName = deviceName
    }
    await device.save()
    res.json(device)
  } catch (err) {
    res.status(400).json({ error: 'Failed' })
  }
})

app.patch('/api/devices/assign', verifyToken, async (req, res) => {
  const { deviceId, playlistId } = req.body
  let assignedPlaylist = null
  if (playlistId && mongoose.Types.ObjectId.isValid(playlistId)) {
    assignedPlaylist = playlistId
  }
  try {
    const device = await Device.findOneAndUpdate(
      { deviceId },
      { assignedPlaylist },
      { new: true }
    ).populate('assignedPlaylist')

    if (!device) return res.status(404).json({ error: 'Device not found' })

    io.to(deviceRoom(deviceId)).emit(`update-${deviceId}`, { playlist: device.assignedPlaylist })
    res.json(device)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/playlists/:id', verifyToken, async (req, res) => {
  try {
    const playlistId = req.params.id
    await Device.updateMany({ assignedPlaylist: playlistId }, { $set: { assignedPlaylist: null } })
    await Playlist.findByIdAndDelete(playlistId)
    res.json({ message: 'Deleted' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/devices/:deviceId/player-token', verifyToken, async (req, res) => {
  try {
    const { deviceId } = req.params
    const device = await Device.findOne({ deviceId })
    if (!device) return res.status(404).json({ message: 'Device not found' })
    const token = signPlayerJwt(deviceId)
    const exp = process.env.PLAYER_JWT_EXPIRES || '365d'
    res.json({ token, expiresIn: exp })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.delete('/api/devices/:deviceId', verifyToken, async (req, res) => {
  try {
    const { deviceId } = req.params
    const deletedDevice = await Device.findOneAndDelete({ deviceId })

    if (!deletedDevice) {
      return res.status(404).json({ success: false, message: 'Device not found' })
    }

    broadcastActiveDevices()
    console.log(`🗑️ Device ${deviceId} removed from system.`)
    res.json({ success: true, message: 'Hardware node deleted successfully' })
  } catch (err) {
    console.error('❌ Delete API Error:', err)
    res.status(500).json({ success: false, error: 'Internal Server Error' })
  }
})

app.get('/api/player/:deviceId', verifyPlayerRequest, async (req, res) => {
  const device = await Device.findOne({ deviceId: req.params.deviceId }).populate('assignedPlaylist')
  if (!device || !device.assignedPlaylist) {
    return res.status(404).json({ message: 'Empty' })
  }
  // Include playlistId so player can report media-wise analytics
  const playlistId = device.assignedPlaylist._id
  const items = (device.assignedPlaylist.items || []).map((it) => ({
    ...it.toObject(),
    playlistId
  }))
  res.json(items)
})

app.get('/api/reports/media', verifyToken, async (req, res) => {
  try {
    const { playlistId } = req.query || {}
    const filter = {}
    if (playlistId && mongoose.Types.ObjectId.isValid(String(playlistId))) {
      filter.playlistId = playlistId
    }
    const rows = await MediaAnalytics.find(filter).sort({ totalPlays: -1, lastPlayedAt: -1 }).limit(5000).lean()
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to build media report' })
  }
})

app.use((err, req, res, next) => {
  if (err && err.message && err.message.includes('Unsupported upload')) {
    return res.status(400).json({ error: err.message })
  }
  if (err) {
    console.error(err)
    return res.status(500).json({ error: err.message || 'Server error' })
  }
  next()
})

server.listen(PORT, () => {
  console.log(`🚀 Backend Live on Port ${PORT}`)
  if (requirePlayerJwt()) {
    console.log('🔒 Player JWT enforced (REQUIRE_PLAYER_JWT). Issue tokens from admin: POST /api/devices/:deviceId/player-token')
  } else if (process.env.NODE_ENV === 'production') {
    console.warn('⚠️  Player GET /api/player/:deviceId is open without JWT. Set REQUIRE_PLAYER_JWT=true for production.')
  } else {
    console.log('ℹ️  Player API: no JWT required (dev). Set REQUIRE_PLAYER_JWT=true to lock down.')
  }
})
