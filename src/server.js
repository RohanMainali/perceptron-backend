'use strict'

const express = require('express')
const cors = require('cors')
const helmet = require('helmet')
const morgan = require('morgan')
const jwt = require('jsonwebtoken')
const dotenv = require('dotenv')

dotenv.config()

const app = express()

const PORT = process.env.PORT || 4000
const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY
const AUTH_TOKEN_SECRET = process.env.AUTH_TOKEN_SECRET || ADMIN_SECRET_KEY
const TOKEN_EXPIRY = process.env.TOKEN_EXPIRY || '30m'

if (!ADMIN_SECRET_KEY) {
  console.error('Missing ADMIN_SECRET_KEY environment variable.')
  process.exit(1)
}

if (!AUTH_TOKEN_SECRET) {
  console.error('Missing AUTH_TOKEN_SECRET environment variable.')
  process.exit(1)
}

const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean)

app.use(
  cors({
    origin: allowedOrigins.length > 0 ? allowedOrigins : true,
    credentials: false,
  })
)
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }))
app.use(express.json({ limit: '1mb' }))
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'))

const buildTokenPayload = () => ({
  scope: ['blog:create'],
  issuedAt: Date.now(),
})

authRoutes(app)

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() })
})

defaultHandler(app)

app.listen(PORT, () => {
  console.log(`Auth service listening on port ${PORT}`)
})

function authRoutes(server) {
  server.post('/auth/login', (req, res) => {
    const { secretKey } = req.body || {}

    if (!secretKey) {
      return res.status(400).json({ error: 'Secret key is required.' })
    }

    if (secretKey !== ADMIN_SECRET_KEY) {
      return res.status(401).json({ error: 'Invalid credentials.' })
    }

    const token = jwt.sign(buildTokenPayload(), AUTH_TOKEN_SECRET, { expiresIn: TOKEN_EXPIRY })

    res.json({ token, expiresIn: TOKEN_EXPIRY })
  })

  server.post('/auth/verify', (req, res) => {
    const { token } = req.body || {}

    if (!token) {
      return res.status(400).json({ error: 'Token is required.' })
    }

    try {
      const decoded = jwt.verify(token, AUTH_TOKEN_SECRET)
      res.json({ valid: true, decoded })
    } catch (error) {
      res.status(401).json({ valid: false, error: 'Invalid or expired token.' })
    }
  })
}

function defaultHandler(server) {
  server.use((_req, res) => {
    res.status(404).json({ error: 'Not found' })
  })
}
