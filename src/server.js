'use strict'

const express = require('express')
const cors = require('cors')
const helmet = require('helmet')
const morgan = require('morgan')
const jwt = require('jsonwebtoken')
const dotenv = require('dotenv')
const mongoose = require('mongoose')
const { z } = require('zod')

dotenv.config()

const app = express()

const PORT = process.env.PORT || 4000
const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY
const AUTH_TOKEN_SECRET = process.env.AUTH_TOKEN_SECRET || ADMIN_SECRET_KEY
const TOKEN_EXPIRY = process.env.TOKEN_EXPIRY || '30m'
const MONGODB_URI = process.env.MONGODB_URI

if (!ADMIN_SECRET_KEY) {
  console.error('Missing ADMIN_SECRET_KEY environment variable.')
  process.exit(1)
}

if (!AUTH_TOKEN_SECRET) {
  console.error('Missing AUTH_TOKEN_SECRET environment variable.')
  process.exit(1)
}

if (!MONGODB_URI) {
  console.error('Missing MONGODB_URI environment variable.')
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

const blogPayloadSchema = z.object({
  title: z.string().min(3).max(160),
  slug: z
    .string()
    .min(3)
    .max(160)
    .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/, 'Slug can only contain lowercase letters, numbers, and single hyphens.'),
  author: z.string().max(120).optional().default(''),
  date: z.string().max(40).optional(),
  excerpt: z.string().max(320).optional(),
  image: z
    .string()
    .url({ message: 'Image must be a valid URL.' })
    .optional()
    .or(z.literal('')),
  content: z.string().min(20, 'Content is too short.'),
})

const blogPostSchema = new mongoose.Schema(
  {
    slug: { type: String, required: true, unique: true, trim: true },
    title: { type: String, required: true, trim: true },
    author: { type: String, default: 'Perceptron Team', trim: true },
    excerpt: { type: String, default: '', trim: true },
    image: { type: String, default: '', trim: true },
    content: { type: String, required: true },
    publishedAt: { type: Date },
  },
  { timestamps: true }
)

blogPostSchema.index({ slug: 1 }, { unique: true })
blogPostSchema.index({ publishedAt: -1, createdAt: -1 })

const BlogPost = mongoose.models.BlogPost || mongoose.model('BlogPost', blogPostSchema)

const buildTokenPayload = () => ({
  scope: ['blog:create'],
  issuedAt: Date.now(),
})

function sanitizeSlug(value = '') {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
}

function summarize(content = '', fallback = '') {
  if (!content) return fallback
  const plain = content
    .replace(/[#>*_`\-]|\[(.*?)\]\((.*?)\)/g, '')
    .replace(/\s+/g, ' ')
    .trim()
  const snippet = plain.slice(0, 180)
  return snippet + (plain.length > 180 ? '...' : '')
}

function formatDisplayDate(value) {
  if (!value) return ''
  const candidate = new Date(value)
  if (Number.isNaN(candidate.getTime())) {
    return ''
  }
  return candidate.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
}

function toBlogResponse(document) {
  if (!document) return null
  const publishedAt = document.publishedAt || document.createdAt
  return {
    slug: document.slug,
    title: document.title,
    author: document.author || 'Perceptron Team',
    excerpt: document.excerpt || summarize(document.content),
    image: document.image || undefined,
    content: document.content,
    date: formatDisplayDate(publishedAt),
  }
}

function verifyToken(request, response, next) {
  const authorization = request.headers.authorization
  if (!authorization || !authorization.startsWith('Bearer ')) {
    return response.status(401).json({ error: 'Missing authorization header.' })
  }

  const token = authorization.slice('Bearer '.length).trim()
  try {
    jwt.verify(token, AUTH_TOKEN_SECRET)
    next()
  } catch (error) {
    console.error('Invalid token', error)
    response.status(401).json({ error: 'Invalid or expired token.' })
  }
}

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() })
})

authRoutes(app)
blogRoutes(app)
defaultHandler(app)

async function connectToDatabase() {
  try {
    mongoose.set('strictQuery', true)
    await mongoose.connect(MONGODB_URI)
    console.log('Connected to MongoDB')
  } catch (error) {
    console.error('Unable to connect to MongoDB', error)
    process.exit(1)
  }
}

async function start() {
  await connectToDatabase()
  app.listen(PORT, () => {
    console.log(`Service listening on port ${PORT}`)
  })
}

start().catch((error) => {
  console.error('Failed to start service', error)
  process.exit(1)
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

function blogRoutes(server) {
  server.get('/blogs', async (req, res) => {
    try {
      const { limit } = req.query || {}
      const parsedLimit = Number.parseInt(limit, 10)
      const safeLimit = Number.isFinite(parsedLimit) && parsedLimit > 0 ? Math.min(parsedLimit, 100) : undefined

      const posts = await BlogPost.find({})
        .sort({ publishedAt: -1, createdAt: -1 })
        .limit(safeLimit ?? 0)
        .lean()
        .exec()

      res.json({ posts: posts.map((document) => toBlogResponse(document)) })
    } catch (error) {
      console.error('Failed to list blog posts', error)
      res.status(500).json({ error: 'Failed to fetch blog posts.' })
    }
  })

  server.get('/blogs/:slug', async (req, res) => {
    try {
      const document = await BlogPost.findOne({ slug: req.params.slug }).lean().exec()
      if (!document) {
        return res.status(404).json({ error: 'Blog post not found.' })
      }

      res.json({ post: toBlogResponse(document) })
    } catch (error) {
      console.error('Failed to fetch blog post', error)
      res.status(500).json({ error: 'Failed to fetch the requested blog post.' })
    }
  })

  server.post('/blogs', verifyToken, async (req, res) => {
    try {
      const normalizedSlug = sanitizeSlug(String(req.body?.slug ?? req.body?.title ?? ''))
      const payload = { ...req.body, slug: normalizedSlug }
      const parsed = blogPayloadSchema.safeParse(payload)

      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid blog payload.', issues: parsed.error.flatten() })
      }

      const data = parsed.data

      let publishedAt = undefined
      if (data.date) {
        const candidate = new Date(data.date)
        if (!Number.isNaN(candidate.getTime())) {
          candidate.setUTCHours(0, 0, 0, 0)
          publishedAt = candidate
        }
      }

      const document = new BlogPost({
        slug: data.slug,
        title: data.title.trim(),
        author: (data.author ?? '').trim() || 'Perceptron Team',
        excerpt: data.excerpt?.trim() || '',
        image: data.image?.trim() || '',
        content: data.content.trim(),
        publishedAt,
      })

      await document.save()

      res.status(201).json({ slug: document.slug })
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 11000) {
        return res.status(409).json({ error: 'A blog post with this slug already exists.' })
      }

      console.error('Failed to persist blog post', error)
      res.status(500).json({ error: 'Failed to store the blog post.' })
    }
  })
}

function defaultHandler(server) {
  server.use((_req, res) => {
    res.status(404).json({ error: 'Not found' })
  })
}
