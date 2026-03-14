'use strict'

const crypto = require('crypto')
const express = require('express')
const cors = require('cors')
const helmet = require('helmet')
const morgan = require('morgan')
const jwt = require('jsonwebtoken')
const dotenv = require('dotenv')
const mongoose = require('mongoose')
const { z } = require('zod')
const { Resend } = require('resend')

dotenv.config()
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const app = express()

const PORT = process.env.PORT || 4000
const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY
const AUTH_TOKEN_SECRET = process.env.AUTH_TOKEN_SECRET || ADMIN_SECRET_KEY
const TOKEN_EXPIRY = process.env.TOKEN_EXPIRY || '30m'
const MONGODB_URI = process.env.MONGODB_URI
const RESEND_API_KEY = process.env.RESEND_API_KEY
const FROM_EMAIL = process.env.FROM_EMAIL || 'Auta <noreply@auta.ai>'

// CVAT integration — used to programmatically create user accounts on approval
const CVAT_API_URL = (process.env.CVAT_API_URL || '').replace(/\/$/, '')
const CVAT_INTERNAL_API_KEY = process.env.CVAT_INTERNAL_API_KEY || ''
// Public URL shown to new users in the welcome email (may differ from internal API URL)
const CVAT_PUBLIC_URL = (process.env.CVAT_PUBLIC_URL || CVAT_API_URL).replace(/\/$/, '')

const resend = RESEND_API_KEY ? new Resend(RESEND_API_KEY) : null

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

blogPostSchema.index({ publishedAt: -1, createdAt: -1 })

const BlogPost = mongoose.models.BlogPost || mongoose.model('BlogPost', blogPostSchema)

const waitlistSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true },
    useCase: {
      type: String,
      enum: ['Medical', 'Sports', 'Autonomous', 'Other'],
      default: 'Other',
    },
    message: { type: String, default: '', trim: true },
    status: {
      type: String,
      enum: ['pending', 'approved', 'rejected'],
      default: 'pending',
    },
    adminNotes: { type: String, default: '', trim: true },
  },
  { timestamps: true }
)

waitlistSchema.index({ email: 1 })
waitlistSchema.index({ status: 1, createdAt: -1 })

const WaitlistEntry = mongoose.models.WaitlistEntry || mongoose.model('WaitlistEntry', waitlistSchema)

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
waitlistRoutes(app)
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

  server.put('/blogs/:slug', verifyToken, async (req, res) => {
    try {
      const existingDoc = await BlogPost.findOne({ slug: req.params.slug }).exec()
      if (!existingDoc) {
        return res.status(404).json({ error: 'Blog post not found.' })
      }

      const normalizedSlug = sanitizeSlug(String(req.body?.slug ?? req.body?.title ?? req.params.slug))
      const payload = { ...req.body, slug: normalizedSlug }
      const parsed = blogPayloadSchema.safeParse(payload)

      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid blog payload.', issues: parsed.error.flatten() })
      }

      const data = parsed.data

      let publishedAt = existingDoc.publishedAt
      if (data.date) {
        const candidate = new Date(data.date)
        if (!Number.isNaN(candidate.getTime())) {
          candidate.setUTCHours(0, 0, 0, 0)
          publishedAt = candidate
        }
      }

      existingDoc.slug = data.slug
      existingDoc.title = data.title.trim()
      existingDoc.author = (data.author ?? '').trim() || 'Perceptron Team'
      existingDoc.excerpt = data.excerpt?.trim() || ''
      existingDoc.image = data.image?.trim() || ''
      existingDoc.content = data.content.trim()
      existingDoc.publishedAt = publishedAt

      await existingDoc.save()

      res.json({ slug: existingDoc.slug })
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 11000) {
        return res.status(409).json({ error: 'A blog post with this slug already exists.' })
      }

      console.error('Failed to update blog post', error)
      res.status(500).json({ error: 'Failed to update the blog post.' })
    }
  })

  server.delete('/blogs/:slug', verifyToken, async (req, res) => {
    try {
      const result = await BlogPost.findOneAndDelete({ slug: req.params.slug }).exec()
      if (!result) {
        return res.status(404).json({ error: 'Blog post not found.' })
      }

      res.json({ deleted: true, slug: req.params.slug })
    } catch (error) {
      console.error('Failed to delete blog post', error)
      res.status(500).json({ error: 'Failed to delete the blog post.' })
    }
  })
}

function waitlistRoutes(server) {
  const waitlistPayloadSchema = z.object({
    name: z.string().min(1).max(120),
    email: z.string().email(),
    useCase: z.enum(['Medical', 'Sports', 'Autonomous', 'Other']).optional().default('Other'),
    message: z.string().max(1000).optional().default(''),
  })

  // Public — submit waitlist signup
  server.post('/waitlist', async (req, res) => {
    const parsed = waitlistPayloadSchema.safeParse(req.body || {})
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid payload.', issues: parsed.error.flatten() })
    }

    try {
      const existing = await WaitlistEntry.findOne({ email: parsed.data.email }).lean().exec()
      if (existing) {
        return res.status(409).json({ error: 'This email is already on the waitlist.' })
      }

      const entry = new WaitlistEntry({
        name: parsed.data.name,
        email: parsed.data.email,
        useCase: parsed.data.useCase,
        message: parsed.data.message,
      })
      await entry.save()
      res.status(201).json({ success: true })
    } catch (error) {
      console.error('Failed to save waitlist entry', error)
      res.status(500).json({ error: 'Failed to save your request. Please try again.' })
    }
  })

  // Protected — list all waitlist entries
  server.get('/waitlist', verifyToken, async (req, res) => {
    try {
      const { status } = req.query || {}
      const filter = status && ['pending', 'approved', 'rejected'].includes(status) ? { status } : {}
      const entries = await WaitlistEntry.find(filter).sort({ createdAt: -1 }).lean().exec()
      res.json({ entries })
    } catch (error) {
      console.error('Failed to list waitlist entries', error)
      res.status(500).json({ error: 'Failed to fetch waitlist entries.' })
    }
  })

  // Protected — update status / adminNotes for an entry
  server.patch('/waitlist/:id', verifyToken, async (req, res) => {
    try {
      const { id } = req.params
      const { status, adminNotes } = req.body || {}

      const entry = await WaitlistEntry.findById(id).exec()
      if (!entry) {
        return res.status(404).json({ error: 'Entry not found.' })
      }

      const previousStatus = entry.status

      if (status && ['pending', 'approved', 'rejected'].includes(status)) {
        entry.status = status
      }
      if (adminNotes !== undefined) {
        entry.adminNotes = adminNotes
      }

      await entry.save()

      // ── Auto-create CVAT account and email credentials ──────────────────
      if (status === 'approved' && previousStatus !== 'approved') {
        if (!CVAT_API_URL || !CVAT_INTERNAL_API_KEY) {
          console.warn('CVAT_API_URL or CVAT_INTERNAL_API_KEY not configured — skipping account creation.')
        } else {
          try {
            // 1. Generate a secure random password
            const password = crypto.randomBytes(12).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 16)

            // 2. Derive a base username from the email prefix, keep only alphanumeric + underscores
            const baseUsername = entry.email
              .split('@')[0]
              .toLowerCase()
              .replace(/[^a-z0-9_]/g, '_')
              .slice(0, 30)

            // 3. Try to create the account, retrying with a numeric suffix on 409 (username taken)
            let username = null
            const MAX_ATTEMPTS = 10
            for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
              const candidate = attempt === 0 ? baseUsername : `${baseUsername}_${attempt}`
              const resp = await fetch(`${CVAT_API_URL}/api/internal/create-user`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'X-Internal-Api-Key': CVAT_INTERNAL_API_KEY,
                },
                body: JSON.stringify({
                  username: candidate,
                  email: entry.email,
                  password,
                  first_name: (entry.name || '').split(' ')[0] || '',
                  last_name: (entry.name || '').split(' ').slice(1).join(' ') || '',
                }),
              })

              if (resp.status === 201) {
                username = candidate
                console.log(`Created CVAT account '${username}' for ${entry.email}`)
                break
              } else if (resp.status === 409) {
                // Username taken — try the next suffix
                continue
              } else {
                const body = await resp.text()
                throw new Error(`CVAT API returned ${resp.status}: ${body}`)
              }
            }

            if (!username) {
              throw new Error(`Could not find a unique username after ${MAX_ATTEMPTS} attempts for ${entry.email}`)
            }

            // 4. Send the welcome email with credentials
            if (resend) {
              await resend.emails.send({
                from: FROM_EMAIL,
                to: entry.email,
                subject: "Your Perceptron account is ready!",
                html: `
                  <div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:40px 24px;background:#0a0f1e;color:#f0f4ff">
                    <h1 style="font-size:26px;font-weight:700;margin-bottom:8px">Welcome to Perceptron!</h1>
                    <p style="color:#94a3b8;font-size:16px;margin-bottom:24px">Hey ${entry.name},</p>
                    <p style="color:#cbd5e1;font-size:15px;line-height:1.6">Your access to the <strong style="color:#53C5E6">Perceptron Private Beta</strong> has been approved. Your account is ready to use.</p>

                    <div style="background:#111827;border:1px solid #1e293b;border-radius:12px;padding:24px;margin:28px 0">
                      <p style="color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:0.08em;margin:0 0 16px">Your login credentials</p>
                      <table style="width:100%;border-collapse:collapse">
                        <tr>
                          <td style="color:#94a3b8;font-size:14px;padding:6px 0;width:110px">Login URL</td>
                          <td style="color:#f1f5f9;font-size:14px;padding:6px 0"><a href="${CVAT_PUBLIC_URL}/auth/login" style="color:#53C5E6;text-decoration:none">${CVAT_PUBLIC_URL}/auth/login</a></td>
                        </tr>
                        <tr>
                          <td style="color:#94a3b8;font-size:14px;padding:6px 0">Username</td>
                          <td style="color:#f1f5f9;font-size:14px;padding:6px 0;font-family:monospace">${username}</td>
                        </tr>
                        <tr>
                          <td style="color:#94a3b8;font-size:14px;padding:6px 0">Password</td>
                          <td style="color:#f1f5f9;font-size:14px;padding:6px 0;font-family:monospace">${password}</td>
                        </tr>
                      </table>
                    </div>

                    <p style="color:#94a3b8;font-size:14px;line-height:1.6">For security, please change your password after your first login via <strong>Profile → Change password</strong>.</p>

                    <div style="margin:32px 0">
                      <a href="${CVAT_PUBLIC_URL}/auth/login" style="background:linear-gradient(135deg,#2178C7,#53C5E6);color:#fff;padding:14px 28px;border-radius:10px;text-decoration:none;font-weight:600;font-size:15px">Log in to Perceptron</a>
                    </div>

                    <p style="color:#475569;font-size:13px">If you have any questions, reply to this email or contact us at support@perceptronai.org.</p>
                    <p style="color:#334155;font-size:12px;margin-top:32px">Perceptron Inc. — Building the future of AI annotation.</p>
                  </div>
                `,
              })
              console.log(`Sent credentials email to ${entry.email}`)
            } else {
              console.warn('RESEND_API_KEY not configured — credentials email not sent.')
            }
          } catch (accountError) {
            console.error('Failed to create CVAT account or send credentials email:', accountError)
            // Non-fatal — the waitlist entry is already saved as approved.
            // Admin should be notified to create the account manually.
          }
        }
      }

      res.json({ success: true, entry: { _id: entry._id, status: entry.status, adminNotes: entry.adminNotes } })
    } catch (error) {
      console.error('Failed to update waitlist entry', error)
      res.status(500).json({ error: 'Failed to update the entry.' })
    }
  })

  // Protected — delete a waitlist entry
  server.delete('/waitlist/:id', verifyToken, async (req, res) => {
    const { id } = req.params
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: 'Invalid id.' })
    }
    try {
      const result = await WaitlistEntry.findByIdAndDelete(id).exec()
      if (!result) {
        return res.status(404).json({ error: 'Entry not found.' })
      }
      res.json({ deleted: true })
    } catch (error) {
      console.error('Failed to delete waitlist entry', error)
      res.status(500).json({ error: 'Failed to delete the entry.' })
    }
  })
}

function defaultHandler(server) {
  server.use((_req, res) => {
    res.status(404).json({ error: 'Not found' })
  })
}
