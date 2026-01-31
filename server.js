const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { neon } = require('@neondatabase/serverless');
const { Resend } = require('resend');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// Configure multer for logo uploads
const logoStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, 'public', 'logos');
        // Create directory if it doesn't exist
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        // Generate unique filename with original extension
        const ext = path.extname(file.originalname).toLowerCase();
        const uniqueName = `${Date.now()}-${uuidv4().slice(0, 8)}${ext}`;
        cb(null, uniqueName);
    }
});

const logoUpload = multer({
    storage: logoStorage,
    limits: {
        fileSize: 2 * 1024 * 1024 // 2MB limit
    },
    fileFilter: function (req, file, cb) {
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/svg+xml', 'image/webp'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG, SVG, and WebP are allowed.'));
        }
    }
});

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Neon
const sql = process.env.DATABASE_URL ? neon(process.env.DATABASE_URL) : null;

// Initialize Resend
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

// Super admin config
const SUPER_ADMIN_EMAIL = 'ml@feedbacknfc.com';

// Generate 6-digit auth code
function generateAuthCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// ==================== API ROUTES ====================

// Request auth code (super admin login)
app.post('/api/auth/request-code', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (email !== SUPER_ADMIN_EMAIL) {
            return res.status(401).json({ error: 'Unauthorized email' });
        }
        
        const code = generateAuthCode();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
        
        // Store auth code in database
        if (sql) {
            await sql`
                INSERT INTO auth_codes (email, code, expires_at)
                VALUES (${email}, ${code}, ${expiresAt})
                ON CONFLICT (email) 
                DO UPDATE SET code = ${code}, expires_at = ${expiresAt}
            `;
        }
        
        // Log code for development
        console.log(`\n========================================`);
        console.log(`Auth Code for ${email}: ${code}`);
        console.log(`========================================\n`);
        
        // Send email via Resend
        try {
            if (resend) {
                await resend.emails.send({
                    from: process.env.EMAIL_FROM || 'onboarding@resend.dev',
                    to: email,
                    subject: 'Your Login Code - FeedbackNFC Admin',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 400px; margin: 0 auto; padding: 20px;">
                            <h2 style="color: #22C55E;">FeedbackNFC Admin</h2>
                            <p>Your login verification code is:</p>
                            <div style="background: #F5F3EF; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 8px; border-radius: 8px;">
                                ${code}
                            </div>
                            <p style="color: #666; margin-top: 20px;">This code expires in 10 minutes.</p>
                        </div>
                    `
                });
                console.log('Email sent successfully via Resend');
            }
        } catch (err) {
            console.log('Email sending failed:', err.message);
        }
        
        // Include code in response for debugging (remove in production)
        const debugMode = process.env.DEBUG_MODE === 'true';
        res.json({ 
            success: true, 
            message: 'Verification code sent to email',
            ...(debugMode && { code }) // Only include code if DEBUG_MODE is true
        });
    } catch (error) {
        console.error('Request code error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Verify auth code (super admin login)
app.post('/api/auth/verify-code', async (req, res) => {
    try {
        const { email, code } = req.body;
        
        if (!sql) {
            return res.status(500).json({ error: 'Database not configured' });
        }
        
        // Get auth code from database
        const result = await sql`
            SELECT code, expires_at FROM auth_codes WHERE email = ${email}
        `;
        
        if (result.length === 0) {
            return res.status(401).json({ error: 'No pending verification' });
        }
        
        const authData = result[0];
        
        if (new Date() > new Date(authData.expires_at)) {
            await sql`DELETE FROM auth_codes WHERE email = ${email}`;
            return res.status(401).json({ error: 'Code expired' });
        }
        
        if (authData.code !== code) {
            return res.status(401).json({ error: 'Invalid code' });
        }
        
        // Create session
        const sessionId = uuidv4();
        const sessionExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        
        await sql`
            INSERT INTO sessions (id, email, role, expires_at)
            VALUES (${sessionId}, ${email}, 'super_admin', ${sessionExpires})
        `;
        
        // Delete used auth code
        await sql`DELETE FROM auth_codes WHERE email = ${email}`;
        
        res.json({ success: true, sessionId, role: 'super_admin' });
    } catch (error) {
        console.error('Verify code error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Company login
app.post('/api/auth/company-login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!sql) {
            return res.status(500).json({ error: 'Database not configured' });
        }
        
        // Debug: Log login attempt
        console.log(`\nCompany login attempt: ${email}`);
        
        // Case-insensitive email lookup
        const result = await sql`
            SELECT id, name, email FROM companies 
            WHERE LOWER(email) = LOWER(${email}) AND password = ${password}
        `;
        
        if (result.length === 0) {
            // Debug: Check if company exists (without password check)
            const companyCheck = await sql`
                SELECT id, name, email FROM companies WHERE LOWER(email) = LOWER(${email})
            `;
            if (companyCheck.length > 0) {
                console.log(`Company found but password mismatch for: ${email}`);
            } else {
                console.log(`No company found with email: ${email}`);
                // List all companies for debugging
                const allCompanies = await sql`SELECT name, email FROM companies`;
                console.log('Available companies:', allCompanies.map(c => c.email));
            }
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const company = result[0];
        
        // Create session
        const sessionId = uuidv4();
        const sessionExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        
        await sql`
            INSERT INTO sessions (id, email, role, company_id, expires_at)
            VALUES (${sessionId}, ${email}, 'company_admin', ${company.id}, ${sessionExpires})
        `;
        
        res.json({ 
            success: true, 
            sessionId, 
            role: 'company_admin',
            company: {
                id: company.id,
                name: company.name
            }
        });
    } catch (error) {
        console.error('Company login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Logout
app.post('/api/auth/logout', async (req, res) => {
    try {
        const sessionId = req.headers['x-session-id'];
        if (sessionId && sql) {
            await sql`DELETE FROM sessions WHERE id = ${sessionId}`;
        }
        res.json({ success: true });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get current session
app.get('/api/auth/session', async (req, res) => {
    try {
        const sessionId = req.headers['x-session-id'];
        
        if (!sessionId || !sql) {
            return res.status(401).json({ error: 'No session' });
        }
        
        const result = await sql`
            SELECT email, role, company_id FROM sessions 
            WHERE id = ${sessionId} AND expires_at > NOW()
        `;
        
        if (result.length === 0) {
            return res.status(401).json({ error: 'Session expired' });
        }
        
        const session = result[0];
        res.json({ 
            email: session.email, 
            role: session.role, 
            companyId: session.company_id,
            sessionId 
        });
    } catch (error) {
        console.error('Session check error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Auth middleware
async function requireAuth(req, res, next) {
    try {
        const sessionId = req.headers['x-session-id'];
        
        if (!sessionId || !sql) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const result = await sql`
            SELECT email, role, company_id FROM sessions 
            WHERE id = ${sessionId} AND expires_at > NOW()
        `;
        
        if (result.length === 0) {
            return res.status(401).json({ error: 'Session expired' });
        }
        
        req.session = {
            email: result[0].email,
            role: result[0].role,
            companyId: result[0].company_id
        };
        next();
    } catch (error) {
        console.error('Auth middleware error:', error);
        res.status(500).json({ error: 'Server error' });
    }
}

// ==================== UPLOAD ROUTES ====================

// Upload company logo
app.post('/api/upload/logo', logoUpload.single('logo'), async (req, res) => {
    try {
        // Verify session
        const sessionId = req.headers['x-session-id'];
        
        if (!sessionId || !sql) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const result = await sql`
            SELECT email, role FROM sessions 
            WHERE id = ${sessionId} AND expires_at > NOW()
        `;
        
        if (result.length === 0) {
            return res.status(401).json({ error: 'Session expired' });
        }
        
        if (result[0].role !== 'super_admin') {
            return res.status(403).json({ error: 'Forbidden' });
        }
        
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        // Return the public URL for the uploaded logo
        const logoUrl = `/logos/${req.file.filename}`;
        
        console.log(`Logo uploaded: ${req.file.filename}`);
        
        res.json({ 
            success: true, 
            url: logoUrl,
            filename: req.file.filename
        });
        
    } catch (error) {
        console.error('Logo upload error:', error);
        res.status(500).json({ error: error.message || 'Upload failed' });
    }
});

// Upload card exterior (front or back) - for company admins
app.post('/api/upload/card-exterior', logoUpload.single('image'), async (req, res) => {
    try {
        // Verify session
        const sessionId = req.headers['x-session-id'];
        const { side } = req.body; // 'front' or 'back'
        
        if (!sessionId || !sql) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const result = await sql`
            SELECT email, role, company_id FROM sessions 
            WHERE id = ${sessionId} AND expires_at > NOW()
        `;
        
        if (result.length === 0) {
            return res.status(401).json({ error: 'Session expired' });
        }
        
        // Allow both super_admin and company_admin
        if (result[0].role !== 'super_admin' && result[0].role !== 'company_admin') {
            return res.status(403).json({ error: 'Forbidden' });
        }
        
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        if (!side || (side !== 'front' && side !== 'back')) {
            return res.status(400).json({ error: 'Invalid side parameter. Use "front" or "back".' });
        }
        
        // Return the public URL for the uploaded image
        const imageUrl = `/logos/${req.file.filename}`;
        
        console.log(`Card ${side} uploaded: ${req.file.filename}`);
        
        res.json({ 
            success: true, 
            url: imageUrl,
            side: side,
            filename: req.file.filename
        });
        
    } catch (error) {
        console.error('Card exterior upload error:', error);
        res.status(500).json({ error: error.message || 'Upload failed' });
    }
});

// Update company card exteriors and logo
app.put('/api/companies/:id/card-exteriors', async (req, res) => {
    try {
        const sessionId = req.headers['x-session-id'];
        const { id } = req.params;
        const { cardFront, cardBack, logo } = req.body;
        
        if (!sessionId || !sql) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const sessionResult = await sql`
            SELECT email, role, company_id FROM sessions 
            WHERE id = ${sessionId} AND expires_at > NOW()
        `;
        
        if (sessionResult.length === 0) {
            return res.status(401).json({ error: 'Session expired' });
        }
        
        const session = sessionResult[0];
        
        // Company admin can only update their own company
        if (session.role === 'company_admin' && session.company_id !== id) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        
        // Update card exteriors and logo
        const result = await sql`
            UPDATE companies 
            SET card_front = COALESCE(${cardFront}, card_front),
                card_back = COALESCE(${cardBack}, card_back),
                logo = COALESCE(${logo}, logo)
            WHERE id = ${id}
            RETURNING id, card_front, card_back, logo
        `;
        
        if (result.length === 0) {
            return res.status(404).json({ error: 'Company not found' });
        }
        
        console.log(`Card exteriors updated for company ${id}`);
        
        res.json({ 
            success: true, 
            cardFront: result[0].card_front,
            cardBack: result[0].card_back,
            logo: result[0].logo
        });
        
    } catch (error) {
        console.error('Update card exteriors error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get company card exteriors (for company dashboard)
app.get('/api/companies/:id/card-exteriors', async (req, res) => {
    try {
        const sessionId = req.headers['x-session-id'];
        const { id } = req.params;
        
        if (!sessionId || !sql) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const sessionResult = await sql`
            SELECT role, company_id FROM sessions 
            WHERE id = ${sessionId} AND expires_at > NOW()
        `;
        
        if (sessionResult.length === 0) {
            return res.status(401).json({ error: 'Session expired' });
        }
        
        const session = sessionResult[0];
        
        // Company admin can only view their own company
        if (session.role === 'company_admin' && session.company_id !== id) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        
        const result = await sql`
            SELECT card_front, card_back, logo FROM companies WHERE id = ${id}
        `;
        
        if (result.length === 0) {
            return res.status(404).json({ error: 'Company not found' });
        }
        
        res.json({ 
            cardFront: result[0].card_front,
            cardBack: result[0].card_back,
            logo: result[0].logo
        });
        
    } catch (error) {
        console.error('Get card exteriors error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Error handler for multer
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large. Maximum size is 2MB.' });
        }
        return res.status(400).json({ error: err.message });
    }
    if (err) {
        return res.status(400).json({ error: err.message });
    }
    next();
});

// ==================== COMPANY ROUTES ====================

// Get all companies (super admin only)
app.get('/api/companies', requireAuth, async (req, res) => {
    try {
        if (req.session.role !== 'super_admin') {
            return res.status(403).json({ error: 'Forbidden' });
        }
        
        const companies = await sql`
            SELECT 
                c.id, c.name, c.email, c.logo, c.created_at,
                COUNT(ct.id) as contact_count
            FROM companies c
            LEFT JOIN contacts ct ON ct.company_id = c.id
            GROUP BY c.id
            ORDER BY c.created_at DESC
        `;
        
        res.json(companies.map(c => ({
            id: c.id,
            name: c.name,
            email: c.email,
            logo: c.logo,
            contactCount: parseInt(c.contact_count),
            createdAt: c.created_at
        })));
    } catch (error) {
        console.error('Get companies error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Create company (super admin only)
app.post('/api/companies', requireAuth, async (req, res) => {
    try {
        if (req.session.role !== 'super_admin') {
            return res.status(403).json({ error: 'Forbidden' });
        }
        
        const { name, email, password, logo } = req.body;
        
        // Check if email already exists
        const existing = await sql`SELECT id FROM companies WHERE email = ${email}`;
        if (existing.length > 0) {
            return res.status(400).json({ error: 'Email already exists' });
        }
        
        const result = await sql`
            INSERT INTO companies (name, email, password, logo)
            VALUES (${name}, ${email}, ${password}, ${logo || ''})
            RETURNING id, name, email, logo, created_at
        `;
        
        const company = result[0];
        res.json({ 
            success: true, 
            id: company.id,
            name: company.name,
            email: company.email,
            logo: company.logo,
            createdAt: company.created_at
        });
    } catch (error) {
        console.error('Create company error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update company (super admin only)
app.put('/api/companies/:id', requireAuth, async (req, res) => {
    try {
        if (req.session.role !== 'super_admin') {
            return res.status(403).json({ error: 'Forbidden' });
        }
        
        const { id } = req.params;
        const { name, email, password, logo } = req.body;
        
        // Build update query dynamically
        let result;
        if (password) {
            result = await sql`
                UPDATE companies 
                SET name = COALESCE(${name}, name),
                    email = COALESCE(${email}, email),
                    password = ${password},
                    logo = COALESCE(${logo}, logo)
                WHERE id = ${id}
                RETURNING id, name, email, logo
            `;
        } else {
            result = await sql`
                UPDATE companies 
                SET name = COALESCE(${name}, name),
                    email = COALESCE(${email}, email),
                    logo = COALESCE(${logo}, logo)
                WHERE id = ${id}
                RETURNING id, name, email, logo
            `;
        }
        
        if (result.length === 0) {
            return res.status(404).json({ error: 'Company not found' });
        }
        
        res.json({ success: true, ...result[0] });
    } catch (error) {
        console.error('Update company error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete company (super admin only)
app.delete('/api/companies/:id', requireAuth, async (req, res) => {
    try {
        if (req.session.role !== 'super_admin') {
            return res.status(403).json({ error: 'Forbidden' });
        }
        
        const { id } = req.params;
        
        const result = await sql`DELETE FROM companies WHERE id = ${id} RETURNING id`;
        
        if (result.length === 0) {
            return res.status(404).json({ error: 'Company not found' });
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('Delete company error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== CONTACT ROUTES ====================

// Get contacts (filtered by company for company admin)
app.get('/api/contacts', requireAuth, async (req, res) => {
    try {
        let contacts;
        
        if (req.session.role === 'company_admin') {
            contacts = await sql`
                SELECT * FROM contacts WHERE company_id = ${req.session.companyId}
                ORDER BY created_at DESC
            `;
        } else if (req.query.companyId) {
            contacts = await sql`
                SELECT * FROM contacts WHERE company_id = ${req.query.companyId}
                ORDER BY created_at DESC
            `;
        } else {
            contacts = await sql`SELECT * FROM contacts ORDER BY created_at DESC`;
        }
        
        res.json(contacts.map(c => ({
            id: c.id,
            companyId: c.company_id,
            nameEn: c.name_en,
            nameAr: c.name_ar,
            positionEn: c.position_en,
            positionAr: c.position_ar,
            location: c.location,
            phone: c.phone,
            email: c.email,
            website: c.website,
            createdAt: c.created_at
        })));
    } catch (error) {
        console.error('Get contacts error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get single contact (public)
app.get('/api/contacts/:id', async (req, res) => {
    try {
        if (!sql) {
            return res.status(500).json({ error: 'Database not configured' });
        }
        
        const result = await sql`
            SELECT c.*, comp.name as company_name, comp.logo as company_logo
            FROM contacts c
            LEFT JOIN companies comp ON comp.id = c.company_id
            WHERE c.id = ${req.params.id}
        `;
        
        if (result.length === 0) {
            return res.status(404).json({ error: 'Contact not found' });
        }
        
        const c = result[0];
        res.json({ 
            id: c.id,
            companyId: c.company_id,
            nameEn: c.name_en,
            nameAr: c.name_ar,
            positionEn: c.position_en,
            positionAr: c.position_ar,
            location: c.location,
            phone: c.phone,
            email: c.email,
            website: c.website,
            companyName: c.company_name,
            companyLogo: c.company_logo
        });
    } catch (error) {
        console.error('Get contact error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Create contact
app.post('/api/contacts', requireAuth, async (req, res) => {
    try {
        const companyId = req.session.role === 'company_admin' 
            ? req.session.companyId 
            : req.body.companyId;
        
        if (!companyId) {
            return res.status(400).json({ error: 'Company ID required' });
        }
        
        const { nameEn, nameAr, positionEn, positionAr, location, phone, email, website } = req.body;
        const id = req.body.id || nameEn.toLowerCase().replace(/\s+/g, '-') + '-' + Date.now();
        
        const result = await sql`
            INSERT INTO contacts (id, company_id, name_en, name_ar, position_en, position_ar, location, phone, email, website)
            VALUES (${id}, ${companyId}, ${nameEn}, ${nameAr || ''}, ${positionEn}, ${positionAr || ''}, ${location}, ${phone}, ${email}, ${website || ''})
            RETURNING *
        `;
        
        const c = result[0];
        res.json({ 
            success: true,
            id: c.id,
            companyId: c.company_id,
            nameEn: c.name_en,
            nameAr: c.name_ar,
            positionEn: c.position_en,
            positionAr: c.position_ar,
            location: c.location,
            phone: c.phone,
            email: c.email,
            website: c.website
        });
    } catch (error) {
        console.error('Create contact error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update contact
app.put('/api/contacts/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        
        // Check permission for company admin
        if (req.session.role === 'company_admin') {
            const check = await sql`
                SELECT company_id FROM contacts WHERE id = ${id}
            `;
            if (check.length === 0 || check[0].company_id !== req.session.companyId) {
                return res.status(403).json({ error: 'Forbidden' });
            }
        }
        
        const { nameEn, nameAr, positionEn, positionAr, location, phone, email, website } = req.body;
        
        const result = await sql`
            UPDATE contacts 
            SET name_en = COALESCE(${nameEn}, name_en),
                name_ar = COALESCE(${nameAr}, name_ar),
                position_en = COALESCE(${positionEn}, position_en),
                position_ar = COALESCE(${positionAr}, position_ar),
                location = COALESCE(${location}, location),
                phone = COALESCE(${phone}, phone),
                email = COALESCE(${email}, email),
                website = COALESCE(${website}, website)
            WHERE id = ${id}
            RETURNING *
        `;
        
        if (result.length === 0) {
            return res.status(404).json({ error: 'Contact not found' });
        }
        
        const c = result[0];
        res.json({ 
            success: true,
            id: c.id,
            nameEn: c.name_en,
            nameAr: c.name_ar,
            positionEn: c.position_en,
            positionAr: c.position_ar,
            location: c.location,
            phone: c.phone,
            email: c.email,
            website: c.website
        });
    } catch (error) {
        console.error('Update contact error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete contact
app.delete('/api/contacts/:id', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        
        // Check permission for company admin
        if (req.session.role === 'company_admin') {
            const check = await sql`
                SELECT company_id FROM contacts WHERE id = ${id}
            `;
            if (check.length === 0 || check[0].company_id !== req.session.companyId) {
                return res.status(403).json({ error: 'Forbidden' });
            }
        }
        
        const result = await sql`DELETE FROM contacts WHERE id = ${id} RETURNING id`;
        
        if (result.length === 0) {
            return res.status(404).json({ error: 'Contact not found' });
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('Delete contact error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== PAGE ROUTES ====================

// Super Admin
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html'));
});

app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'login.html'));
});

app.get('/admin/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin', 'dashboard.html'));
});

// Company Admin
app.get('/company', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'company', 'index.html'));
});

app.get('/company/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'company', 'login.html'));
});

app.get('/company/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'company', 'dashboard.html'));
});

// Public contact pages
app.get('/c/:id', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'contact.html'));
});

app.get('/qr/:id', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'qr.html'));
});

// Home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server (only when running locally, not on Vercel)
if (process.env.VERCEL !== '1') {
    app.listen(PORT, () => {
        console.log(`\n🚀 Server running at http://localhost:${PORT}`);
        console.log(`\n📋 Routes:`);
        console.log(`   - Home:           http://localhost:${PORT}/`);
        console.log(`   - Super Admin:    http://localhost:${PORT}/admin`);
        console.log(`   - Company Login:  http://localhost:${PORT}/company`);
        console.log(`\n🔐 Super Admin: ml@feedbacknfc.com`);
        console.log(`   (Auth code will be shown in console)\n`);
    });
}

// Export for Vercel
module.exports = app;
