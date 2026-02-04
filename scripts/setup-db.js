const { neon } = require('@neondatabase/serverless');
require('dotenv').config();

async function setupDatabase() {
    if (!process.env.DATABASE_URL) {
        console.error('❌ DATABASE_URL not found in environment variables');
        process.exit(1);
    }

    const sql = neon(process.env.DATABASE_URL);

    console.log('🔄 Setting up database tables...\n');

    try {
        // Create companies table
        await sql`
            CREATE TABLE IF NOT EXISTS companies (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                logo TEXT,
                card_front TEXT,
                card_back TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `;
        console.log('✅ Created companies table');
        
        // Add card_front and card_back columns if they don't exist (for existing databases)
        try {
            await sql`ALTER TABLE companies ADD COLUMN IF NOT EXISTS card_front TEXT`;
            await sql`ALTER TABLE companies ADD COLUMN IF NOT EXISTS card_back TEXT`;
            console.log('✅ Added card exterior columns');
        } catch (e) {
            // Columns might already exist
        }

        // Create contacts table
        await sql`
            CREATE TABLE IF NOT EXISTS contacts (
                id VARCHAR(255) PRIMARY KEY,
                company_id UUID REFERENCES companies(id) ON DELETE CASCADE,
                name_en VARCHAR(255) NOT NULL,
                name_ar VARCHAR(255),
                position_en VARCHAR(255) NOT NULL,
                position_ar VARCHAR(255),
                location TEXT,
                phone VARCHAR(50) NOT NULL,
                telephone VARCHAR(50),
                email VARCHAR(255) NOT NULL,
                website VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `;
        console.log('✅ Created contacts table');

        // Add telephone column if it doesn't exist (for existing databases)
        try {
            await sql`ALTER TABLE contacts ADD COLUMN IF NOT EXISTS telephone VARCHAR(50)`;
            console.log('✅ Added contacts telephone column');
        } catch (e) {
            // Column might already exist
        }

        // Create sessions table
        await sql`
            CREATE TABLE IF NOT EXISTS sessions (
                id UUID PRIMARY KEY,
                email VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL,
                company_id UUID REFERENCES companies(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
        `;
        console.log('✅ Created sessions table');

        // Create auth_codes table
        await sql`
            CREATE TABLE IF NOT EXISTS auth_codes (
                email VARCHAR(255) PRIMARY KEY,
                code VARCHAR(6) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `;
        console.log('✅ Created auth_codes table');

        // Create leads table for customer lead capture
        await sql`
            CREATE TABLE IF NOT EXISTS leads (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                contact_id VARCHAR(255) REFERENCES contacts(id) ON DELETE CASCADE,
                company_id UUID REFERENCES companies(id) ON DELETE CASCADE,
                customer_name VARCHAR(255) NOT NULL,
                customer_email VARCHAR(255),
                customer_phone VARCHAR(50),
                customer_company VARCHAR(255),
                notes TEXT,
                consented_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `;
        console.log('✅ Created leads table');

        // Create index for faster lookups
        await sql`CREATE INDEX IF NOT EXISTS idx_contacts_company ON contacts(company_id)`;
        await sql`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`;
        await sql`CREATE INDEX IF NOT EXISTS idx_leads_company ON leads(company_id)`;
        await sql`CREATE INDEX IF NOT EXISTS idx_leads_contact ON leads(contact_id)`;
        
        console.log('✅ Created indexes');

        console.log('\n🎉 Database setup complete!');

    } catch (error) {
        console.error('❌ Error setting up database:', error.message);
        process.exit(1);
    }
}

setupDatabase();
