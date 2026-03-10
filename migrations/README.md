# Database Migrations

## Files
- `migrations/mysql/001_init_schema.sql`: MySQL (Laragon) schema
- `migrations/mysql/002_content_tables.sql`: MySQL news/events content tables + seed
- `migrations/postgres/001_init_schema.sql`: PostgreSQL (Supabase) schema
- `migrations/postgres/002_content_tables.sql`: PostgreSQL news/events content tables + seed

## Database Name
Use: `pima_training_institute`

## Run (MySQL)
```bash
npm run migrate:mysql
```

## Run (PostgreSQL / Supabase SQL Editor)
```bash
npm run migrate:postgres
```

Run specific target:
```bash
npm run migrate:postgres -- 001
npm run migrate:postgres -- 002
npm run migrate:postgres -- all
```

If you prefer Supabase SQL Editor, run:
- `migrations/postgres/001_init_schema.sql`
- `migrations/postgres/002_content_tables.sql`

Then set env:
- local dev: `DB_CLIENT=mysql`
- production: `DB_CLIENT=postgres`
