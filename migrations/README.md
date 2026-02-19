# Database Migrations

## Files
- `migrations/mysql/001_init_schema.sql`: MySQL (Laragon) schema
- `migrations/postgres/001_init_schema.sql`: PostgreSQL (Supabase) schema

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

If you prefer Supabase SQL Editor, run:
- `migrations/postgres/001_init_schema.sql`

Then set env:
- local dev: `DB_CLIENT=mysql`
- production: `DB_CLIENT=postgres`
