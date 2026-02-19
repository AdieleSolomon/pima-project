import fs from "fs";
import path from "path";
import dotenv from "dotenv";
import pg from "pg";

const { Pool } = pg;

dotenv.config();

const migrationFile = path.resolve("migrations/postgres/001_init_schema.sql");

async function run() {
    const connectionString = process.env.SUPABASE_DB_URL || process.env.DATABASE_URL;
    const database = process.env.PG_DB_NAME || process.env.DB_NAME || "pima_training_institute";

    const pool = connectionString
        ? new Pool({
            connectionString,
            ssl: process.env.PG_SSL === "false" ? false : { rejectUnauthorized: false }
        })
        : new Pool({
            host: process.env.PG_HOST,
            port: Number(process.env.PG_PORT || 5432),
            user: process.env.PG_USER,
            password: process.env.PG_PASSWORD,
            database,
            ssl: process.env.PG_SSL === "false" ? false : { rejectUnauthorized: false }
        });

    const sql = fs.readFileSync(migrationFile, "utf8");
    const client = await pool.connect();

    try {
        await client.query(sql);
        console.log(`PostgreSQL migration completed for database: ${database}`);
    } finally {
        client.release();
        await pool.end();
    }
}

run().catch((error) => {
    console.error("PostgreSQL migration failed:", error.message);
    process.exit(1);
});
