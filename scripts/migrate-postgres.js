import fs from "fs";
import path from "path";
import dotenv from "dotenv";
import pg from "pg";

const { Pool } = pg;

dotenv.config();

const migrationsDir = path.resolve("migrations/postgres");

function getMigrationFiles(targetArg) {
    const target = (targetArg || "001").toLowerCase();
    const migrationMap = {
        "001": "001_init_schema.sql",
        "1": "001_init_schema.sql",
        "init": "001_init_schema.sql",
        "001_init_schema": "001_init_schema.sql",
        "001_init_schema.sql": "001_init_schema.sql",
        "002": "002_content_tables.sql",
        "2": "002_content_tables.sql",
        "content": "002_content_tables.sql",
        "002_content_tables": "002_content_tables.sql",
        "002_content_tables.sql": "002_content_tables.sql"
    };

    if (target === "all") {
        return fs
            .readdirSync(migrationsDir)
            .filter((file) => /^\d+_.+\.sql$/i.test(file))
            .sort();
    }

    const selected = migrationMap[target];
    if (!selected) {
        throw new Error(
            `Unknown migration target "${targetArg}". Use 001, 002, or all.`
        );
    }

    return [selected];
}

async function run() {
    const connectionString = process.env.SUPABASE_DB_URL || process.env.DATABASE_URL;
    const database = process.env.PG_DB_NAME || process.env.DB_NAME || "pima_training_institute";
    const requestedTarget = process.argv[2];
    const migrationFiles = getMigrationFiles(requestedTarget);

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

    const client = await pool.connect();

    try {
        for (const migrationFile of migrationFiles) {
            const migrationPath = path.join(migrationsDir, migrationFile);
            const sql = fs.readFileSync(migrationPath, "utf8");
            await client.query(sql);
            console.log(`Applied PostgreSQL migration: ${migrationFile}`);
        }

        console.log(
            `PostgreSQL migration completed for database: ${database} (target: ${requestedTarget || "001"})`
        );
    } finally {
        client.release();
        await pool.end();
    }
}

run().catch((error) => {
    console.error("PostgreSQL migration failed:", error.message);
    process.exit(1);
});
