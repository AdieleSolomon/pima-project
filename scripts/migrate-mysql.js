import fs from "fs";
import path from "path";
import dotenv from "dotenv";
import mysql from "mysql2/promise";

dotenv.config();

const migrationFile = path.resolve("migrations/mysql/001_init_schema.sql");

async function run() {
    const host = process.env.DB_HOST || "localhost";
    const user = process.env.DB_USER || "root";
    const password = process.env.DB_PASSWORD || "";
    const database = process.env.DB_NAME || "pima_training_institute";
    const port = Number(process.env.DB_PORT || 3306);

    const sql = fs.readFileSync(migrationFile, "utf8");

    const connection = await mysql.createConnection({
        host,
        user,
        password,
        database,
        port,
        multipleStatements: true
    });

    try {
        await connection.query(sql);
        console.log(`MySQL migration completed for database: ${database}`);
    } finally {
        await connection.end();
    }
}

run().catch((error) => {
    console.error("MySQL migration failed:", error.message);
    process.exit(1);
});
