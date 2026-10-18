import pg from 'pg';
import "dotenv/config";

export const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
});

pool.on('error', (err) => {
  console.error('Unexpected Postgres error', err);
});

export default pool;