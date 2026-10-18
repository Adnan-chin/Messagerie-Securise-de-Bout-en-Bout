import express from 'express';

import pool from "../db/db.js";

const app = express();

app.get("/", async (req, res) => {
    try {
        await pool.query("SELECT 1");

        res.status(200).json({
            status: "ok",
            database: "connected",
        });
    } catch (error) {
        console.error("Database health check failed:", error.message);

        res.status(503).json({
            status: "error",
            database: "disconnected",
        });
    }
});

export default app;
