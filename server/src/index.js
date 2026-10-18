// import "dotenv/config";
import express from 'express';
import auth_Router from './routes/auth.js';
import health_Router from './routes/health.js';


const app = express();
const PORT = 4040;

// middlewares 
app.use( "/auth", express.json({ limit: "1mb" }) );

// routers


//index page  
app.get('/', (req, res) => {
  res.send('Welcome to my first node express app!');
});



//routers
app.use("/auth", auth_Router);
app.use("/health", health_Router);



app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});

