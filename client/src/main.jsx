import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

if (!window.crypto?.subtle) {
  throw new Error('crypto.subtle indisponible : utilisez HTTPS ou localhost');
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
