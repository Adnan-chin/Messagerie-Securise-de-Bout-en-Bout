import { useState } from 'react'
import heroImg from './assets/hero.png'
import reactLogo from './assets/react.svg'
import viteLogo from './assets/vite.svg'
import './App.css'
import ChatWindow from './components/ChatWindow.jsx';

function App() {
  const [count, setCount] = useState(0)

  return (
    <>
      <ChatWindow
        currentUser="alice"
        peer="bob"
        token=""
        role="initiator"
      />
    </>
  )
}

export default App
