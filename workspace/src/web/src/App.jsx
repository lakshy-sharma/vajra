import { useState } from 'react'
import './App.css'
import VajraDashboard from './components/App'

function App() {
  const [count, setCount] = useState(0)

  return (
    <>
    <VajraDashboard />
    </>
  )
}

export default App
