import { useState } from 'react'
import './App.css'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { Signup,
         Login,
         Profile,
         VerifyEmail,
         ForgetPassword

 } from './components'  
function App() {
  return (
    <>
    <Router>
      <Routes>
        <Route path="/" index element={<Signup />}/>
        <Route path="/login" element={<Login />}/>
        <Route path="/dashboard" element={<Profile />}/>
        <Route path="/otp/verify" element={<VerifyEmail />}/>
        <Route path="/forget_password" element={<ForgetPassword />}/>
      </Routes>
    </Router>
    </>
  )
}
export default App
