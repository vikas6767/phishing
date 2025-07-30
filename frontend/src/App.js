import React, { useEffect } from "react";
import "./App.css";
import { Routes, Route } from 'react-router-dom';
import EmailAnalysis from "./pages/emailanalysis/EmailAnalysis";
import Navbar from "./components/navbar/Navbar";
import Features from "./components/features/Features";
import CheckUrl from "./pages/checkurl/CheckUrl";
import Head from "./components/head/Head";
import Footer from "./components/footer/Footer";
import Dashboard from "./pages/dashboard/Dashboard";
import PasswordCheckerPage from "./pages/passwordChecker/PasswordCheckerPage";
import Notification from "./components/notifications/Notification";
import { NotificationProvider, useNotification } from "./context/NotificationContext";

function AppContent() {
  const { notifications, removeNotification } = useNotification();

  return (
    <div className="App">
      <Navbar />
      <Routes>
        <Route path="/" element={<Head />} />
        <Route path="/checkurl" element={<CheckUrl />} />
        <Route path="/features" element={<Features />} />
        <Route path="/email-analysis" element={<EmailAnalysis />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/password-checker" element={<PasswordCheckerPage />} />
      </Routes>
      <Footer />
      <Notification notifications={notifications} onDismiss={removeNotification} />
    </div>
  );
}

function App() {
  useEffect(() => {
    // Force dark theme
    localStorage.setItem('theme', 'dark');
    document.documentElement.setAttribute('data-theme', 'dark');
  }, []);

  return (
    <NotificationProvider>
      <AppContent />
    </NotificationProvider>
  );
}

export default App;
