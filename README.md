# 🚀 ClearLens – Real-Time Focus & Productivity Web App

ClearLens is a modern, AI-powered productivity web application that helps students and professionals improve their focus using **real-time webcam-based attention tracking**, **analytics**, **leaderboards**, and an **integrated AI DoubtSolver** — all in one clean, distraction-free platform.

---

## 📌 Problem Statement

Students often sit in front of their laptops but still lose focus due to:
- Digital distractions  
- App switching  
- Lack of real-time attention awareness  
- No true measurement of actual focus  

Most existing productivity tools only track **time**, not **attention**.  
**ClearLens solves this by monitoring real human focus using webcam-based AI.**

---

## 🎯 Objectives

- Provide **real-time webcam-based attention monitoring**
- Track **true focus instead of just time**
- Encourage consistency through **streaks and leaderboards**
- Offer **instant doubt solving** without leaving the platform
- Deliver an **all-in-one distraction-free productivity environment**

---

## ✨ Key Features

✅ **Real-Time Focus Monitoring**  
Tracks eye and face movement using **MediaPipe FaceMesh** to detect attention.

✅ **Session Analytics & Scoring**  
Stores focused time, total time, and generates productivity scores.

✅ **Daily Streaks & Calendar View**  
Encourages consistent study habits.

✅ **Gamified Leaderboard**  
Ranks users based on focus performance.

✅ **Integrated DoubtSolver (AI Chatbot)**  
Instant academic help using **Ollama + Mistral** without switching apps.

✅ **Privacy-Friendly Design**  
All webcam processing happens on the **client side only**.

✅ **Modern, Minimal UI**  
Inspired by Apple-style design for a distraction-free experience.

---

## 🧑‍💻 Tech Stack

### Frontend
- React + Vite
- Tailwind CSS
- Framer Motion
- MediaPipe FaceMesh

### Backend
- Node.js
- Express.js
- MongoDB Atlas
- JWT Authentication
- Axios

### AI
- Ollama Local AI Runtime
- Mistral LLM Model

---

## ⚙️ System Architecture

- Webcam → MediaPipe (Client)
- Focus Data → Express API
- Storage → MongoDB Atlas
- Authentication → JWT
- AI DoubtSolver → Ollama + Mistral
- Leaderboard & Analytics → MongoDB Aggregations

---

## 🖥️ Major Modules

- **Home Dashboard**
- **Focus Session (CalmCam)**
- **Leaderboard**
- **DoubtSolver AI**
- **User Authentication**
- **Streak Tracking**
- **Session Analytics**

---

## 📊 Result

The system successfully:
- Tracks real-time focus using the webcam
- Stores accurate focus analytics
- Motivates users through streaks and leaderboards
- Provides instant AI-based academic support
- Reduces distraction and app-switching

---

## 🚀 Future Scope

- Advanced gaze tracking with head-pose estimation
- Emotion & fatigue detection
- Mobile app development
- AI-based personalized productivity suggestions
- Google Classroom & LMS integration
- Peer accountability focus rooms
- Voice-based DoubtSolver
- Deep analytics dashboards with performance graphs

---

## 🛠️ Installation & Setup

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/your-username/ClearLens.git
cd ClearLens
```

### 2️⃣ Backend Setup
```bash
cd Backend
npm install
```

Create a `.env` file:
```env
PORT=8080
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_secret_key
```

Run backend:
```bash
npm start
```

### 3️⃣ Frontend Setup
```bash
cd Frontend
npm install
npm run dev
```

---

## 🔐 Authentication Flow

- JWT-based secure authentication
- Token stored in localStorage
- Auto-login persistence
- Protected routes using middleware

---

## 👥 Team Members

- **Jiyotirmaan Singh** (0131CL231040)  
- **Arbaaz Arif** (0131CL231028)  
- **Piyush Billore** (0131CL231065)  

---

## 👨‍🏫 Guide

**Prof. Uma Vishwakarma**

**Head of Department:**  
**Dr. Ayonija Pathre**

**Department:** Artificial Intelligence & Machine Learning  
**Session:** 2025–2026  

---

## 📚 References

- MediaPipe Documentation – https://developers.google.com/mediapipe  
- React Documentation – https://react.dev  
- Express.js – https://expressjs.com  
- MongoDB Atlas – https://www.mongodb.com/atlas  
- Tailwind CSS – https://tailwindcss.com  
- Axios – https://axios-http.com  
- JWT – https://jwt.io  
- Ollama – https://ollama.com  
- Google Scholar – https://scholar.google.com  

---

## 🙏 Acknowledgement

We sincerely thank **Dr. Ayonija Pathre**, Head of the Department (CSE–AIML), for providing continuous encouragement and academic support.  

We also express our heartfelt gratitude to our guide **Prof. Uma Vishwakarma** for her valuable guidance, feedback, and constant mentorship throughout the development of **ClearLens**.

---

## 📌 Project Status

✅ Functional  
✅ Database Integrated  
✅ AI DoubtSolver Working  
✅ Leaderboard Live  
✅ Focus Tracking Implemented  
✅ Authentication Secured  

---

## ⭐ If you like this project, give it a star!
