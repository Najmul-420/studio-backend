import express from 'express';
import 'dotenv/config';
import { MongoClient, ObjectId } from 'mongodb';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';

const PORT = process.env.PORT || 5000;
const app = express();

// 1. Middlewares Setup (CORS for cookies support)
app.use(express.json());
app.use(cookieParser());

const allowedOrigins = [
    'https://studio-frontend-dun.vercel.app', 
    'https://studio-space-client.vercel.app',
    'http://localhost:3000',
    process.env.CLIENT_URL
].filter(Boolean);

app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps, curl, or same-origin)
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(null, true); // Permissive in dev/staging to avoid unexpected CORS blocks
        }
    },
    credentials: true
}));

const getCookieOptions = () => ({
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    path: '/'
});

// 2. JWT Verification Middleware
const verifyToken = (req, res, next) => {
    const token = req.cookies?.token || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.split(' ')[1] : null);
    if (!token) {
        return res.status(401).send({ message: 'Unauthorized access: No token provided' });
    }
    jwt.verify(token, (process.env.JWT_SECRET || 'secretkey').trim(), (err, decoded) => {
        if (err) {
            return res.status(401).send({ message: 'Unauthorized access: Invalid token' });
        }
        req.user = decoded;
        next();
    });
};

// 3. MongoDB Connection & Collections Setup
const mongoUrl = process.env.MONGODB_URL;
const client = mongoUrl ? new MongoClient(mongoUrl) : null;

let studioCollection;
let bookingCollection;
let userCollection; 

async function connectDB() {
    if (!client) {
        throw new Error("MONGODB_URL is not configured in environment variables.");
    }
    if (!userCollection || !studioCollection || !bookingCollection) {
        await client.connect();
        const db = client.db("studioSpaceDB");
        studioCollection = db.collection("studios");
        bookingCollection = db.collection("bookings");
        userCollection = db.collection("users");
    }
}

// Middleware to ensure DB connection on serverless environments
app.use(async (req, res, next) => {
    try {
        await connectDB();
        next();
    } catch (err) {
        console.error("MongoDB Connection Error:", err);
        return res.status(500).send({ message: "Database connection failed", error: err.message });
    }
});

// ================= AUTHENTICATION & USER APIs =================
app.post(['/jwt', '/api/jwt'], async (req, res) => {
    const user = req.body; // { email: 'user@gmail.com' }
    const token = jwt.sign(user, (process.env.JWT_SECRET || 'secretkey').trim(), { expiresIn: '7d' });
    
    res.cookie('token', token, getCookieOptions()).send({ success: true });
});

app.post(['/logout', '/api/logout'], async (req, res) => {
    res.clearCookie('token', getCookieOptions()).send({ success: true });
});

// রেজিস্টার করা ইউজারদের ডাটা MongoDB তে সেভ করার API
app.post(['/users', '/api/users'], async (req, res) => {
    try {
        const newUser = req.body;
        
        if (!newUser.email || !newUser.name) {
            return res.status(400).send({ message: 'Name and email are required.' });
        }

        // চেক করা ইউজার ইতিমধ্যে ডাটাবেজে আছে কি না
        const existingUser = await userCollection.findOne({ 
            email: { $regex: new RegExp(`^${newUser.email.trim()}$`, 'i') } 
        });
        if (existingUser) {
            return res.status(400).send({ message: 'User already exists!' });
        }

        const userToSave = {
            ...newUser,
            email: newUser.email.trim().toLowerCase(),
            createdAt: new Date()
        };

        const result = await userCollection.insertOne(userToSave);
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: "Failed to register user" });
    }
});

// Google Authentication / Sign In Route
app.post(['/auth/google', '/api/auth/google'], async (req, res) => {
    try {
        const { email, name, photoUrl } = req.body;
        if (!email) {
            return res.status(400).send({ message: "Email is required" });
        }

        const normalizedEmail = email.trim().toLowerCase();
        
        // ১. ডাটাবেজে ইউজার আছে কি না চেক করা
        let user = await userCollection.findOne({ email: normalizedEmail });
        
        if (!user) {
            // না থাকলে নতুন ইউজার হিসেবে সেভ করা
            const newUser = { 
                name: name || 'Creator', 
                email: normalizedEmail, 
                photoUrl: photoUrl || '', 
                createdAt: new Date() 
            };
            await userCollection.insertOne(newUser);
            user = newUser;
        }

        // ২. JWT টোকেন তৈরি করা
        const token = jwt.sign(
            { email: user.email, name: user.name }, 
            (process.env.JWT_SECRET || 'secretkey').trim(), 
            { expiresIn: '7d' }
        );
        
        // ৩. কুকিতে টোকেন সেট করে রেসপন্স পাঠানো
        res.cookie('token', token, getCookieOptions()).send({ 
            success: true, 
            user: { name: user.name, email: user.email, photoUrl: user.photoUrl } 
        });
    } catch (error) {
        res.status(500).send({ message: "Google authentication failed" });
    }
});

// Login Route: Authenticate user and send token cookie
app.post(['/auth/login', '/api/auth/login'], async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).send({ message: 'Email and password are required.' });
        }

        const normalizedEmail = email.trim().toLowerCase();
        
        // ১. ডাটাবেজ থেকে ইউজার খুঁজে দেখা
        const user = await userCollection.findOne({ email: normalizedEmail });
        if (!user) {
            return res.status(401).send({ message: 'Invalid email or password.' });
        }

        // ২. যদি পাসওয়ার্ড ছাড়া অ্যাকাউন্ট তৈরি হয়ে থাকে (যেমন গুগল লগইন)
        if (!user.password) {
            return res.status(400).send({ 
                message: 'This account was created with Google Sign-In. Please sign in using Google.' 
            });
        }

        // ৩. পাসওয়ার্ড ম্যাচ চেক
        if (user.password !== password) {
            return res.status(401).send({ message: 'Invalid email or password.' });
        }

        // ৪. JWT টোকেন তৈরি করা
        const token = jwt.sign(
            { email: user.email, name: user.name }, 
            (process.env.JWT_SECRET || 'secretkey').trim(), 
            { expiresIn: '7d' }
        );
        
        // ৫. কুকিতে টোকেন সেট করে ইউজার ডাটা পাঠানো
        res.cookie('token', token, getCookieOptions()).send({ 
            success: true, 
            user: { name: user.name, email: user.email, photoUrl: user.photoUrl } 
        });

    } catch (error) {
        res.status(500).send({ message: "Failed to sign in" });
    }
});

// ================= STUDIOS APIs =================

// Public Route: Get All Studios (উন্মুক্ত ব্রাউজিং - টোকেন ছাড়া যে কেউ দেখতে পারবে)
app.get(['/studios', '/api/studios'], async (req, res) => {
    try {
        const category = req.query.category;
        const limit = parseInt(req.query.limit);
        let query = {};
        
        if (category && category !== 'All') {
            query = { category: category };
        }

        let cursor = studioCollection.find(query);
        if (limit && limit > 0) {
            cursor = cursor.limit(limit);
        }
        const studios = await cursor.toArray();
        
        // Map _id to id string while keeping _id intact
        const result = studios.map(studio => ({
            ...studio,
            _id: studio._id.toString(),
            id: studio._id.toString(),
            imageUrl: studio.imageUrl || studio.thumbnail || '',
            thumbnail: studio.thumbnail || studio.imageUrl || ''
        }));

        res.send(result);
    } catch (error) {
        res.status(500).send({ message: "Failed to fetch studios" });
    }
});

// Public Route: Get Single Studio Details (উন্মুক্ত রুট - টোকেন ছাড়া দেখা যাবে)
app.get(['/studios/:id', '/api/studios/:id'], async (req, res) => {
    try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
            return res.status(404).send({ message: "Studio not found" });
        }
        const query = { _id: new ObjectId(id) };
        const studio = await studioCollection.findOne(query);
        if (!studio) {
            return res.status(404).send({ message: "Studio not found" });
        }

        const result = {
            ...studio,
            _id: studio._id.toString(),
            imageUrl: studio.imageUrl || studio.thumbnail || '',
            thumbnail: studio.thumbnail || studio.imageUrl || ''
        };

        res.send(result);
    } catch (error) {
        res.status(500).send({ message: "Failed to fetch studio details" });
    }
});

// Protected Route: Add New Studio (লগইন করা বাধ্যতামূলক)
app.post(['/studios', '/api/studios'], verifyToken, async (req, res) => {
    try {
        const studioBody = req.body;
        const image = studioBody.thumbnail || studioBody.imageUrl || '';
        
        const newStudio = {
            ...studioBody,
            thumbnail: image,
            imageUrl: image,
            hostEmail: (studioBody.hostEmail || req.user.email).toLowerCase(),
            createdAt: new Date()
        };

        const result = await studioCollection.insertOne(newStudio);
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: "Failed to add studio" });
    }
});

// Protected Route: Get My Studio Listings (লগইন করা বাধ্যতামূলক)
app.get(['/my-listings', '/api/my-listings'], verifyToken, async (req, res) => {
    try {
        const email = req.query.email;
        if (!email || req.user.email.toLowerCase() !== email.toLowerCase()) {
            return res.status(403).send({ message: 'Forbidden access' });
        }
        const query = { 
            hostEmail: { $regex: new RegExp(`^${email.trim()}$`, 'i') } 
        };
        const listings = await studioCollection.find(query).toArray();
        const result = listings.map(studio => ({
            ...studio,
            _id: studio._id.toString(),
            imageUrl: studio.imageUrl || studio.thumbnail || '',
            thumbnail: studio.thumbnail || studio.imageUrl || ''
        }));
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: "Failed to fetch user listings" });
    }
});

// Protected Route: Update Studio (লগইন করা বাধ্যতামূলক এবং মালিকানা চেক)
app.put(['/studios/:id', '/api/studios/:id'], verifyToken, async (req, res) => {
    try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
            return res.status(404).send({ message: "Studio not found" });
        }
        const filter = { _id: new ObjectId(id) };

        // মালিকানা ভেরিফিকেশন
        const existingStudio = await studioCollection.findOne(filter);
        if (!existingStudio) {
            return res.status(404).send({ message: "Studio not found" });
        }
        if (existingStudio.hostEmail && existingStudio.hostEmail.toLowerCase() !== req.user.email.toLowerCase()) {
            return res.status(403).send({ message: "Forbidden: You are not authorized to edit this studio" });
        }

        const updatedStudio = req.body;
        const image = updatedStudio.thumbnail || updatedStudio.imageUrl || existingStudio.thumbnail || existingStudio.imageUrl || '';

        const updateDoc = {
            $set: {
                title: updatedStudio.title,
                category: updatedStudio.category,
                hourlyRate: updatedStudio.hourlyRate,
                securityDeposit: updatedStudio.securityDeposit,
                maxCapacity: updatedStudio.maxCapacity,
                location: updatedStudio.location,
                thumbnail: image,
                imageUrl: image,
                images: updatedStudio.images || existingStudio.images || [],
                overview: updatedStudio.overview,
                amenities: updatedStudio.amenities,
                updatedAt: new Date()
            },
        };
        const result = await studioCollection.updateOne(filter, updateDoc);
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: "Failed to update studio" });
    }
});

// Protected Route: Delete Studio (লগইন করা বাধ্যতামূলক এবং মালিকানা চেক)
app.delete(['/studios/:id', '/api/studios/:id'], verifyToken, async (req, res) => {
    try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
            return res.status(404).send({ message: "Studio not found" });
        }
        const query = { _id: new ObjectId(id) };

        // মালিকানা ভেরিফিকেশন
        const existingStudio = await studioCollection.findOne(query);
        if (!existingStudio) {
            return res.status(404).send({ message: "Studio not found" });
        }
        if (existingStudio.hostEmail && existingStudio.hostEmail.toLowerCase() !== req.user.email.toLowerCase()) {
            return res.status(403).send({ message: "Forbidden: You are not authorized to delete this studio" });
        }

        const result = await studioCollection.deleteOne(query);
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: "Failed to delete studio" });
    }
});

// ================= BOOKING APIs =================

// Protected Route: Create Booking (Double-Booking Prevention with standard interval overlap)
app.post(['/bookings', '/api/bookings'], verifyToken, async (req, res) => {
    try {
        const booking = req.body; 

        if (!booking.studioId || !booking.bookingDate || !booking.startTime || !booking.endTime) {
            return res.status(400).send({ message: 'Missing required booking parameters' });
        }

       
        const studioIdFilters = [{ studioId: booking.studioId }];
        if (ObjectId.isValid(booking.studioId)) {
            studioIdFilters.push({ studioId: new ObjectId(booking.studioId) });
        }

        const existingBooking = await bookingCollection.findOne({
            $or: studioIdFilters,
            bookingDate: booking.bookingDate,
            status: { $in: ['Confirmed', 'Pending'] },
            startTime: { $lt: booking.endTime },
            endTime: { $gt: booking.startTime }
        });

        if (existingBooking) {
            return res.status(400).send({ 
                message: 'Time slot collision! This studio is already booked for the selected time.' 
            });
        }

        const newBooking = {
            ...booking,
            userName: booking.userName || req.user.name || 'Creator',
            userEmail: req.user.email.toLowerCase(),
            createdAt: new Date()
        };

        const result = await bookingCollection.insertOne(newBooking);
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: "Failed to create booking" });
    }
});

// Protected Route: Get My Bookings (লগইন করা বাধ্যতামূলক)
app.get(['/my-bookings', '/api/my-bookings'], verifyToken, async (req, res) => {
    try {
        const email = (req.query.email || req.user.email).trim().toLowerCase();
        if (req.user.email.toLowerCase() !== email) {
            return res.status(403).send({ message: 'Forbidden access' });
        }
        const query = { 
            userEmail: { $regex: new RegExp(`^${email}$`, 'i') } 
        };
        const bookings = await bookingCollection.find(query).toArray();
        const result = bookings.map(b => ({
            ...b,
            _id: b._id.toString()
        }));
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: "Failed to fetch bookings" });
    }
});


// Root Endpoint
app.get("/", (req, res) => {
    res.send('StudioSpace Backend Server is Running...');
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    
});

export default app;
