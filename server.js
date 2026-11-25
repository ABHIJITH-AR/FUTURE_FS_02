import "dotenv/config";
import express from "express";
import path from "path";
import crypto from "crypto";
import { GoogleGenAI } from "@google/genai";
import {
  findUserById,
  findUserByEmail,
  createUser,
  updateUser,
  getClientsByUserId,
  getClientById,
  createClientRecord,
  createClientRecords,
  updateClientRecord,
  deleteClientRecord,
  createSession,
  getSession,
  deleteSession,
  hashPassword,
  verifyPassword,
} from "./server/db.js";

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

// Authentication Middleware
async function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      res.status(401).json({ error: "Access denied. Token missing." });
      return;
    }

    const session = await getSession(token);
    if (!session) {
      res.status(401).json({ error: "Session expired or invalid. Please login again." });
      return;
    }

    const user = await findUserById(session.userId);
    if (!user) {
      res.status(401).json({ error: "User associated with this session no longer exists." });
      return;
    }

    req.user = user;
    req.token = token;
    next();
  } catch (err) {
    console.error("Auth middleware error:", err);
    res.status(500).json({ error: "Authentication verification failed." });
  }
}

// ==========================================
// AUTHENTICATION ENDPOINTS
// ==========================================

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { fullName, email, password } = req.body || {};

    if (typeof fullName !== "string" || typeof email !== "string" || typeof password !== "string") {
      res.status(400).json({ error: "All fields (fullName, email, password) are required." });
      return;
    }

    if (!fullName.trim() || !email.trim() || !password) {
      res.status(400).json({ error: "All fields (fullName, email, password) are required." });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      res.status(400).json({ error: "Invalid email format." });
      return;
    }

    if (password.length < 6) {
      res.status(400).json({ error: "Password must be at least 6 characters long." });
      return;
    }

    const existing = await findUserByEmail(normalizedEmail);
    if (existing) {
      res.status(400).json({ error: "An account with this email already exists." });
      return;
    }

    const userId = "u-" + crypto.randomBytes(8).toString("hex");
    const passwordHash = hashPassword(password);

    const newUser = {
      id: userId,
      fullName: fullName.trim(),
      email: normalizedEmail,
      passwordHash,
      createdAt: new Date().toISOString(),
    };

    await createUser(newUser);

    // Auto-seed 5 sample client records for newly registered user
    const defaultSampleLeads = [
      {
        fullName: "Sarah Connor",
        email: "sarah.connor@cyberdyne.com",
        phone: "+1 (555) 019-2834",
        companyName: "Cyberdyne Systems",
        status: "Active",
        priority: "High",
        dealValue: 75000,
        leadSource: "Referral",
        notes: "Interested in full digital systems upgrade and cloud transition.",
      },
      {
        fullName: "Tony Stark",
        email: "tony@starkindustries.com",
        phone: "+1 (555) 382-9102",
        companyName: "Stark Industries",
        status: "Active",
        priority: "High",
        dealValue: 240000,
        leadSource: "Partner Referral",
        notes: "Evaluating dashboard enterprise subscription model.",
      },
      {
        fullName: "Bruce Wayne",
        email: "bruce@wayneenterprises.com",
        phone: "+1 (555) 728-1192",
        companyName: "Wayne Enterprises",
        status: "Pending",
        priority: "Medium",
        dealValue: 125000,
        leadSource: "Direct Web",
        notes: "Evaluating system security metrics and active response indicators.",
      },
      {
        fullName: "Peter Parker",
        email: "peter.parker@dailybugle.com",
        phone: "+1 (555) 918-2039",
        companyName: "Daily Bugle",
        status: "Inactive",
        priority: "Low",
        dealValue: 8500,
        leadSource: "Conference",
        notes: "Needs low-tier pricing plan. Scheduled callback next quarter.",
      },
      {
        fullName: "Diana Prince",
        email: "diana.prince@themysis.org",
        phone: "+1 (555) 867-5309",
        companyName: "Themysis Exhibits",
        status: "Pending",
        priority: "Medium",
        dealValue: 48500,
        leadSource: "Website",
        notes: "Requested a prototype layout and contract by end of the week.",
      },
    ];

    const seedRecords = defaultSampleLeads.map((lead, index) => ({
      id: "c-seed-" + index + "-" + crypto.randomBytes(4).toString("hex"),
      userId,
      fullName: lead.fullName,
      email: lead.email,
      phone: lead.phone,
      companyName: lead.companyName,
      status: lead.status,
      createdAt: new Date(Date.now() - (index + 1) * 3600000 * 24).toISOString(),
      priority: lead.priority,
      dealValue: lead.dealValue,
      leadSource: lead.leadSource,
      notes: lead.notes,
      photo: "",
    }));

    await createClientRecords(seedRecords);

    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 3600000 * 24).toISOString();
    await createSession({ token, userId, expiresAt });

    res.status(201).json({
      message: "Registration successful!",
      token,
      user: {
        id: newUser.id,
        fullName: newUser.fullName,
        email: newUser.email,
      },
    });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: err?.message || "Registration failed. Please try again." });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (typeof email !== "string" || typeof password !== "string" || !email.trim() || !password) {
      res.status(400).json({ error: "Email and password are required." });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const user = await findUserByEmail(normalizedEmail);

    if (!user) {
      res.status(400).json({ error: "No account found with this email. You must register first before you can sign in!" });
      return;
    }

    if (!verifyPassword(password, user.passwordHash)) {
      res.status(400).json({ error: "Incorrect password. Please verify your credentials and try again." });
      return;
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 3600000 * 24).toISOString();
    await createSession({ token, userId: user.id, expiresAt });

    res.json({
      message: "Welcome back!",
      token,
      user: {
        id: user.id,
        fullName: user.fullName,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: err?.message || "Sign in failed. Please try again." });
  }
});

// Logout
app.post("/api/auth/logout", authenticateToken, async (req, res) => {
  try {
    await deleteSession(req.token);
    res.json({ success: true, message: "Logged out successfully." });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ error: "Logout failed." });
  }
});

// Me (Get profile info)
app.get("/api/auth/me", authenticateToken, (req, res) => {
  const user = req.user;
  res.json({
    id: user.id,
    fullName: user.fullName,
    email: user.email,
  });
});

// Update Profile
app.put("/api/auth/profile", authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const { fullName, email } = req.body || {};

    if (typeof fullName !== "string" || typeof email !== "string" || !fullName.trim() || !email.trim()) {
      res.status(400).json({ error: "Full Name and Email are required." });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      res.status(400).json({ error: "Invalid email format." });
      return;
    }

    const existing = await findUserByEmail(normalizedEmail);
    if (existing && existing.id !== user.id) {
      res.status(400).json({ error: "Email is already taken." });
      return;
    }

    await updateUser(user.id, fullName.trim(), normalizedEmail);

    res.json({
      message: "Profile updated successfully!",
      user: {
        id: user.id,
        fullName: fullName.trim(),
        email: normalizedEmail,
      },
    });
  } catch (err) {
    console.error("Update profile error:", err);
    res.status(500).json({ error: "Failed to update profile." });
  }
});

// Change Password
app.put("/api/auth/change-password", authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const { currentPassword, newPassword } = req.body || {};

    if (typeof currentPassword !== "string" || typeof newPassword !== "string" || !currentPassword || !newPassword) {
      res.status(400).json({ error: "Current and new passwords are required." });
      return;
    }

    if (newPassword.length < 6) {
      res.status(400).json({ error: "New password must be at least 6 characters long." });
      return;
    }

    if (!verifyPassword(currentPassword, user.passwordHash)) {
      res.status(400).json({ error: "Current password is incorrect." });
      return;
    }

    const newPasswordHash = hashPassword(newPassword);
    await updateUser(user.id, user.fullName, user.email, newPasswordHash);

    res.json({ message: "Password updated successfully!" });
  } catch (err) {
    console.error("Change password error:", err);
    res.status(500).json({ error: "Failed to update password." });
  }
});

// ==========================================
// CLIENT LEADS ENDPOINTS
// ==========================================

// Get all client leads for authenticated user
app.get("/api/clients", authenticateToken, async (req, res) => {
  try {
    const myClients = await getClientsByUserId(req.user.id);
    res.json(myClients);
  } catch (err) {
    console.error("Fetch clients error:", err);
    res.status(500).json({ error: "Failed to load client leads." });
  }
});

// Add Client
app.post("/api/clients", authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const { fullName, email, phone, companyName, status, priority, dealValue, leadSource, notes } = req.body || {};

    if (
      typeof fullName !== "string" ||
      typeof email !== "string" ||
      typeof phone !== "string" ||
      typeof companyName !== "string" ||
      typeof status !== "string" ||
      !fullName.trim() ||
      !email.trim() ||
      !phone.trim() ||
      !companyName.trim()
    ) {
      res.status(400).json({ error: "All client fields are required." });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      res.status(400).json({ error: "Invalid email format." });
      return;
    }

    const validStatuses = ["Active", "Pending", "Inactive"];
    if (!validStatuses.includes(status)) {
      res.status(400).json({ error: "Status must be Active, Pending, or Inactive." });
      return;
    }

    const validPriorities = ["High", "Medium", "Low"];
    const sanitizedPriority = validPriorities.includes(priority) ? priority : "Medium";
    const parsedDealValue = Number(dealValue);

    const newClient = {
      id: "c-" + crypto.randomBytes(8).toString("hex"),
      userId: user.id,
      fullName: fullName.trim(),
      email: normalizedEmail,
      phone: phone.trim(),
      companyName: companyName.trim(),
      status,
      createdAt: new Date().toISOString(),
      priority: sanitizedPriority,
      dealValue: Number.isFinite(parsedDealValue) && parsedDealValue >= 0 ? parsedDealValue : 0,
      leadSource: typeof leadSource === "string" && leadSource.trim() ? leadSource.trim() : "Direct Web",
      notes: typeof notes === "string" ? notes.trim() : "",
      photo: "",
    };

    const created = await createClientRecord(newClient);

    res.status(201).json({
      message: "Client lead added successfully!",
      client: created,
    });
  } catch (err) {
    console.error("Add client error:", err);
    res.status(500).json({ error: "Failed to create client lead." });
  }
});

// Seed Sample Clients
app.post("/api/clients/seed", authenticateToken, async (req, res) => {
  try {
    const user = req.user;

    const sampleLeads = [
      {
        fullName: "Anand Krishna",
        email: "anand.krishna@keralatech.co",
        phone: "+91 94470 12345",
        companyName: "Kerala Spices & Tech IT",
        status: "Active",
        priority: "High",
        dealValue: 75000,
        leadSource: "Referral",
        notes: "Interested in full digital systems upgrade and cloud transition.",
      },
      {
        fullName: "Meera Nair",
        email: "meera.nair@malabargroup.com",
        phone: "+91 98460 54321",
        companyName: "Malabar Digital Ventures",
        status: "Pending",
        priority: "Medium",
        dealValue: 45000,
        leadSource: "Website",
        notes: "Requested a prototype layout by mid-week.",
      },
      {
        fullName: "Elon Musk",
        email: "elon@spacex.com",
        phone: "+1 (555) 420-6900",
        companyName: "SpaceX Aerospace",
        status: "Active",
        priority: "High",
        dealValue: 990000,
        leadSource: "Cold Outbound",
        notes: "Trying to move Starshield software integrations onto our cloud CRM matrix.",
      },
      {
        fullName: "Rahul Menon",
        email: "rahul.menon@cochinbuilders.in",
        phone: "+91 94460 98765",
        companyName: "Cochin Infrastructure Ltd",
        status: "Inactive",
        priority: "Low",
        dealValue: 12000,
        leadSource: "Direct Web",
        notes: "Follow up scheduled next month after quarterly earnings.",
      },
      {
        fullName: "Siddharth Verma",
        email: "sid.verma@bangalorelabs.com",
        phone: "+91 80252 44321",
        companyName: "Bangalore AI Group",
        status: "Pending",
        priority: "High",
        dealValue: 150000,
        leadSource: "Partner Referral",
        notes: "LLM training pipeline hardware consulting deal.",
      },
      {
        fullName: "Deepa Abraham",
        email: "deepa@indiasoftware.net",
        phone: "+91 90480 11223",
        companyName: "India Software Solutions",
        status: "Active",
        priority: "Medium",
        dealValue: 62000,
        leadSource: "Conference",
        notes: "Prefers communication over secure e-mails and voice notes.",
      },
    ];

    const recordsToInsert = sampleLeads.map((lead, index) => ({
      id: "c-seed-" + index + "-" + crypto.randomBytes(4).toString("hex"),
      userId: user.id,
      fullName: lead.fullName,
      email: lead.email,
      phone: lead.phone,
      companyName: lead.companyName,
      status: lead.status,
      createdAt: new Date(Date.now() - (index + 1) * 3600000 * 24).toISOString(),
      priority: lead.priority,
      dealValue: lead.dealValue,
      leadSource: lead.leadSource,
      notes: lead.notes,
      photo: "",
    }));

    const seededClients = await createClientRecords(recordsToInsert);

    res.status(201).json({
      message: "Successfully seeded 6 premium client leads!",
      clients: seededClients,
    });
  } catch (err) {
    console.error("Seed clients error:", err);
    res.status(500).json({ error: "Failed to seed sample leads." });
  }
});

// Edit Client
app.put("/api/clients/:id", authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const clientId = req.params.id;
    const { fullName, email, phone, companyName, status, priority, dealValue, leadSource, notes } = req.body || {};

    if (
      typeof fullName !== "string" ||
      typeof email !== "string" ||
      typeof phone !== "string" ||
      typeof companyName !== "string" ||
      typeof status !== "string" ||
      !fullName.trim() ||
      !email.trim() ||
      !phone.trim() ||
      !companyName.trim()
    ) {
      res.status(400).json({ error: "All client fields are required." });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      res.status(400).json({ error: "Invalid email format." });
      return;
    }

    const validStatuses = ["Active", "Pending", "Inactive"];
    if (!validStatuses.includes(status)) {
      res.status(400).json({ error: "Status must be Active, Pending, or Inactive." });
      return;
    }

    const clientToEdit = await getClientById(clientId);
    if (!clientToEdit) {
      res.status(404).json({ error: "Client lead not found." });
      return;
    }

    if (clientToEdit.userId !== user.id) {
      res.status(403).json({ error: "Unauthorized access to this client lead." });
      return;
    }

    const validPriorities = ["High", "Medium", "Low"];
    const sanitizedPriority = validPriorities.includes(priority) ? priority : "Medium";
    const parsedDealValue = Number(dealValue);

    const updatedClient = {
      id: clientId,
      userId: user.id,
      fullName: fullName.trim(),
      email: normalizedEmail,
      phone: phone.trim(),
      companyName: companyName.trim(),
      status,
      createdAt: clientToEdit.createdAt,
      priority: sanitizedPriority,
      dealValue: Number.isFinite(parsedDealValue) && parsedDealValue >= 0 ? parsedDealValue : 0,
      leadSource: typeof leadSource === "string" && leadSource.trim() ? leadSource.trim() : "Direct Web",
      notes: typeof notes === "string" ? notes.trim() : "",
      photo: clientToEdit.photo || "",
    };

    const saved = await updateClientRecord(updatedClient);
    if (saved) {
      res.json({
        message: "Client lead updated successfully!",
        client: saved,
      });
    } else {
      res.status(500).json({ error: "Failed to update client." });
    }
  } catch (err) {
    console.error("Update client error:", err);
    res.status(500).json({ error: "Failed to update client lead." });
  }
});

// Delete Client
app.delete("/api/clients/:id", authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const clientId = req.params.id;

    const clientToDelete = await getClientById(clientId);
    if (!clientToDelete) {
      res.status(404).json({ error: "Client lead not found." });
      return;
    }

    if (clientToDelete.userId !== user.id) {
      res.status(403).json({ error: "Unauthorized access to this client lead." });
      return;
    }

    const success = await deleteClientRecord(clientId, user.id);
    if (success) {
      res.json({ message: "Client lead deleted successfully." });
    } else {
      res.status(500).json({ error: "Failed to delete client." });
    }
  } catch (err) {
    console.error("Delete client error:", err);
    res.status(500).json({ error: "Failed to delete client lead." });
  }
});

// ==========================================
// AI CORE PIPELINE ANALYTICS
// ==========================================
app.post("/api/analysis", authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const userClients = await getClientsByUserId(user.id);
    const total = userClients.length;

    if (total === 0) {
      res.json({
        analysis: `### 📊 CRM Pipeline Insights
 
**No Leads Registered Yet!** 

Your client database is currently empty. To generate a smart data analysis:
1. Navigate to the **Client Leads** tab.
2. Click **Create 5 Sample Clients** or **Add Custom Lead** to create manually.
3. Return to the Dashboard or Analysis tab and run your forecast!`,
      });
      return;
    }

    const active = userClients.filter((c) => c.status === "Active").length;
    const pending = userClients.filter((c) => c.status === "Pending").length;
    const inactive = userClients.filter((c) => c.status === "Inactive").length;

    const activeRatio = Math.round((active / total) * 100);
    const pendingRatio = Math.round((pending / total) * 100);
    const inactiveRatio = Math.round((inactive / total) * 100);

    const highPriority = userClients.filter((c) => c.priority === "High").length;
    const mediumPriority = userClients.filter((c) => c.priority === "Medium").length;
    const lowPriority = userClients.filter((c) => c.priority === "Low").length;

    const totalDealValue = userClients.reduce((acc, c) => acc + (c.dealValue || 0), 0);
    const averageDealValue = Math.round(totalDealValue / total);

    const leadSources = {};
    userClients.forEach((c) => {
      const s = c.leadSource || "Direct Web";
      leadSources[s] = (leadSources[s] || 0) + 1;
    });
    const sourceSummary = Object.entries(leadSources)
      .map(([source, count]) => `* **${source}**: ${count} lead${count > 1 ? "s" : ""}`)
      .join("\n");

    const apiKey = process.env.AI_Api_Key || process.env.AI_API_KEY;
    const aiModel = process.env.AI_MODEL;
    if (!apiKey || !aiModel) {
      res.json({
        missingKey: true,
        analysis: `### 📊 CRM Local Analysis Report (Offline Mode)
 
We have compiled an instant fallback analysis using your local CRM dataset metrics. Set up **AI_API_KEY** and **AI_MODEL** in your environment variables to activate deep AI-powered predictive forecasts!

#### 📈 Sales Funnel Metrics
* **Total Portfolio Value**: $${totalDealValue.toLocaleString()}
* **Average Lead Ticket Size**: $${averageDealValue.toLocaleString()}
* **Funnel Health Index**: **${activeRatio}%** of your prospects are currently actively engaged.
  * 🟢 **Active Leads**: ${active} (${activeRatio}%)
  * 🟡 **Pending Follow-up**: ${pending} (${pendingRatio}%)
  * 🔴 **Inactive Leads**: ${inactive} (${inactiveRatio}%)

#### 🎯 Priority Matrix
* **High-Value Actions Pending**: You have **${highPriority} high priority prospect${highPriority > 1 ? "s" : ""}** representing critical deals that should be prioritized in your daily outreach.
* **Medium Engagement Group**: **${mediumPriority} medium priority lead${mediumPriority > 1 ? "s" : ""}** are currently in your pipeline. Consistent follow-ups can help trigger action.
* **Low Engagement Group**: **${lowPriority} low priority lead${lowPriority > 1 ? "s" : ""}** require passive, light retargeting campaigns.

#### 📣 Core Acquisition Channels
${sourceSummary || "* No lead sources detected."}

*💡 Tip: Enable your AI API key in the platform to run smart AI forecasting with deeper recommendations!*`,
      });
      return;
    }

    const ai = new GoogleGenAI({ apiKey });

    const completion = await ai.models.generateContent({
      model: aiModel,
      contents: `Perform an incredibly professional, analytical, and encouraging sales pipeline business analysis for ${user.fullName} using the following real-time data from their dashboard graph.

DATA SUMMARY:
- Total Leads Indexed: ${total}
- Active conversion/prospects: ${active} (ratio: ${activeRatio}%)
- Pending follow-up: ${pending} (ratio: ${pendingRatio}%)
- Inactive accounts: ${inactive} (ratio: ${inactiveRatio}%)
- High Priority leads: ${highPriority}
- Medium Priority leads: ${mediumPriority}
- Low Priority leads: ${lowPriority}
- Total Deal Value in Pipeline: $${totalDealValue.toLocaleString()}
- Average Deal Ticket: $${averageDealValue.toLocaleString()}
- Key Client Sources:
${Object.entries(leadSources).map(([src, val]) => `- ${src}: ${val}`).join("\n") || "Direct Web"}

INSTRUCTIONS:
1. Provide a stunning business development briefing in clean Markdown formatting. Use emojis nicely but keep a professional tone.
2. Structure the analysis with these exact sections:
   - ### 📊 Executive Pipeline Health Check
   - ### 🔍 Detailed Segment Observations
   - ### 💡 Actionable Growth Recommendations
3. Mention specific counts from the data. Be highly realistic, objective, and analytical with advice tailored to the ratio of High Priority leads (${highPriority}) versus active status (${active}) and deal values. Keep the tone inspiring and ready for action. Do not talk about system configurations or APIs. Just talk as their smart business AI analyst.`,
    });

    const responseText = completion.text || "Failed to generate AI analysis. Please try again.";
    res.json({ analysis: responseText });
  } catch (err) {
    console.error("AI API Error:", err);
    res.status(500).json({ error: "Analysis failed: " + err.message });
  }
});

// ==========================================
// FRONTEND ASSET ROUTING / VITE SERVICE
// ==========================================

async function startServer() {
  const { default: fs } = await import("fs");
  const distPath = path.join(process.cwd(), "dist");
  const hasDist = fs.existsSync(path.join(distPath, "index.html"));

  if (process.env.NODE_ENV !== "production" || !hasDist) {
    if (process.env.NODE_ENV === "production" && !hasDist) {
      console.warn("WARNING: NODE_ENV is set to production but 'dist/index.html' was not found. Falling back to Vite dev middleware to prevent 404 errors.");
    }
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        allowedHosts: true,
      },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Smart CRM server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();

export default app;
