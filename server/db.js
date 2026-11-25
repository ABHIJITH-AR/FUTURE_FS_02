import fs from "fs";
import path from "path";
import crypto from "crypto";
import { supabase, isSupabaseConfigured } from "./supabase.js";

// Detect if running on production serverless/ephemeral environments where root dir may be read-only
const IS_EPHEMERAL = process.env.VERCEL || process.env.NOW_BUILDER || !process.env.AIS_DEV;
let DB_FILE = path.join(process.cwd(), "data.json");
if (IS_EPHEMERAL) {
  DB_FILE = path.join("/tmp", "data.json");
}

export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `scrypt:${salt}:${derived}`;
}

export function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== "string") return false;

  if (storedHash.startsWith("scrypt:")) {
    const parts = storedHash.split(":");
    if (parts.length !== 3) return false;
    const [, salt, originalHex] = parts;
    const derivedBuf = crypto.scryptSync(password, salt, 64);
    const originalBuf = Buffer.from(originalHex, "hex");
    if (derivedBuf.length !== originalBuf.length) return false;
    return crypto.timingSafeEqual(derivedBuf, originalBuf);
  }

  // Legacy SHA-256 fallback for previously stored local records
  const legacyHex = crypto.createHash("sha256").update(password).digest("hex");
  const legacyBuf = Buffer.from(legacyHex, "hex");
  const storedBuf = Buffer.from(storedHash, "hex");
  if (legacyBuf.length !== storedBuf.length) return false;
  return crypto.timingSafeEqual(legacyBuf, storedBuf);
}

// ==========================================
// LOCAL JSON FALLBACK STORE (when Supabase env vars are not set)
// ==========================================

function initializeLocalDatabase() {
  if (fs.existsSync(DB_FILE)) {
    try {
      const data = fs.readFileSync(DB_FILE, "utf-8");
      const parsed = JSON.parse(data);
      if (parsed.users && parsed.clients && parsed.sessions) {
        return parsed;
      }
    } catch (e) {
      console.error("Failed to parse local database, creating a fresh one...", e);
    }
  }

  const rootDbFile = path.join(process.cwd(), "data.json");
  if (IS_EPHEMERAL && fs.existsSync(rootDbFile)) {
    try {
      const data = fs.readFileSync(rootDbFile, "utf-8");
      const parsed = JSON.parse(data);
      if (parsed.users && parsed.clients && parsed.sessions) {
        try {
          fs.writeFileSync(DB_FILE, data, "utf-8");
        } catch (errWrite) {
          console.error("Failed to write copy to writable DB_FILE:", errWrite);
        }
        return parsed;
      }
    } catch (e) {
      console.error("Failed to read root database:", e);
    }
  }

  const defaultSchema = {
    users: [],
    clients: [],
    sessions: [],
  };

  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(defaultSchema, null, 2), "utf-8");
  } catch (err) {
    console.error("Failed to write default local DB:", err);
  }
  return defaultSchema;
}

let dbCache = isSupabaseConfigured() ? null : initializeLocalDatabase();

function getLocalCache() {
  if (!dbCache) {
    dbCache = initializeLocalDatabase();
  }
  return dbCache;
}

function saveLocalDatabase() {
  if (!dbCache) return;
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(dbCache, null, 2), "utf-8");
  } catch (err) {
    console.warn("Warning: Local database persistence failed.", err);
  }
}

// ==========================================
// SUPABASE <-> APP DATA MAPPERS
// ==========================================

function mapUserFromDb(row) {
  if (!row) return null;
  return {
    id: row.id,
    fullName: row.full_name,
    email: row.email,
    passwordHash: row.password_hash,
    createdAt: row.created_at,
  };
}

function mapClientFromDb(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    fullName: row.full_name,
    email: row.email,
    phone: row.phone,
    companyName: row.company_name,
    status: row.status,
    priority: row.priority || "Medium",
    dealValue: Number(row.deal_value) || 0,
    leadSource: row.lead_source || "Direct Web",
    notes: row.notes || "",
    photo: row.photo || "",
    createdAt: row.created_at,
  };
}

function mapClientToDb(client) {
  return {
    id: client.id,
    user_id: client.userId,
    full_name: client.fullName,
    email: client.email,
    phone: client.phone,
    company_name: client.companyName,
    status: client.status,
    priority: client.priority || "Medium",
    deal_value: Number(client.dealValue) || 0,
    lead_source: client.leadSource || "Direct Web",
    notes: client.notes || "",
    photo: client.photo || "",
    created_at: client.createdAt || new Date().toISOString(),
  };
}

// ==========================================
// USERS DATA ACCESS
// ==========================================

export async function findUserById(id) {
  if (supabase) {
    const { data, error } = await supabase
      .from("users")
      .select("id, full_name, email, password_hash, created_at")
      .eq("id", id)
      .maybeSingle();

    if (error) {
      console.error("Supabase findUserById error:", error);
      throw new Error("Database query failed.", { cause: error });
    }
    return mapUserFromDb(data);
  }

  return getLocalCache().users.find((u) => u.id === id) || null;
}

export async function findUserByEmail(email) {
  const normalized = email.trim().toLowerCase();

  if (supabase) {
    const { data, error } = await supabase
      .from("users")
      .select("id, full_name, email, password_hash, created_at")
      .eq("email", normalized)
      .maybeSingle();

    if (error) {
      console.error("Supabase findUserByEmail error:", error);
      throw new Error("Database query failed.", { cause: error });
    }
    return mapUserFromDb(data);
  }

  return getLocalCache().users.find((u) => u.email.toLowerCase() === normalized) || null;
}

export async function createUser(user) {
  if (supabase) {
    const { data, error } = await supabase
      .from("users")
      .insert({
        id: user.id,
        full_name: user.fullName,
        email: user.email,
        password_hash: user.passwordHash,
        created_at: user.createdAt,
      })
      .select("id, full_name, email, password_hash, created_at")
      .single();

    if (error) {
      console.error("Supabase createUser error:", error);
      throw new Error("Failed to register user in database.", { cause: error });
    }
    return mapUserFromDb(data);
  }

  getLocalCache().users.push(user);
  saveLocalDatabase();
  return user;
}

export async function updateUser(id, fullName, email, passwordHash) {
  if (supabase) {
    const updates = {
      full_name: fullName,
      email,
    };
    if (passwordHash) {
      updates.password_hash = passwordHash;
    }

    const { data, error } = await supabase
      .from("users")
      .update(updates)
      .eq("id", id)
      .select("id");

    if (error) {
      console.error("Supabase updateUser error:", error);
      throw new Error("Failed to update user profile.", { cause: error });
    }
    return Array.isArray(data) && data.length > 0;
  }

  const users = getLocalCache().users;
  const index = users.findIndex((u) => u.id === id);
  if (index !== -1) {
    users[index].fullName = fullName;
    users[index].email = email;
    if (passwordHash) {
      users[index].passwordHash = passwordHash;
    }
    saveLocalDatabase();
    return true;
  }
  return false;
}

// ==========================================
// CLIENTS DATA ACCESS
// ==========================================

export async function getClientsByUserId(userId) {
  if (supabase) {
    const { data, error } = await supabase
      .from("clients")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Supabase getClientsByUserId error:", error);
      throw new Error("Failed to load client leads.", { cause: error });
    }
    return (data || []).map(mapClientFromDb);
  }

  return getLocalCache().clients.filter((c) => c.userId === userId);
}

export async function getClientById(id) {
  if (supabase) {
    const { data, error } = await supabase
      .from("clients")
      .select("*")
      .eq("id", id)
      .maybeSingle();

    if (error) {
      console.error("Supabase getClientById error:", error);
      throw new Error("Failed to load client lead.", { cause: error });
    }
    return mapClientFromDb(data);
  }

  return getLocalCache().clients.find((c) => c.id === id) || null;
}

export async function createClientRecord(client) {
  if (supabase) {
    const { data, error } = await supabase
      .from("clients")
      .insert(mapClientToDb(client))
      .select("*")
      .single();

    if (error) {
      console.error("Supabase createClientRecord error:", error);
      throw new Error("Failed to create client lead.", { cause: error });
    }
    return mapClientFromDb(data);
  }

  getLocalCache().clients.push(client);
  saveLocalDatabase();
  return client;
}

export async function createClientRecords(clients) {
  if (!Array.isArray(clients) || clients.length === 0) return [];

  if (supabase) {
    const { data, error } = await supabase
      .from("clients")
      .insert(clients.map(mapClientToDb))
      .select("*");

    if (error) {
      console.error("Supabase createClientRecords error:", error);
      throw new Error("Failed to create sample client leads.", { cause: error });
    }
    return (data || []).map(mapClientFromDb);
  }

  getLocalCache().clients.push(...clients);
  saveLocalDatabase();
  return clients;
}

export async function updateClientRecord(updated) {
  if (supabase) {
    const { data, error } = await supabase
      .from("clients")
      .update({
        full_name: updated.fullName,
        email: updated.email,
        phone: updated.phone,
        company_name: updated.companyName,
        status: updated.status,
        priority: updated.priority,
        deal_value: Number(updated.dealValue) || 0,
        lead_source: updated.leadSource,
        notes: updated.notes,
        photo: updated.photo,
      })
      .eq("id", updated.id)
      .eq("user_id", updated.userId)
      .select("*")
      .maybeSingle();

    if (error) {
      console.error("Supabase updateClientRecord error:", error);
      throw new Error("Failed to update client lead.", { cause: error });
    }
    return mapClientFromDb(data);
  }

  const clients = getLocalCache().clients;
  const index = clients.findIndex((c) => c.id === updated.id && c.userId === updated.userId);
  if (index !== -1) {
    clients[index] = updated;
    saveLocalDatabase();
    return updated;
  }
  return null;
}

export async function deleteClientRecord(id, userId) {
  if (supabase) {
    const { data, error } = await supabase
      .from("clients")
      .delete()
      .eq("id", id)
      .eq("user_id", userId)
      .select("id");

    if (error) {
      console.error("Supabase deleteClientRecord error:", error);
      throw new Error("Failed to delete client lead.", { cause: error });
    }
    return Array.isArray(data) && data.length > 0;
  }

  const cache = getLocalCache();
  const lengthBefore = cache.clients.length;
  cache.clients = cache.clients.filter((c) => !(c.id === id && c.userId === userId));
  if (cache.clients.length < lengthBefore) {
    saveLocalDatabase();
    return true;
  }
  return false;
}

// ==========================================
// SESSIONS DATA ACCESS
// ==========================================

export async function createSession(session) {
  if (supabase) {
    await supabase.from("sessions").delete().eq("user_id", session.userId);

    const { error } = await supabase.from("sessions").insert({
      token: session.token,
      user_id: session.userId,
      expires_at: session.expiresAt,
    });

    if (error) {
      console.error("Supabase createSession error:", error);
      throw new Error("Failed to create session.", { cause: error });
    }
    return;
  }

  const cache = getLocalCache();
  cache.sessions = cache.sessions.filter((s) => s.userId !== session.userId);
  cache.sessions.push(session);
  saveLocalDatabase();
}

export async function deleteSession(token) {
  if (supabase) {
    const { data, error } = await supabase
      .from("sessions")
      .delete()
      .eq("token", token)
      .select("token");

    if (error) {
      console.error("Supabase deleteSession error:", error);
      throw new Error("Failed to delete session.", { cause: error });
    }
    return Array.isArray(data) && data.length > 0;
  }

  const cache = getLocalCache();
  const lengthBefore = cache.sessions.length;
  cache.sessions = cache.sessions.filter((s) => s.token !== token);
  if (cache.sessions.length < lengthBefore) {
    saveLocalDatabase();
    return true;
  }
  return false;
}

export async function getSession(token) {
  if (supabase) {
    const { data, error } = await supabase
      .from("sessions")
      .select("token, user_id, expires_at")
      .eq("token", token)
      .maybeSingle();

    if (error) {
      console.error("Supabase getSession error:", error);
      throw new Error("Failed to verify session.", { cause: error });
    }
    if (!data) return undefined;

    if (new Date() > new Date(data.expires_at)) {
      await deleteSession(token);
      return undefined;
    }

    return {
      token: data.token,
      userId: data.user_id,
      expiresAt: data.expires_at,
    };
  }

  const session = getLocalCache().sessions.find((s) => s.token === token);
  if (!session) return undefined;

  if (new Date() > new Date(session.expiresAt)) {
    await deleteSession(token);
    return undefined;
  }
  return session;
}
