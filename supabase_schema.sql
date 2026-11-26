-- Smart CRM - Supabase (PostgreSQL) Schema
-- Run this SQL in your Supabase Dashboard -> SQL Editor

-- 1. Users Table
CREATE TABLE IF NOT EXISTS public.users (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Clients Table
CREATE TABLE IF NOT EXISTS public.clients (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT NOT NULL,
  company_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Active', 'Pending', 'Inactive')),
  priority TEXT NOT NULL DEFAULT 'Medium' CHECK (priority IN ('High', 'Medium', 'Low')),
  deal_value NUMERIC NOT NULL DEFAULT 0,
  lead_source TEXT NOT NULL DEFAULT 'Direct Web',
  notes TEXT NOT NULL DEFAULT '',
  photo TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Ensure columns exist if an older clients table was created previously
ALTER TABLE public.clients ADD COLUMN IF NOT EXISTS priority TEXT NOT NULL DEFAULT 'Medium';
ALTER TABLE public.clients ADD COLUMN IF NOT EXISTS deal_value NUMERIC NOT NULL DEFAULT 0;
ALTER TABLE public.clients ADD COLUMN IF NOT EXISTS lead_source TEXT NOT NULL DEFAULT 'Direct Web';
ALTER TABLE public.clients ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT '';
ALTER TABLE public.clients ADD COLUMN IF NOT EXISTS photo TEXT NOT NULL DEFAULT '';

-- 3. Sessions Table
CREATE TABLE IF NOT EXISTS public.sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users(email);
CREATE INDEX IF NOT EXISTS idx_clients_user_id ON public.clients(user_id);
CREATE INDEX IF NOT EXISTS idx_clients_status ON public.clients(status);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON public.sessions(user_id);

-- Enable Row Level Security (RLS)
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sessions ENABLE ROW LEVEL SECURITY;

-- Ensure service_role has full access to public tables even if auto-grant was unchecked
GRANT USAGE ON SCHEMA public TO service_role;
GRANT ALL ON TABLE public.users, public.clients, public.sessions TO service_role;

-- Refresh PostgREST schema cache
NOTIFY pgrst, 'reload schema';
