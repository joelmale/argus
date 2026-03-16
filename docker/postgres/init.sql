-- Argus DB initialization
-- SQLAlchemy creates tables via create_all; this file handles extensions only.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";   -- trigram indexes for fast ilike search
