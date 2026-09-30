-- Extensions required by CYBERTRACE.
-- pg_trgm powers fuzzy search across case titles, evidence filenames and entity values.
-- citext gives case-insensitive uniqueness for emails without lower() indexes everywhere.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS citext;
