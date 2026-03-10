-- PostgreSQL migration: content tables for website news/events
-- Target: PostgreSQL 14+

BEGIN;

CREATE TABLE IF NOT EXISTS news_updates (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    summary TEXT NULL,
    image_url VARCHAR(600) NULL,
    link VARCHAR(500) NULL,
    category VARCHAR(120) NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'published' CHECK (status IN ('draft', 'published', 'archived')),
    published_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS campus_events (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    summary TEXT NULL,
    event_date TIMESTAMP NULL,
    location VARCHAR(255) NULL,
    link VARCHAR(500) NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'published' CHECK (status IN ('draft', 'published', 'archived')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_news_status ON news_updates (status);
CREATE INDEX IF NOT EXISTS idx_news_published ON news_updates (published_at);
CREATE INDEX IF NOT EXISTS idx_events_status ON campus_events (status);
CREATE INDEX IF NOT EXISTS idx_events_date ON campus_events (event_date);

CREATE OR REPLACE FUNCTION set_content_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_news_updates_updated_at ON news_updates;
CREATE TRIGGER trg_news_updates_updated_at
BEFORE UPDATE ON news_updates
FOR EACH ROW
EXECUTE FUNCTION set_content_updated_at();

DROP TRIGGER IF EXISTS trg_campus_events_updated_at ON campus_events;
CREATE TRIGGER trg_campus_events_updated_at
BEFORE UPDATE ON campus_events
FOR EACH ROW
EXECUTE FUNCTION set_content_updated_at();

INSERT INTO news_updates (title, summary, image_url, link, category, status, published_at)
SELECT
    'Revised Academic Activities for 2025/2026 Second Semester',
    'Updated workshop rotation, practical assessment windows, and semester milestones are now active across all schools.',
    'https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?auto=format&fit=crop&w=1200&q=80',
    'contact.html',
    'Academic Calendar',
    'published',
    '2026-02-23 09:00:00'
WHERE NOT EXISTS (SELECT 1 FROM news_updates LIMIT 1);

INSERT INTO campus_events (title, summary, event_date, location, link, status)
SELECT
    'Skills Showcase and Open Lab Day',
    'Prospective applicants can visit workshops and engage live with instructors and student projects.',
    '2026-03-12 09:00:00',
    'Main Campus Practical Studios',
    'contact.html',
    'published'
WHERE NOT EXISTS (SELECT 1 FROM campus_events LIMIT 1);

COMMIT;
