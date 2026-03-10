-- MySQL migration: content tables for website news/events
-- Target: MySQL 8+

CREATE TABLE IF NOT EXISTS news_updates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    summary TEXT NULL,
    image_url VARCHAR(600) NULL,
    link VARCHAR(500) NULL,
    category VARCHAR(120) NULL,
    status ENUM('draft', 'published', 'archived') NOT NULL DEFAULT 'published',
    published_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_news_status (status),
    INDEX idx_news_published (published_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS campus_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    summary TEXT NULL,
    event_date DATETIME NULL,
    location VARCHAR(255) NULL,
    link VARCHAR(500) NULL,
    status ENUM('draft', 'published', 'archived') NOT NULL DEFAULT 'published',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_events_status (status),
    INDEX idx_events_date (event_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO news_updates (title, summary, image_url, link, category, status, published_at)
SELECT * FROM (
    SELECT
        'Revised Academic Activities for 2025/2026 Second Semester',
        'Updated workshop rotation, practical assessment windows, and semester milestones are now active across all schools.',
        'https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?auto=format&fit=crop&w=1200&q=80',
        'contact.html',
        'Academic Calendar',
        'published',
        '2026-02-23 09:00:00'
) AS seed
WHERE NOT EXISTS (SELECT 1 FROM news_updates LIMIT 1);

INSERT INTO campus_events (title, summary, event_date, location, link, status)
SELECT * FROM (
    SELECT
        'Skills Showcase and Open Lab Day',
        'Prospective applicants can visit workshops and engage live with instructors and student projects.',
        '2026-03-12 09:00:00',
        'Main Campus Practical Studios',
        'contact.html',
        'published'
) AS seed
WHERE NOT EXISTS (SELECT 1 FROM campus_events LIMIT 1);
