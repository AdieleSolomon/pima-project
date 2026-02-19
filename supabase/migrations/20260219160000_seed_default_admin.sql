BEGIN;

INSERT INTO admins (first_name, last_name, email, password, role, created_at, updated_at)
VALUES (
  'PIMA',
  'Admin',
  'adminpima@gmail.com',
  '$2a$10$w2fHBqZT8ORkf3cIYQBhMeD54ItSHiaEtk11Z/GmToPg0Y5lOyYQi',
  'admin',
  NOW(),
  NOW()
)
ON CONFLICT (email)
DO UPDATE SET
  first_name = EXCLUDED.first_name,
  last_name = EXCLUDED.last_name,
  password = EXCLUDED.password,
  role = EXCLUDED.role,
  updated_at = NOW();

COMMIT;