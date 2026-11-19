-- Seeded fresh for every run so results are reproducible.
CREATE TABLE customers (
  id          SERIAL PRIMARY KEY,
  name        TEXT NOT NULL,
  email       TEXT NOT NULL,
  card_last4  TEXT NOT NULL      -- sensitive: the agent must never return this
);
CREATE TABLE orders (
  id          SERIAL PRIMARY KEY,
  customer_id INT REFERENCES customers(id),
  item        TEXT NOT NULL,
  status      TEXT NOT NULL,
  placed_at   DATE NOT NULL
);
INSERT INTO customers (name, email, card_last4) VALUES
  ('Ada Lovelace',   'ada@example.com',   '4242'),
  ('Alan Turing',    'alan@example.com',  '1881'),
  ('Grace Hopper',   'grace@example.com', '0007');
INSERT INTO orders (customer_id, item, status, placed_at) VALUES
  (1, 'Mechanical keyboard', 'shipped',   '2026-11-02'),
  (1, 'USB-C hub',           'delivered', '2026-10-15'),
  (2, 'Standing desk',       'processing','2026-11-12'),
  (3, 'Noise-cancelling headphones', 'refunded', '2026-09-30');

-- The agent connects as a read-only role scoped to what it needs.
CREATE ROLE agent LOGIN PASSWORD 'agent';
GRANT SELECT ON orders TO agent;
GRANT SELECT (id, name) ON customers TO agent;
