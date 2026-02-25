-- CREATE TABLE admin (
--     admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
--     name TEXT,
--     email TEXT UNIQUE,
--     password TEXT,
--     profile_image TEXT
-- );

CREATE TABLE admin (
    admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    profile_image TEXT,
    is_online INTEGER DEFAULT 0
);


CREATE TABLE order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    product_name TEXT,
    quantity INTEGER,
    price REAL
);

CREATE TABLE orders (
    order_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    razorpay_order_id TEXT,
    razorpay_payment_id TEXT,
    amount REAL,
    payment_status TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);


-- CREATE TABLE products (
--     product_id INTEGER PRIMARY KEY AUTOINCREMENT,
--     name TEXT,
--     description TEXT,
--     category TEXT,
--     price REAL,
--     image TEXT
-- );

CREATE TABLE products (
    product_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    category TEXT,
    price REAL,
    image TEXT,
    admin_id INTEGER
);

CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    profile_image TEXT
);
