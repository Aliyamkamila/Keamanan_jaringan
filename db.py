import sqlite3

conn = sqlite3.connect("order.db")  # <- nama database sesuai yang kamu pakai
c = conn.cursor()

c.execute("DROP TABLE IF EXISTS orders")

c.execute("""
CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enc_nama TEXT,
    enc_alamat TEXT,
    enc_produk TEXT,
    enc_jumlah TEXT,
    rsa_key TEXT,
    metode TEXT
)
""")

conn.commit()
conn.close()


