from flask import Flask, render_template, request, redirect, url_for, flash
from aes_encryption import encrypt_aes, decrypt_aes
from rsa_encryption import generate_keys, load_keys, decrypt_rsa
import sqlite3
import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

app = Flask(__name__)
app.secret_key = 'rahasia_super_secret'

# Cek dan load RSA Key saat server start
if not os.path.exists('private.pem') or not os.path.exists('public.pem'):
    generate_keys()

private_key_str, public_key_str = load_keys()

# Init database
def init_db():
    conn = sqlite3.connect('order.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        enc_nama TEXT,
        enc_alamat TEXT,
        enc_produk TEXT,
        enc_jumlah TEXT,
        enc_key TEXT,
        metode TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

def get_db_connection():
    conn = sqlite3.connect('order.db')
    conn.row_factory = sqlite3.Row
    return conn

# Simpan order ke DB
def save_order(enc, key, metode):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO orders (enc_nama, enc_alamat, enc_produk, enc_jumlah, enc_key, metode) VALUES (?, ?, ?, ?, ?, ?)",
        (enc['nama'], enc['alamat'], enc['produk'], enc['jumlah'], key, metode)
    )
    conn.commit()
    conn.close()

@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/order_form')
def order_form():
    return render_template('order_form.html')

@app.route('/order', methods=['POST'])
def order():
    nama = request.form['nama']
    alamat = request.form['alamat']
    produk = request.form['produk']
    jumlah = request.form['jumlah']
    password = request.form['kunci']
    metode = request.form.get('encryption_method')

    if not all([nama, alamat, produk, jumlah, password, metode]):
        flash("❗ Semua field harus diisi.")
        return redirect(url_for("order_form"))

    if metode == "aes":
        enc = {
            'nama': encrypt_aes(nama, password),
            'alamat': encrypt_aes(alamat, password),
            'produk': encrypt_aes(produk, password),
            'jumlah': encrypt_aes(jumlah, password)
        }
        key_output = password
        save_order(enc, key_output, metode)

    elif metode == "rsa":
        try:
            public_key = RSA.import_key(public_key_str.encode())
            cipher_rsa = PKCS1_OAEP.new(public_key)
            enc = {
                'nama': base64.b64encode(cipher_rsa.encrypt(nama.encode())).decode(),
                'alamat': base64.b64encode(cipher_rsa.encrypt(alamat.encode())).decode(),
                'produk': base64.b64encode(cipher_rsa.encrypt(produk.encode())).decode(),
                'jumlah': base64.b64encode(cipher_rsa.encrypt(jumlah.encode())).decode()
            }
            # Simpan referensi ke private key, bukan kontennya
            key_output = "SYSTEM_PRIVATE_KEY"
            save_order(enc, key_output, metode)

        except Exception as e:
            flash(f"❌ Gagal enkripsi RSA: {str(e)}")
            return redirect(url_for('order_form'))

    flash("✅ Order berhasil disimpan!")
    return redirect(url_for('riwayat'))

@app.route('/riwayat')
def riwayat():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, enc_nama, enc_alamat, enc_produk, enc_jumlah, enc_key, metode FROM orders")
    data = c.fetchall()
    conn.close()
    return render_template('riwayat.html', orders=data)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        id = request.form['id']
        metode = request.form['metode']
        key = request.form['key']

        conn = sqlite3.connect('order.db')
        c = conn.cursor()
        c.execute("SELECT enc_nama, enc_alamat, enc_produk, enc_jumlah, enc_key FROM orders WHERE id=?", (id,))
        row = c.fetchone()
        conn.close()

        if not row:
            flash("❗ Data tidak ditemukan.")
            return redirect(url_for('riwayat'))

        enc_nama, enc_alamat, enc_produk, enc_jumlah, enc_key = row

        if metode.lower() == "aes":
            decrypted_data = {
                'nama': decrypt_aes(enc_nama, key),
                'alamat': decrypt_aes(enc_alamat, key),
                'produk': decrypt_aes(enc_produk, key),
                'jumlah': decrypt_aes(enc_jumlah, key)
            }

        elif metode.lower() == "rsa":
            # Jika menggunakan kunci sistem
            if enc_key == "SYSTEM_PRIVATE_KEY":
                actual_key = private_key_str  # Gunakan kunci sistem yang sudah di-load
            else:
                actual_key = key  # Gunakan kunci yang dimasukkan user
                
            try:
                # Import private key dengan penanganan error yang lebih baik
                try:
                    private_key = RSA.import_key(actual_key.encode())
                except ValueError:
                    flash("❌ Format RSA key tidak valid")
                    return redirect(url_for('riwayat'))
                    
                cipher_rsa = PKCS1_OAEP.new(private_key)

                decrypted_data = {
                    'nama': cipher_rsa.decrypt(base64.b64decode(enc_nama)).decode(),
                    'alamat': cipher_rsa.decrypt(base64.b64decode(enc_alamat)).decode(),
                    'produk': cipher_rsa.decrypt(base64.b64decode(enc_produk)).decode(),
                    'jumlah': cipher_rsa.decrypt(base64.b64decode(enc_jumlah)).decode()
                }
            except Exception as e:
                flash(f"❌ Gagal dekripsi RSA: {str(e)}")
                return redirect(url_for('riwayat'))
        else:
            flash("❗ Metode enkripsi tidak dikenali.")
            return redirect(url_for('riwayat'))

        flash("✅ Data berhasil didekripsi.")
        return render_template('decrypted_result.html', data=decrypted_data)

    except Exception as e:
        flash(f"❌ Error: {str(e)}")
        return redirect(url_for('riwayat'))

@app.route('/delete/<int:id>', methods=['POST'])
def delete_order(id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM orders WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("🗑️ Order berhasil dihapus!")
    return redirect(url_for('riwayat'))

if __name__ == '__main__':
    app.run(debug=True)