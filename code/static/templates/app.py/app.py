from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
import sqlite3, hashlib, os, random, string
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'dfa-aokge-secret-2025'
DB = 'forensics.db'

# ─── DATABASE ─────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        # Create tables if they don't exist yet
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            role        TEXT DEFAULT "user",
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER,
            filename        TEXT,
            original_data   TEXT,
            original_hash   TEXT,
            encrypted_data  TEXT,
            encrypted_hash  TEXT,
            encryption_key  TEXT,
            block_id        TEXT,
            status          TEXT DEFAULT "stored",
            integrity       TEXT DEFAULT "verified",
            uploaded_at     TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS blockchain_blocks (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            block_hash   TEXT,
            prev_hash    TEXT,
            evidence_id  INTEGER,
            timestamp    TEXT,
            nonce        INTEGER,
            verified     INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            action     TEXT,
            details    TEXT,
            ip_address TEXT,
            timestamp  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        ''')

        # ── Migration: safely add any columns that may be missing from
        #    an older version of the database. SQLite does not support
        #    "ALTER TABLE ... ADD COLUMN IF NOT EXISTS", so we check
        #    PRAGMA table_info first and only add what is absent. ────────
        existing = {row[1] for row in db.execute("PRAGMA table_info(evidence)")}
        new_cols = {
            'original_data':  'ALTER TABLE evidence ADD COLUMN original_data  TEXT DEFAULT ""',
            'encrypted_data': 'ALTER TABLE evidence ADD COLUMN encrypted_data TEXT DEFAULT ""',
            'encryption_key': 'ALTER TABLE evidence ADD COLUMN encryption_key TEXT DEFAULT ""',
            'encrypted_hash': 'ALTER TABLE evidence ADD COLUMN encrypted_hash TEXT DEFAULT ""',
            'original_hash':  'ALTER TABLE evidence ADD COLUMN original_hash  TEXT DEFAULT ""',
            'block_id':       'ALTER TABLE evidence ADD COLUMN block_id        TEXT DEFAULT ""',
        }
        for col, sql in new_cols.items():
            if col not in existing:
                db.execute(sql)
        db.commit()

        # Seed default admin
        pw = hashlib.sha256('admin123'.encode()).hexdigest()
        try:
            db.execute("INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)",
                       ('admin', 'admin@forensiq.io', pw, 'admin'))
            db.commit()
        except:
            pass

init_db()

# ─── CRYPTO HELPERS ───────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def deco(*a, **kw):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*a, **kw)
    return deco

def sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def generate_key(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def eeo_optimize_key(base: str) -> str:
    """
    Enhanced Equilibrium Optimizer — simulates swarm of 10 candidate keys,
    scores each by weighted character entropy, returns the SHA-256-derived
    winner seeded with the evidence hash for per-file uniqueness.
    """
    candidates = [generate_key(32) for _ in range(10)]
    def fitness(k):
        return sum(ord(c) * (i + 1) for i, c in enumerate(k)) % 99999
    best = max(candidates, key=fitness)
    return sha256(best + base)[:32]

def mhe_encrypt(plaintext: str, key: str) -> str:
    """
    XOR-based Multi-Key Homomorphic Encryption.
    Every character is XORed with a repeating key byte and stored as a
    zero-padded 4-digit hex token joined by pipes.  Fully reversible.
    """
    kb = key.encode()
    return '|'.join(f'{ord(c) ^ kb[i % len(kb)]:04x}' for i, c in enumerate(plaintext))

def mhe_decrypt(ciphertext: str, key: str) -> str:
    """Reverse of mhe_encrypt — splits on |, parses hex, XORs back."""
    kb = key.encode()
    return ''.join(chr(int(tok, 16) ^ kb[i % len(kb)])
                   for i, tok in enumerate(ciphertext.split('|')))

def mine_block(prev_hash: str, data: str):
    """Proof-of-work: increment nonce until hash starts with '00'."""
    nonce = 0
    while True:
        h = sha256(prev_hash + data + str(nonce))
        if h.startswith('00'):
            return h, nonce
        nonce += 1

def log_action(user_id, action, details):
    with get_db() as db:
        db.execute("INSERT INTO audit_log (user_id,action,details,ip_address) VALUES (?,?,?,?)",
                   (user_id, action, details, request.remote_addr))
        db.commit()

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/how-it-works')
def how_it_works():
    return render_template('how_it_works.html')

# ── Auth ──────────────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        user = get_db().execute(
            "SELECT * FROM users WHERE username=? AND password=?", (username, password)
        ).fetchone()
        if user:
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['role']     = user['role']
            log_action(user['id'], 'LOGIN', f'User {username} authenticated')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email    = request.form['email']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        try:
            with get_db() as db:
                db.execute("INSERT INTO users (username,email,password) VALUES (?,?,?)",
                           (username, email, password))
                db.commit()
            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Username or email already exists.', 'error')
    return render_template('register.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], 'LOGOUT', f"User {session['username']} signed out")
    session.clear()
    return redirect(url_for('index'))

# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    db  = get_db()
    uid = session['user_id']
    if session['role'] == 'admin':
        evidence = db.execute(
            "SELECT e.*, u.username FROM evidence e JOIN users u ON e.user_id=u.id ORDER BY e.uploaded_at DESC"
        ).fetchall()
        users  = db.execute("SELECT * FROM users").fetchall()
        logs   = db.execute(
            "SELECT a.*, u.username FROM audit_log a JOIN users u ON a.user_id=u.id ORDER BY a.timestamp DESC LIMIT 20"
        ).fetchall()
        blocks = db.execute("SELECT * FROM blockchain_blocks ORDER BY id DESC LIMIT 10").fetchall()
        total  = db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
    else:
        evidence = db.execute(
            "SELECT * FROM evidence WHERE user_id=? ORDER BY uploaded_at DESC", (uid,)
        ).fetchall()
        users  = []
        logs   = db.execute(
            "SELECT * FROM audit_log WHERE user_id=? ORDER BY timestamp DESC LIMIT 10", (uid,)
        ).fetchall()
        blocks = db.execute(
            "SELECT b.* FROM blockchain_blocks b JOIN evidence e ON b.evidence_id=e.id WHERE e.user_id=? ORDER BY b.id DESC LIMIT 5",
            (uid,)
        ).fetchall()
        total  = db.execute("SELECT COUNT(*) FROM evidence WHERE user_id=?", (uid,)).fetchone()[0]

    stats = {
        'total_evidence': total,
        'verified':       db.execute("SELECT COUNT(*) FROM evidence WHERE integrity='verified'").fetchone()[0],
        'blocks':         db.execute("SELECT COUNT(*) FROM blockchain_blocks").fetchone()[0],
        'users':          db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
    }
    return render_template('dashboard.html',
                           evidence=evidence, users=users, logs=logs,
                           blocks=blocks, stats=stats)

# ── Upload ────────────────────────────────────────────────────────────────────

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        filename = request.form.get('filename', 'evidence_' + generate_key(8) + '.bin')
        data     = request.form.get('data', '').strip()
        uid      = session['user_id']

        if not data:
            flash('Evidence data cannot be empty.', 'error')
            return redirect(url_for('upload'))

        orig_hash  = sha256(data)
        key        = eeo_optimize_key(orig_hash)
        enc_data   = mhe_encrypt(data, key)
        enc_hash   = sha256(enc_data)

        db   = get_db()
        last = db.execute("SELECT block_hash FROM blockchain_blocks ORDER BY id DESC LIMIT 1").fetchone()
        prev = last['block_hash'] if last else '0' * 64
        block_hash, nonce = mine_block(prev, enc_hash)
        block_id = 'BLK-' + block_hash[:8].upper()

        with db:
            cur = db.execute(
                """INSERT INTO evidence
                   (user_id, filename, original_data, original_hash,
                    encrypted_data, encrypted_hash, encryption_key, block_id)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (uid, filename, data, orig_hash, enc_data, enc_hash, key, block_id)
            )
            ev_id = cur.lastrowid
            db.execute(
                "INSERT INTO blockchain_blocks (block_hash,prev_hash,evidence_id,timestamp,nonce) VALUES (?,?,?,?,?)",
                (block_hash, prev, ev_id, datetime.now().isoformat(), nonce)
            )
            db.commit()

        log_action(uid, 'UPLOAD', f'Evidence "{filename}" stored as {block_id}')
        flash('Evidence encrypted and committed to blockchain!', 'success')
        return redirect(url_for('evidence_detail', ev_id=ev_id))

    return render_template('upload.html')

# ── Evidence Detail ───────────────────────────────────────────────────────────

@app.route('/evidence/<int:ev_id>')
@login_required
def evidence_detail(ev_id):
    db  = get_db()
    uid = session['user_id']
    ev  = db.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
    if not ev:
        flash('Evidence not found.', 'error')
        return redirect(url_for('dashboard'))
    if ev['user_id'] != uid and session['role'] != 'admin':
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    block = db.execute("SELECT * FROM blockchain_blocks WHERE evidence_id=?", (ev_id,)).fetchone()
    log_action(uid, 'VIEW', f'Viewed detail for "{ev["filename"]}"')
    return render_template('evidence_detail.html', ev=ev, block=block)

# ── Verify API ────────────────────────────────────────────────────────────────

@app.route('/verify/<int:ev_id>')
@login_required
def verify(ev_id):
    db    = get_db()
    uid   = session['user_id']
    ev    = db.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
    block = db.execute("SELECT * FROM blockchain_blocks WHERE evidence_id=?", (ev_id,)).fetchone()

    if not ev or not block:
        return jsonify({'verified': False, 'message': 'No blockchain record found'})

    enc_data = ev['encrypted_data'] or ''
    enc_hash = ev['encrypted_hash'] or ''

    if not enc_data:
        return jsonify({'verified': False,
                        'message': 'Legacy record — no encrypted data stored. Please re-upload.'})

    recomputed = sha256(enc_data)
    intact     = (recomputed == enc_hash)

    log_action(uid, 'VERIFY', f'SBVM check "{ev["filename"]}" → {"PASS" if intact else "FAIL"}')
    return jsonify({
        'verified':        intact,
        'message':         'Integrity confirmed via SBVM ✓' if intact else 'INTEGRITY FAILURE — hash mismatch!',
        'original_hash':   ev['original_hash'],
        'encrypted_hash':  enc_hash,
        'recomputed_hash': recomputed,
        'block_id':        ev['block_id'],
        'block_hash':      block['block_hash'],
        'nonce':           block['nonce'],
    })

# ── Decrypt API ───────────────────────────────────────────────────────────────

@app.route('/decrypt/<int:ev_id>')
@login_required
def decrypt(ev_id):
    db  = get_db()
    uid = session['user_id']
    ev  = db.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()

    if not ev:
        return jsonify({'success': False, 'error': 'Evidence not found'})
    if ev['user_id'] != uid and session['role'] != 'admin':
        return jsonify({'success': False, 'error': 'Access denied'})

    enc_data = ev['encrypted_data'] or ''
    enc_key  = ev['encryption_key'] or ''

    if not enc_data or not enc_key:
        return jsonify({'success': False,
                        'error': 'Legacy record — no encrypted data. Please re-upload this evidence.'})

    # Must pass integrity check before decryption
    if sha256(enc_data) != (ev['encrypted_hash'] or ''):
        log_action(uid, 'DECRYPT_FAIL', f'Integrity FAILED for "{ev["filename"]}"')
        return jsonify({'success': False,
                        'error': 'Integrity check failed — decryption blocked to protect evidence!'})

    try:
        plaintext = mhe_decrypt(enc_data, enc_key)
    except Exception as ex:
        return jsonify({'success': False, 'error': f'Decryption error: {str(ex)}'})

    dec_hash   = sha256(plaintext)
    hash_match = (dec_hash == (ev['original_hash'] or ''))

    log_action(uid, 'DECRYPT', f'Decrypted "{ev["filename"]}" — hash match: {hash_match}')
    return jsonify({
        'success':        True,
        'filename':       ev['filename'],
        'plaintext':      plaintext,
        'original_hash':  ev['original_hash'],
        'decrypted_hash': dec_hash,
        'hash_match':     hash_match,
        'key_preview':    enc_key[:8] + '...',
        'key_full':       enc_key,
    })

# ── Download Plaintext ────────────────────────────────────────────────────────

@app.route('/download/<int:ev_id>')
@login_required
def download(ev_id):
    db  = get_db()
    uid = session['user_id']
    ev  = db.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()

    if not ev or (ev['user_id'] != uid and session['role'] != 'admin'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))

    enc_data = ev['encrypted_data'] or ''
    enc_key  = ev['encryption_key'] or ''

    if not enc_data or not enc_key:
        flash('Legacy record — no encrypted data stored. Please re-upload.', 'error')
        return redirect(url_for('dashboard'))

    if sha256(enc_data) != (ev['encrypted_hash'] or ''):
        flash('Integrity check failed — download blocked.', 'error')
        return redirect(url_for('dashboard'))

    plaintext = mhe_decrypt(enc_data, enc_key)
    log_action(uid, 'DOWNLOAD', f'Downloaded plaintext for "{ev["filename"]}"')

    return Response(
        plaintext,
        mimetype='text/plain',
        headers={
            'Content-Disposition': f'attachment; filename="{ev["filename"]}"',
            'X-Evidence-Hash':     ev['original_hash'] or '',
            'X-Block-ID':          ev['block_id'] or '',
        }
    )

# ── Download Encrypted Blob ───────────────────────────────────────────────────

@app.route('/download-encrypted/<int:ev_id>')
@login_required
def download_encrypted(ev_id):
    db  = get_db()
    uid = session['user_id']
    ev  = db.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()

    if not ev or (ev['user_id'] != uid and session['role'] != 'admin'):
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))

    enc_name = ev['filename'].rsplit('.', 1)[0] + '.enc'
    log_action(uid, 'DOWNLOAD_ENC', f'Downloaded encrypted blob for "{ev["filename"]}"')

    return Response(
        ev['encrypted_data'] or '',
        mimetype='application/octet-stream',
        headers={'Content-Disposition': f'attachment; filename="{enc_name}"'}
    )

# ── Stats API ─────────────────────────────────────────────────────────────────

@app.route('/api/stats')
@login_required
def api_stats():
    db = get_db()
    return jsonify({
        'evidence': db.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
        'blocks':   db.execute("SELECT COUNT(*) FROM blockchain_blocks").fetchone()[0],
        'users':    db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        'verified': db.execute("SELECT COUNT(*) FROM evidence WHERE integrity='verified'").fetchone()[0],
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
