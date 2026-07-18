// ================================================================
// server.js – الخادم المتكامل (مستخدم + إدارة)
// متوافق مع Railway و Aiven عبر متغيرات البيئة
// ================================================================

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ==================== دالة قراءة المتغيرات بأسماء متعددة ====================
const getEnvVar = (names) => {
    for (const name of names) {
        if (process.env[name]) return process.env[name];
    }
    return undefined;
};

// ==================== إعدادات الاتصال بقاعدة البيانات ====================
// استخراج المضيف أولاً لتجنب خطأ "Cannot access before initialization"
const host = getEnvVar(['MYSQL_HOST', 'DB_HOST']) || 'localhost';
const dbConfig = {
    host: host,
    user: getEnvVar(['MYSQL_USER', 'DB_USER']) || 'root',
    password: getEnvVar(['MYSQL_PASSWORD', 'DB_PASSWORD']) || '',
    database: getEnvVar(['MYSQL_DATABASE', 'DB_NAME']) || 'wifi_app_db',
    port: parseInt(getEnvVar(['MYSQL_PORT', 'DB_PORT']) || '3306', 10),
    ssl: (process.env.DB_SSL === 'true' || process.env.MYSQL_SSL === 'true' ||
          (host && (host.includes('aivencloud.com') || host.includes('railway.internal'))))
        ? { rejectUnauthorized: false }
        : false
};

console.log('🔌 محاولة الاتصال بقاعدة البيانات:');
console.log(`   المضيف: ${dbConfig.host}`);
console.log(`   المستخدم: ${dbConfig.user}`);
console.log(`   قاعدة البيانات: ${dbConfig.database}`);
console.log(`   المنفذ: ${dbConfig.port}`);
console.log(`   SSL: ${dbConfig.ssl ? 'مفعل' : 'غير مفعل'}`);

const db = mysql.createConnection(dbConfig);

db.connect((err) => {
    if (err) {
        console.error('❌ فشل الاتصال بقاعدة البيانات:', err);
        console.error('💡 تأكد من إضافة خدمة MySQL في Railway أو تعيين المتغيرات الصحيحة.');
        // لا نخرج من العملية حتى يستمر الخادم في التشغيل للاختبار
        // process.exit(1); // تم التعليق لمنع تعطل الحاوية
    } else {
        console.log('✅ تم الاتصال بقاعدة البيانات');
    }
});

const JWT_SECRET = process.env.JWT_SECRET || 'wifi_app_super_secret_key';

// ==================== دوال مساعدة ====================
function generateAccountNumber() {
    return Math.floor(1000000000 + Math.random() * 9000000000).toString();
}

function generateCardCode() {
    return `WIFI-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
}

// ==================== وسيط المصادقة ====================
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ status: false, message: 'غير مصرح به' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        db.query('SELECT id FROM admins WHERE id = ?', [decoded.id], (err, results) => {
            if (err || results.length === 0) {
                return res.status(403).json({ status: false, message: 'صلاحية غير كافية' });
            }
            req.adminId = decoded.id;
            next();
        });
    } catch (err) {
        return res.status(401).json({ status: false, message: 'توكن غير صالح' });
    }
};

// ================================================================
// 1. نقاط نهاية المستخدم
// ================================================================

// تسجيل حساب جديد
app.post('/api/register', async (req, res) => {
    const { name, phone, password } = req.body;
    if (!name || !phone || !password) return res.status(400).json({ status: false, message: 'جميع الحقول مطلوبة' });
    try {
        db.query('SELECT * FROM users WHERE phone = ?', [phone], async (err, results) => {
            if (err) return res.status(500).json({ status: false, message: 'خطأ في الخادم' });
            if (results.length > 0) return res.status(400).json({ status: false, message: 'رقم الهاتف مسجل بالفعل' });
            const hashedPassword = await bcrypt.hash(password, 10);
            let accountNumber, isUnique = false, attempts = 0;
            while (!isUnique && attempts < 10) {
                accountNumber = generateAccountNumber();
                const check = await new Promise((resolve, reject) => {
                    db.query('SELECT * FROM users WHERE account_number = ?', [accountNumber], (err, result) => {
                        if (err) reject(err);
                        else resolve(result);
                    });
                });
                if (check.length === 0) isUnique = true;
                attempts++;
            }
            if (!isUnique) return res.status(500).json({ status: false, message: 'فشل توليد رقم حساب فريد' });
            db.query('INSERT INTO users (name, phone, password, balance, account_number) VALUES (?, ?, ?, 0, ?)',
                [name, phone, hashedPassword, accountNumber],
                (err, result) => {
                    if (err) return res.status(500).json({ status: false, message: 'فشل في إنشاء الحساب' });
                    res.status(201).json({ status: true, message: 'تم إنشاء الحساب بنجاح', userId: result.insertId, accountNumber });
                });
        });
    } catch (error) {
        res.status(500).json({ status: false, message: 'خطأ أثناء التشفير' });
    }
});

// تسجيل الدخول
app.post('/api/login', (req, res) => {
    const { phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ status: false, message: 'جميع الحقول مطلوبة' });
    db.query('SELECT * FROM users WHERE phone = ?', [phone], async (err, results) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في الخادم' });
        if (results.length === 0) return res.status(401).json({ status: false, message: 'رقم الهاتف غير مسجل' });
        const user = results[0];
        try {
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return res.status(401).json({ status: false, message: 'كلمة السر غير صحيحة' });
            const token = jwt.sign({ id: user.id, phone: user.phone }, JWT_SECRET, { expiresIn: '7d' });
            res.json({ status: true, message: 'تم تسجيل الدخول بنجاح', token, user: { id: user.id, name: user.name, phone: user.phone, balance: user.balance || 0, accountNumber: user.account_number } });
        } catch (error) {
            res.status(500).json({ status: false, message: 'خطأ أثناء التحقق' });
        }
    });
});

// شراء كروت (نظام المخزون)
app.post('/api/purchase-card', (req, res) => {
    const { userId, category, quantity = 1, receiverPhone } = req.body;
    if (!userId || !category || quantity < 1) return res.status(400).json({ status: false, message: 'بيانات غير صالحة' });
    db.beginTransaction((err) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في بدء المعاملة' });
        db.query('SELECT * FROM categories WHERE name = ? OR id = ? FOR UPDATE', [category, category], (err, catResults) => {
            if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' }));
            if (catResults.length === 0) return db.rollback(() => res.status(404).json({ status: false, message: 'الفئة غير موجودة' }));
            const price = parseFloat(catResults[0].price) || 0;
            const totalCost = price * quantity;
            db.query('SELECT COUNT(*) as available_count FROM cards WHERE category = ? AND user_id IS NULL AND status = "available"', [category], (err, stockResult) => {
                if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'خطأ في التحقق من المخزون' }));
                const availableCount = stockResult[0]?.available_count || 0;
                if (availableCount < quantity) return db.rollback(() => res.status(400).json({ status: false, message: `لا يوجد كروت كافية. المتاح: ${availableCount}` }));
                db.query('SELECT balance FROM users WHERE id = ? FOR UPDATE', [userId], (err, userResults) => {
                    if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' }));
                    if (userResults.length === 0) return db.rollback(() => res.status(404).json({ status: false, message: 'المستخدم غير موجود' }));
                    const currentBalance = parseFloat(userResults[0].balance) || 0;
                    if (currentBalance < totalCost) return db.rollback(() => res.status(400).json({ status: false, message: 'الرصيد غير كافٍ' }));
                    const newBalance = currentBalance - totalCost;
                    db.query('UPDATE users SET balance = ? WHERE id = ?', [newBalance, userId], (err) => {
                        if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تحديث الرصيد' }));
                        db.query('UPDATE cards SET user_id = ?, sold_at = NOW(), status = "sold", receiver_phone = ? WHERE category = ? AND user_id IS NULL AND status = "available" LIMIT ?',
                            [userId, receiverPhone || null, category, quantity],
                            (err, result) => {
                                if (err) return db.rollback(() => { console.error('خطأ في حجز الكروت:', err); res.status(500).json({ status: false, message: 'فشل حجز الكروت' }); });
                                if (result.affectedRows < quantity) return db.rollback(() => res.status(400).json({ status: false, message: `تم حجز ${result.affectedRows} كرت فقط` }));
                                db.query('SELECT card_code FROM cards WHERE user_id = ? AND sold_at = NOW() AND status = "sold" ORDER BY id DESC LIMIT ?', [userId, quantity], (err, cardResults) => {
                                    if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'خطأ في جلب الكروت' }));
                                    const cardCodes = cardResults.map(row => row.card_code);
                                    const description = `شراء باقة ${category} (عدد ${quantity})` + (receiverPhone ? ` مرسلة إلى ${receiverPhone}` : '');
                                    db.query('INSERT INTO transactions (user_id, amount, type, description, created_at) VALUES (?, ?, ?, ?, NOW())', [userId, totalCost, 'purchase', description], (err) => {
                                        if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تسجيل المعاملة' }));
                                        db.commit((err) => {
                                            if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تأكيد المعاملة' }));
                                            res.status(200).json({ status: true, message: `تم شراء ${quantity} بطاقة/باقة بنجاح`, purchasedCards: cardCodes, newBalance, receiverPhone: receiverPhone || null });
                                        });
                                    });
                                });
                            });
                    });
                });
            });
        });
    });
});

// تحويل الرصيد
app.post('/api/transfer', (req, res) => {
    const { senderId, receiverAccount, amount, note } = req.body;
    if (!senderId || !receiverAccount || !amount || amount <= 0) return res.status(400).json({ status: false, message: 'بيانات غير صالحة' });
    db.beginTransaction((err) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في بدء المعاملة' });
        db.query('SELECT id, name, balance FROM users WHERE id = ? FOR UPDATE', [senderId], (err, senderResults) => {
            if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' }));
            if (senderResults.length === 0) return db.rollback(() => res.status(404).json({ status: false, message: 'المرسل غير موجود' }));
            const sender = senderResults[0];
            const senderBalance = parseFloat(sender.balance) || 0;
            if (senderBalance < amount) return db.rollback(() => res.status(400).json({ status: false, message: 'الرصيد غير كافٍ' }));
            db.query('SELECT id, name FROM users WHERE account_number = ? FOR UPDATE', [receiverAccount], (err, receiverResults) => {
                if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' }));
                if (receiverResults.length === 0) return db.rollback(() => res.status(404).json({ status: false, message: 'المستقبل غير موجود' }));
                const receiver = receiverResults[0];
                if (receiver.id === senderId) return db.rollback(() => res.status(400).json({ status: false, message: 'لا يمكن التحويل لنفس الحساب' }));
                db.query('UPDATE users SET balance = balance - ? WHERE id = ?', [amount, senderId], (err) => {
                    if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تحديث رصيد المرسل' }));
                    db.query('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, receiver.id], (err) => {
                        if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تحديث رصيد المستقبل' }));
                        db.query('INSERT INTO transactions (user_id, amount, type, description, created_at) VALUES (?, ?, ?, ?, NOW())', [senderId, -amount, 'transfer', `تحويل إلى ${receiver.name}`], (err) => {
                            if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تسجيل معاملة المرسل' }));
                            db.query('INSERT INTO transactions (user_id, amount, type, description, created_at) VALUES (?, ?, ?, ?, NOW())', [receiver.id, amount, 'transfer', `استلام تحويل من ${sender.name}`], (err) => {
                                if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تسجيل معاملة المستقبل' }));
                                db.commit((err) => {
                                    if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تأكيد المعاملة' }));
                                    res.status(200).json({ status: true, message: 'تم التحويل بنجاح', newBalance: senderBalance - amount });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});

// إرسال الكروت عبر واتساب (محاكاة)
app.post('/api/send-whatsapp', (req, res) => {
    const { cardCodes, phone } = req.body;
    if (!cardCodes || !Array.isArray(cardCodes) || cardCodes.length === 0 || !phone) return res.status(400).json({ status: false, message: 'البيانات ناقصة' });
    const promises = cardCodes.map(code => new Promise((resolve, reject) => {
        db.query('UPDATE cards SET receiver_phone = ? WHERE card_code = ?', [phone, code], (err) => { if (err) reject(err); else resolve(); });
    }));
    Promise.all(promises).then(() => res.status(200).json({ status: true, message: `تم إرسال ${cardCodes.length} كود إلى ${phone}` }))
        .catch(err => res.status(500).json({ status: false, message: 'فشل تحديث أرقام المستلمين' }));
});

// إرسال كود كرت محدد
app.post('/api/send-card', (req, res) => {
    const { cardCode, phoneNumber } = req.body;
    if (!cardCode || !phoneNumber) return res.status(400).json({ status: false, message: 'البيانات ناقصة' });
    db.query('SELECT * FROM cards WHERE card_code = ?', [cardCode], (err, results) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        if (results.length === 0) return res.status(404).json({ status: false, message: 'الكود غير موجود' });
        db.query('UPDATE cards SET receiver_phone = ? WHERE card_code = ?', [phoneNumber, cardCode], (err) => {
            if (err) return res.status(500).json({ status: false, message: 'فشل تحديث رقم المستلم' });
            res.status(200).json({ status: true, message: `تم إرسال الكود ${cardCode} إلى ${phoneNumber}` });
        });
    });
});

// جلب مشتريات المستخدم
app.get('/api/my-cards/:userId', (req, res) => {
    db.query('SELECT * FROM cards WHERE user_id = ? ORDER BY sold_at DESC', [req.params.userId], (err, results) => {
        if (err) return res.status(500).json([]);
        res.json(results);
    });
});

// جلب الفئات
app.get('/api/packages', (req, res) => {
    db.query('SELECT * FROM categories ORDER BY price ASC', (err, results) => {
        if (err) return res.status(500).json([]);
        res.json(results);
    });
});

// جلب بيانات المستخدم
app.get('/api/user/:userId', (req, res) => {
    db.query('SELECT id, name, phone, balance, account_number FROM users WHERE id = ?', [req.params.userId], (err, results) => {
        if (err) return res.status(500).json(null);
        if (results.length === 0) return res.status(404).json(null);
        res.json(results[0]);
    });
});

// جلب مستخدم بواسطة رقم الحساب
app.get('/api/user/account/:accountNumber', (req, res) => {
    db.query('SELECT id, name, phone, balance, account_number FROM users WHERE account_number = ?', [req.params.accountNumber], (err, results) => {
        if (err) return res.status(500).json(null);
        if (results.length === 0) return res.status(404).json(null);
        res.json(results[0]);
    });
});

// جلب معاملات المستخدم
app.get('/api/transactions/:userId', (req, res) => {
    db.query('SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC', [req.params.userId], (err, results) => {
        if (err) return res.status(500).json([]);
        res.json(results);
    });
});

// حذف كرت
app.delete('/api/cards/:cardId', (req, res) => {
    db.query('DELETE FROM cards WHERE id = ?', [req.params.cardId], (err, result) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        if (result.affectedRows === 0) return res.status(404).json({ status: false, message: 'الكرت غير موجود' });
        res.json({ status: true, message: 'تم حذف الكرت بنجاح' });
    });
});

// حذف جميع كروت المستخدم
app.delete('/api/cards/user/:userId', (req, res) => {
    db.query('DELETE FROM cards WHERE user_id = ?', [req.params.userId], (err, result) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        res.json({ status: true, message: `تم حذف ${result.affectedRows} كرت بنجاح`, deletedCount: result.affectedRows });
    });
});

// ================================================================
// 2. نقاط نهاية الإدارة
// ================================================================

// تسجيل دخول الإدارة
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ status: false, message: 'اسم المستخدم وكلمة المرور مطلوبة' });
    db.query('SELECT * FROM admins WHERE username = ?', [username], async (err, results) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في الخادم' });
        if (results.length === 0) return res.status(401).json({ status: false, message: 'اسم المستخدم غير صحيح' });
        const admin = results[0];
        try {
            const isMatch = await bcrypt.compare(password, admin.password);
            if (!isMatch) return res.status(401).json({ status: false, message: 'كلمة المرور غير صحيحة' });
            const token = jwt.sign({ id: admin.id, role: 'admin' }, JWT_SECRET, { expiresIn: '1d' });
            res.json({ status: true, message: 'تم تسجيل الدخول بنجاح', token });
        } catch (error) {
            res.status(500).json({ status: false, message: 'خطأ أثناء التحقق' });
        }
    });
});

// إحصائيات
app.get('/api/admin/stats', authenticateAdmin, (req, res) => {
    const queries = {
        totalUsers: 'SELECT COUNT(*) as count FROM users',
        totalCards: 'SELECT COUNT(*) as count FROM cards WHERE user_id IS NULL AND status = "available"',
        soldCards: 'SELECT COUNT(*) as count FROM cards WHERE user_id IS NOT NULL AND status = "sold"',
        totalRevenue: 'SELECT SUM(amount) as total FROM transactions WHERE type = "purchase"',
        todayTransactions: 'SELECT COUNT(*) as count FROM transactions WHERE DATE(created_at) = CURDATE()',
        monthTransactions: 'SELECT COUNT(*) as count FROM transactions WHERE MONTH(created_at) = MONTH(CURDATE()) AND YEAR(created_at) = YEAR(CURDATE())'
    };
    let results = {}, completed = 0, keys = Object.keys(queries);
    keys.forEach(key => {
        db.query(queries[key], (err, result) => {
            if (err) { console.error(err); results[key] = { count: 0, total: 0 }; } else { results[key] = result[0] || { count: 0, total: 0 }; }
            completed++;
            if (completed === keys.length) {
                res.json({ totalUsers: results.totalUsers?.count || 0, availableCards: results.totalCards?.count || 0, soldCards: results.soldCards?.count || 0, totalRevenue: results.totalRevenue?.total || 0, todayTransactions: results.todayTransactions?.count || 0, monthTransactions: results.monthTransactions?.count || 0 });
            }
        });
    });
});

// إدارة المستخدمين (مختصرة ولكن كاملة)
app.get('/api/admin/users', authenticateAdmin, (req, res) => {
    const { search } = req.query;
    let sql = 'SELECT id, name, phone, balance, account_number, status, created_at FROM users';
    const params = [];
    if (search) { sql += ' WHERE name LIKE ? OR phone LIKE ? OR account_number LIKE ?'; const s = `%${search}%`; params.push(s, s, s); }
    sql += ' ORDER BY id DESC';
    db.query(sql, params, (err, results) => { if (err) return res.status(500).json([]); res.json(results); });
});
app.get('/api/admin/users/:id', authenticateAdmin, (req, res) => {
    db.query('SELECT id, name, phone, balance, account_number, status FROM users WHERE id = ?', [req.params.id], (err, result) => { if (err) return res.status(500).json({ status: false, message: 'خطأ' }); if (result.length === 0) return res.status(404).json({ status: false, message: 'المستخدم غير موجود' }); res.json(result[0]); });
});
app.post('/api/admin/users', authenticateAdmin, async (req, res) => {
    const { name, phone, password, balance, status } = req.body;
    if (!name || !phone) return res.status(400).json({ status: false, message: 'الاسم والهاتف مطلوبان' });
    try {
        const hashed = password ? await bcrypt.hash(password, 10) : null;
        const accountNumber = generateAccountNumber();
        db.query('INSERT INTO users (name, phone, password, balance, account_number, status) VALUES (?, ?, ?, ?, ?, ?)', [name, phone, hashed, balance || 0, accountNumber, status || 'active'], (err, result) => { if (err) return res.status(500).json({ status: false, message: 'فشل إضافة المستخدم' }); res.json({ status: true, message: 'تمت إضافة المستخدم بنجاح', id: result.insertId }); });
    } catch (err) { res.status(500).json({ status: false, message: 'خطأ في الخادم' }); }
});
app.put('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
    const { name, phone, password, balance, status } = req.body;
    let sql = 'UPDATE users SET name = ?, phone = ?, balance = ?, status = ?';
    const params = [name, phone, balance || 0, status || 'active'];
    if (password) { const hashed = await bcrypt.hash(password, 10); sql += ', password = ?'; params.push(hashed); }
    sql += ' WHERE id = ?'; params.push(req.params.id);
    db.query(sql, params, (err) => { if (err) return res.status(500).json({ status: false, message: 'فشل تحديث المستخدم' }); res.json({ status: true, message: 'تم تحديث المستخدم بنجاح' }); });
});
app.put('/api/admin/users/:id/toggle-status', authenticateAdmin, (req, res) => {
    db.query('SELECT status FROM users WHERE id = ?', [req.params.id], (err, result) => {
        if (err || result.length === 0) return res.status(404).json({ status: false, message: 'المستخدم غير موجود' });
        const newStatus = result[0].status === 'suspended' ? 'active' : 'suspended';
        db.query('UPDATE users SET status = ? WHERE id = ?', [newStatus, req.params.id], (err) => { if (err) return res.status(500).json({ status: false, message: 'فشل تغيير الحالة' }); res.json({ status: true, message: `تم ${newStatus === 'active' ? 'تفعيل' : 'توقيف'} المستخدم` }); });
    });
});
app.post('/api/admin/users/:id/recharge', authenticateAdmin, (req, res) => {
    const { amount, note } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ status: false, message: 'المبلغ يجب أن يكون أكبر من صفر' });
    db.beginTransaction((err) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في بدء المعاملة' });
        db.query('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, req.params.id], (err, result) => {
            if (err || result.affectedRows === 0) return db.rollback(() => res.status(500).json({ status: false, message: 'فشل شحن الرصيد' }));
            db.query('INSERT INTO transactions (user_id, amount, type, description) VALUES (?, ?, "recharge", ?)', [req.params.id, amount, note || 'شحن رصيد من لوحة الإدارة'], (err) => {
                if (err) return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تسجيل المعاملة' }));
                db.commit(() => res.json({ status: true, message: `تم شحن ${amount} ر.ي بنجاح` }));
            });
        });
    });
});
app.delete('/api/admin/users/:id', authenticateAdmin, (req, res) => {
    db.query('DELETE FROM users WHERE id = ?', [req.params.id], (err, result) => { if (err) return res.status(500).json({ status: false, message: 'فشل حذف المستخدم' }); if (result.affectedRows === 0) return res.status(404).json({ status: false, message: 'المستخدم غير موجود' }); res.json({ status: true, message: 'تم حذف المستخدم بنجاح' }); });
});

// إدارة الكروت (مختصرة)
app.get('/api/admin/cards', authenticateAdmin, (req, res) => {
    const { search, category, status } = req.query;
    let sql = 'SELECT * FROM cards WHERE 1=1'; const params = [];
    if (search) { sql += ' AND (card_code LIKE ? OR category LIKE ?)'; const s = `%${search}%`; params.push(s, s); }
    if (category) { sql += ' AND category = ?'; params.push(category); }
    if (status) { sql += ' AND status = ?'; params.push(status); }
    sql += ' ORDER BY id DESC';
    db.query(sql, params, (err, results) => { if (err) return res.status(500).json([]); res.json(results); });
});
app.get('/api/admin/cards/:id', authenticateAdmin, (req, res) => {
    db.query('SELECT * FROM cards WHERE id = ?', [req.params.id], (err, result) => { if (err) return res.status(500).json({ status: false, message: 'خطأ' }); if (result.length === 0) return res.status(404).json({ status: false, message: 'الكرت غير موجود' }); res.json(result[0]); });
});
app.post('/api/admin/cards', authenticateAdmin, (req, res) => {
    const { category, status, receiver_phone } = req.body;
    if (!category) return res.status(400).json({ status: false, message: 'الفئة مطلوبة' });
    const cardCode = generateCardCode();
    db.query('INSERT INTO cards (category, card_code, status, receiver_phone) VALUES (?, ?, ?, ?)', [category, cardCode, status || 'available', receiver_phone || null], (err, result) => { if (err) return res.status(500).json({ status: false, message: 'فشل إضافة الكرت' }); res.json({ status: true, message: 'تم إضافة الكرت بنجاح', id: result.insertId }); });
});
app.post('/api/admin/cards/bulk', authenticateAdmin, (req, res) => {
    const { category, count } = req.body;
    if (!category || !count || count < 1) return res.status(400).json({ status: false, message: 'الفئة والعدد مطلوبان' });
    const numCount = parseInt(count);
    if (isNaN(numCount) || numCount < 1) return res.status(400).json({ status: false, message: 'العدد يجب أن يكون رقماً صحيحاً' });
    const values = [];
    for (let i = 0; i < numCount; i++) { values.push([category, `WIFI-${Date.now()}-${Math.floor(Math.random() * 100000)}-${i}`, 'available', new Date()]); }
    db.query('INSERT INTO cards (category, card_code, status, created_at) VALUES ?', [values], (err, result) => { if (err) return res.status(500).json({ status: false, message: 'فشل إضافة الدفعة' }); res.json({ status: true, message: `تمت إضافة ${numCount} كرت بنجاح` }); });
});
app.post('/api/admin/cards/bulk-import', authenticateAdmin, (req, res) => {
    const { category, cardCodes } = req.body;
    if (!category || !cardCodes || !Array.isArray(cardCodes) || cardCodes.length === 0) return res.status(400).json({ status: false, message: 'الفئة وقائمة الأكواد مطلوبة' });
    const cleanCodes = cardCodes.map(code => code.trim()).filter(code => code.length > 0);
    if (cleanCodes.length === 0) return res.status(400).json({ status: false, message: 'لا توجد أكواد صالحة' });
    const values = cleanCodes.map(code => [category, code, 'available', new Date()]);
    db.query('INSERT INTO cards (category, card_code, status, created_at) VALUES ?', [values], (err, result) => { if (err) return res.status(500).json({ status: false, message: 'فشل إضافة الكروت' }); res.json({ status: true, message: `تم إضافة ${cleanCodes.length} كرت`, addedCount: cleanCodes.length }); });
});
app.put('/api/admin/cards/:id', authenticateAdmin, (req, res) => {
    const { category, status, receiver_phone } = req.body;
    db.query('UPDATE cards SET category = ?, status = ?, receiver_phone = ? WHERE id = ?', [category, status || 'available', receiver_phone || null, req.params.id], (err) => { if (err) return res.status(500).json({ status: false, message: 'فشل تحديث الكرت' }); res.json({ status: true, message: 'تم تحديث الكرت بنجاح' }); });
});
app.delete('/api/admin/cards/:id', authenticateAdmin, (req, res) => {
    db.query('DELETE FROM cards WHERE id = ?', [req.params.id], (err, result) => { if (err) return res.status(500).json({ status: false, message: 'فشل حذف الكرت' }); if (result.affectedRows === 0) return res.status(404).json({ status: false, message: 'الكرت غير موجود' }); res.json({ status: true, message: 'تم حذف الكرت بنجاح' }); });
});
app.post('/api/admin/cards/bulk-delete', authenticateAdmin, (req, res) => {
    const { cardIds } = req.body;
    if (!cardIds || !Array.isArray(cardIds) || cardIds.length === 0) return res.status(400).json({ status: false, message: 'يرجى تحديد الكروت' });
    const placeholders = cardIds.map(() => '?').join(',');
    db.query(`DELETE FROM cards WHERE id IN (${placeholders})`, cardIds, (err, result) => { if (err) return res.status(500).json({ status: false, message: 'فشل الحذف' }); res.json({ status: true, message: `تم حذف ${result.affectedRows} كرت` }); });
});
app.delete('/api/admin/cards/all', authenticateAdmin, (req, res) => {
    db.query('DELETE FROM cards', (err, result) => { if (err) return res.status(500).json({ status: false, message: 'فشل الحذف' }); res.json({ status: true, message: `تم حذف ${result.affectedRows} كرت` }); });
});

// إدارة الفئات
app.get('/api/admin/categories', authenticateAdmin, (req, res) => {
    db.query('SELECT c.*, (SELECT COUNT(*) FROM cards WHERE category = c.name) as card_count FROM categories c ORDER BY c.id DESC', (err, results) => { if (err) return res.status(500).json([]); res.json(results); });
});
app.get('/api/admin/categories/:id', authenticateAdmin, (req, res) => {
    db.query('SELECT * FROM categories WHERE id = ?', [req.params.id], (err, result) => { if (err) return res.status(500).json({ status: false, message: 'خطأ' }); if (result.length === 0) return res.status(404).json({ status: false, message: 'الفئة غير موجودة' }); res.json(result[0]); });
});
app.post('/api/admin/categories', authenticateAdmin, (req, res) => {
    const { name, price } = req.body;
    if (!name || price === undefined || price < 0) return res.status(400).json({ status: false, message: 'الاسم والسعر مطلوبان' });
    db.query('INSERT INTO categories (name, price) VALUES (?, ?)', [name, price], (err, result) => { if (err) return res.status(500).json({ status: false, message: 'فشل إضافة الفئة' }); res.json({ status: true, message: 'تمت إضافة الفئة', id: result.insertId }); });
});
app.put('/api/admin/categories/:id', authenticateAdmin, (req, res) => {
    const { name, price } = req.body;
    if (!name || price === undefined || price < 0) return res.status(400).json({ status: false, message: 'الاسم والسعر مطلوبان' });
    db.query('UPDATE categories SET name = ?, price = ? WHERE id = ?', [name, price, req.params.id], (err) => { if (err) return res.status(500).json({ status: false, message: 'فشل تحديث الفئة' }); res.json({ status: true, message: 'تم تحديث الفئة' }); });
});
app.delete('/api/admin/categories/:id', authenticateAdmin, (req, res) => {
    db.query('SELECT name FROM categories WHERE id = ?', [req.params.id], (err, result) => {
        if (err || result.length === 0) return res.status(404).json({ status: false, message: 'الفئة غير موجودة' });
        const categoryName = result[0].name;
        db.query('DELETE FROM cards WHERE category = ?', [categoryName], (err) => {
            if (err) return res.status(500).json({ status: false, message: 'فشل حذف الكروت التابعة' });
            db.query('DELETE FROM categories WHERE id = ?', [req.params.id], (err) => { if (err) return res.status(500).json({ status: false, message: 'فشل حذف الفئة' }); res.json({ status: true, message: 'تم حذف الفئة والكروت التابعة' }); });
        });
    });
});

// المعاملات
app.get('/api/admin/transactions', authenticateAdmin, (req, res) => {
    const { type, date } = req.query;
    let sql = 'SELECT t.*, u.name as user_name FROM transactions t LEFT JOIN users u ON t.user_id = u.id WHERE 1=1'; const params = [];
    if (type) { sql += ' AND t.type = ?'; params.push(type); }
    if (date) { sql += ' AND DATE(t.created_at) = ?'; params.push(date); }
    sql += ' ORDER BY t.created_at DESC LIMIT 500';
    db.query(sql, params, (err, results) => { if (err) return res.status(500).json([]); res.json(results); });
});
app.get('/api/admin/transactions/export', authenticateAdmin, (req, res) => {
    db.query('SELECT t.*, u.name as user_name FROM transactions t LEFT JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC LIMIT 1000', (err, results) => { if (err) return res.status(500).json([]); res.json(results); });
});
app.delete('/api/admin/transactions/all', authenticateAdmin, (req, res) => {
    db.query('DELETE FROM transactions', (err, result) => { if (err) return res.status(500).json({ status: false, message: 'فشل الحذف' }); res.json({ status: true, message: `تم حذف ${result.affectedRows} معاملة` }); });
});

// التقارير
app.get('/api/admin/reports', authenticateAdmin, (req, res) => {
    const { type, user, dateFrom, dateTo } = req.query;
    let sql = 'SELECT t.*, u.name as user_name FROM transactions t LEFT JOIN users u ON t.user_id = u.id WHERE 1=1'; const params = [];
    if (user) { sql += ' AND u.name LIKE ?'; params.push(`%${user}%`); }
    if (dateFrom) { sql += ' AND DATE(t.created_at) >= ?'; params.push(dateFrom); }
    if (dateTo) { sql += ' AND DATE(t.created_at) <= ?'; params.push(dateTo); }
    if (type && type !== 'all') { sql += ' AND t.type = ?'; params.push(type); }
    sql += ' ORDER BY t.created_at DESC';
    db.query(sql, params, (err, results) => { if (err) return res.status(500).json([]); res.json(results); });
});

// إدارة المديرين
app.get('/api/admin/admins', authenticateAdmin, (req, res) => {
    db.query('SELECT id, username, created_at FROM admins ORDER BY id DESC', (err, results) => { if (err) return res.status(500).json([]); res.json(results); });
});
app.get('/api/admin/admins/:id', authenticateAdmin, (req, res) => {
    db.query('SELECT id, username FROM admins WHERE id = ?', [req.params.id], (err, result) => { if (err) return res.status(500).json({ status: false, message: 'خطأ' }); if (result.length === 0) return res.status(404).json({ status: false, message: 'المدير غير موجود' }); res.json(result[0]); });
});
app.post('/api/admin/admins', authenticateAdmin, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ status: false, message: 'اسم المستخدم وكلمة المرور مطلوبان' });
    try { const hashed = await bcrypt.hash(password, 10); db.query('INSERT INTO admins (username, password) VALUES (?, ?)', [username, hashed], (err, result) => { if (err) return res.status(500).json({ status: false, message: 'فشل إضافة المدير' }); res.json({ status: true, message: 'تمت إضافة المدير', id: result.insertId }); }); } catch (err) { res.status(500).json({ status: false, message: 'خطأ في الخادم' }); }
});
app.put('/api/admin/admins/:id', authenticateAdmin, async (req, res) => {
    const { username, password } = req.body;
    let sql = 'UPDATE admins SET username = ?'; const params = [username];
    if (password) { const hashed = await bcrypt.hash(password, 10); sql += ', password = ?'; params.push(hashed); }
    sql += ' WHERE id = ?'; params.push(req.params.id);
    db.query(sql, params, (err) => { if (err) return res.status(500).json({ status: false, message: 'فشل تحديث المدير' }); res.json({ status: true, message: 'تم تحديث المدير' }); });
});
app.delete('/api/admin/admins/:id', authenticateAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    if (id === req.adminId) return res.status(400).json({ status: false, message: 'لا يمكن حذف حسابك الحالي' });
    db.query('DELETE FROM admins WHERE id = ?', [id], (err, result) => { if (err) return res.status(500).json({ status: false, message: 'فشل حذف المدير' }); if (result.affectedRows === 0) return res.status(404).json({ status: false, message: 'المدير غير موجود' }); res.json({ status: true, message: 'تم حذف المدير' }); });
});

// نقاط مؤقتة
app.post('/api/admin/create-admin', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ status: false, message: 'بيانات ناقصة' });
    try {
        const hashed = await bcrypt.hash(password, 10);
        db.query('DELETE FROM admins WHERE username = ?', [username], (err) => {
            db.query('INSERT INTO admins (username, password) VALUES (?, ?)', [username, hashed], (err, result) => {
                if (err) return res.status(500).json({ status: false, message: 'فشل إنشاء المدير' });
                res.json({ status: true, message: 'تم إنشاء المدير بنجاح', hash: hashed });
            });
        });
    } catch (err) { res.status(500).json({ status: false, message: 'خطأ في التشفير' }); }
});
app.post('/api/admin/reset-password', async (req, res) => {
    const { username, newPassword } = req.body;
    if (!username || !newPassword) return res.status(400).json({ status: false, message: 'بيانات ناقصة' });
    try {
        const hashed = await bcrypt.hash(newPassword, 10);
        db.query('UPDATE admins SET password = ? WHERE username = ?', [hashed, username], (err, result) => {
            if (err) return res.status(500).json({ status: false, message: 'خطأ في التحديث' });
            if (result.affectedRows === 0) return res.status(404).json({ status: false, message: 'المستخدم غير موجود' });
            res.json({ status: true, message: 'تم تحديث كلمة المرور بنجاح' });
        });
    } catch (err) { res.status(500).json({ status: false, message: 'خطأ في التشفير' }); }
});

// ================================================================
// تشغيل الخادم
// ================================================================
app.listen(PORT, () => {
    console.log(`🚀 الخادم شغال على http://localhost:${PORT}`);
    console.log('📡 نقاط النهاية متاحة');
    console.log('✅ الخادم جاهز للاستخدام');
});