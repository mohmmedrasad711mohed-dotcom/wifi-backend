// ================================================================
// server-admin.js – خادم لوحة الإدارة المستقل
// يعمل على المنفذ 3001، ويشارك نفس قاعدة بيانات التطبيق
// يدعم جميع عمليات CRUD المتقدمة والبحث والتصفية والتقارير
// مع فحص تلقائي لقاعدة البيانات لإنشاء الأعمدة المفقودة
// ================================================================

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const ADMIN_PORT = 3001;

// ==================== الإعدادات الأساسية ====================
app.use(cors());
app.use(express.json());
// ==================== خدمة الملفات الثابتة ====================
app.use(express.static('public'));

// ==================== نقطة إضافية لتوجيه /admin إلى /admin.html ====================
app.get('/admin', (req, res) => {
    res.sendFile(__dirname + '/public/admin.html');
});
// ==================== اتصال قاعدة البيانات ====================
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'wifi_app_db'
});

db.connect((err) => {
    if (err) {
        console.error('❌ فشل الاتصال بقاعدة البيانات:', err);
        process.exit(1);
    }
    console.log('✅ [Admin] تم الاتصال بقاعدة البيانات (wifi_app_db)');

    // فحص وإنشاء الأعمدة المفقودة
    ensureDatabaseSchema();
});

const JWT_SECRET = 'wifi_app_super_secret_key';

// ================================================================
// دوال مساعدة
// ================================================================

/**
 * توليد رقم حساب فريد (10 أرقام عشوائية)
 */
function generateAccountNumber() {
    return Math.floor(1000000000 + Math.random() * 9000000000).toString();
}

/**
 * توليد كود كرت فريد (للاستخدام الفردي)
 */
function generateCardCode() {
    return `WIFI-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
}

/**
 * التحقق من وجود عمود في جدول معين، وإنشاؤه إذا لم يكن موجوداً
 */
function ensureColumn(table, column, definition) {
    return new Promise((resolve, reject) => {
        const checkSql = `
            SELECT COUNT(*) as count 
            FROM information_schema.COLUMNS 
            WHERE TABLE_SCHEMA = 'wifi_app_db' 
            AND TABLE_NAME = ? 
            AND COLUMN_NAME = ?
        `;
        db.query(checkSql, [table, column], (err, results) => {
            if (err) {
                console.error(`❌ فشل التحقق من العمود ${column} في جدول ${table}:`, err);
                return reject(err);
            }
            if (results[0].count === 0) {
                const alterSql = `ALTER TABLE ${table} ADD COLUMN ${definition}`;
                db.query(alterSql, (err) => {
                    if (err) {
                        console.error(`❌ فشل إنشاء العمود ${column} في جدول ${table}:`, err);
                        return reject(err);
                    }
                    console.log(`✅ [Admin] تم إنشاء العمود ${column} في جدول ${table}`);
                    resolve();
                });
            } else {
                resolve();
            }
        });
    });
}

/**
 * فحص وإنشاء الأعمدة المفقودة في جميع الجداول
 */
async function ensureDatabaseSchema() {
    try {
        // 1. عمود status في جدول users
        await ensureColumn('users', 'status', "ENUM('active', 'suspended') DEFAULT 'active'");

        // 2. عمود receiver_phone في جدول cards (إن لم يكن موجوداً)
        await ensureColumn('cards', 'receiver_phone', "VARCHAR(20) NULL");

        // 3. عمود created_at في جدول admins (إن لم يكن موجوداً)
        await ensureColumn('admins', 'created_at', "TIMESTAMP DEFAULT CURRENT_TIMESTAMP");

        console.log('✅ [Admin] جميع الأعمدة المطلوبة موجودة أو تم إنشاؤها');
    } catch (err) {
        console.error('❌ [Admin] فشل فحص قاعدة البيانات:', err);
    }
}

// ================================================================
// وسيط المصادقة للتحقق من صلاحية المدير
// ================================================================
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ status: false, message: 'غير مصرح به، يلزم توكن' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const sql = 'SELECT id FROM admins WHERE id = ?';
        db.query(sql, [decoded.id], (err, results) => {
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
// 1. نقاط نهاية المصادقة
// ================================================================

/**
 * POST /api/admin/login – تسجيل دخول المدير
 */
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    console.log('📥 [Admin] محاولة تسجيل دخول:', username);

    if (!username || !password) {
        return res.status(400).json({ status: false, message: 'اسم المستخدم وكلمة المرور مطلوبة' });
    }

    const sql = 'SELECT * FROM admins WHERE username = ?';
    db.query(sql, [username], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'خطأ في الخادم' });
        }
        if (results.length === 0) {
            return res.status(401).json({ status: false, message: 'اسم المستخدم غير صحيح' });
        }
        const admin = results[0];
        try {
            const isMatch = await bcrypt.compare(password, admin.password);
            console.log('🔍 [Admin] نتيجة مقارنة bcrypt:', isMatch);
            if (!isMatch) {
                return res.status(401).json({ status: false, message: 'كلمة المرور غير صحيحة' });
            }
            const token = jwt.sign({ id: admin.id, role: 'admin' }, JWT_SECRET, { expiresIn: '1d' });
            res.json({ status: true, message: 'تم تسجيل الدخول بنجاح', token: token });
        } catch (error) {
            console.error(error);
            res.status(500).json({ status: false, message: 'خطأ أثناء التحقق' });
        }
    });
});

// ================================================================
// 2. نقاط نهاية الإحصائيات
// ================================================================

/**
 * GET /api/admin/stats – إحصائيات متقدمة للوحة التحكم
 */
app.get('/api/admin/stats', authenticateAdmin, (req, res) => {
    const queries = {
        totalUsers: 'SELECT COUNT(*) as count FROM users',
        totalCards: 'SELECT COUNT(*) as count FROM cards WHERE user_id IS NULL AND status = "available"',
        soldCards: 'SELECT COUNT(*) as count FROM cards WHERE user_id IS NOT NULL AND status = "sold"',
        totalRevenue: 'SELECT SUM(amount) as total FROM transactions WHERE type = "purchase"',
        todayTransactions: 'SELECT COUNT(*) as count FROM transactions WHERE DATE(created_at) = CURDATE()',
        monthTransactions: 'SELECT COUNT(*) as count FROM transactions WHERE MONTH(created_at) = MONTH(CURDATE()) AND YEAR(created_at) = YEAR(CURDATE())'
    };

    let results = {};
    let completed = 0;
    const keys = Object.keys(queries);

    keys.forEach((key) => {
        db.query(queries[key], (err, result) => {
            if (err) {
                console.error(err);
                results[key] = { count: 0, total: 0 };
            } else {
                results[key] = result[0] || { count: 0, total: 0 };
            }
            completed++;
            if (completed === keys.length) {
                res.json({
                    totalUsers: results.totalUsers?.count || 0,
                    availableCards: results.totalCards?.count || 0,
                    soldCards: results.soldCards?.count || 0,
                    totalRevenue: results.totalRevenue?.total || 0,
                    todayTransactions: results.todayTransactions?.count || 0,
                    monthTransactions: results.monthTransactions?.count || 0
                });
            }
        });
    });
});

// ================================================================
// 3. نقاط نهاية المستخدمين (CRUD + بحث + توقيف + شحن)
// ================================================================

/**
 * GET /api/admin/users – جلب المستخدمين مع بحث اختياري
 */
app.get('/api/admin/users', authenticateAdmin, (req, res) => {
    const { search } = req.query;
    let sql = 'SELECT id, name, phone, balance, account_number, status, created_at FROM users';
    const params = [];
    if (search) {
        sql += ' WHERE name LIKE ? OR phone LIKE ? OR account_number LIKE ?';
        const s = `%${search}%`;
        params.push(s, s, s);
    }
    sql += ' ORDER BY id DESC';
    db.query(sql, params, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results);
    });
});

/**
 * GET /api/admin/users/:id – جلب مستخدم محدد
 */
app.get('/api/admin/users/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    const sql = 'SELECT id, name, phone, balance, account_number, status FROM users WHERE id = ?';
    db.query(sql, [id], (err, result) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        if (result.length === 0) return res.status(404).json({ status: false, message: 'المستخدم غير موجود' });
        res.json(result[0]);
    });
});

/**
 * POST /api/admin/users – إضافة مستخدم جديد
 */
app.post('/api/admin/users', authenticateAdmin, async (req, res) => {
    const { name, phone, password, balance, status } = req.body;
    if (!name || !phone) {
        return res.status(400).json({ status: false, message: 'الاسم والهاتف مطلوبان' });
    }
    try {
        const hashed = password ? await bcrypt.hash(password, 10) : null;
        const accountNumber = generateAccountNumber();
        const sql = 'INSERT INTO users (name, phone, password, balance, account_number, status) VALUES (?, ?, ?, ?, ?, ?)';
        db.query(sql, [name, phone, hashed, balance || 0, accountNumber, status || 'active'], (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ status: false, message: 'فشل إضافة المستخدم' });
            }
            res.json({ status: true, message: 'تمت إضافة المستخدم بنجاح', id: result.insertId });
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ status: false, message: 'خطأ في الخادم' });
    }
});

/**
 * PUT /api/admin/users/:id – تحديث بيانات المستخدم
 */
app.put('/api/admin/users/:id', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, phone, password, balance, status } = req.body;
    let sql = 'UPDATE users SET name = ?, phone = ?, balance = ?, status = ?';
    const params = [name, phone, balance || 0, status || 'active'];
    if (password) {
        const hashed = await bcrypt.hash(password, 10);
        sql += ', password = ?';
        params.push(hashed);
    }
    sql += ' WHERE id = ?';
    params.push(id);
    db.query(sql, params, (err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل تحديث المستخدم' });
        }
        res.json({ status: true, message: 'تم تحديث المستخدم بنجاح' });
    });
});

/**
 * PUT /api/admin/users/:id/toggle-status – تبديل حالة المستخدم (توقيف/تفعيل)
 */
app.put('/api/admin/users/:id/toggle-status', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    db.query('SELECT status FROM users WHERE id = ?', [id], (err, result) => {
        if (err || result.length === 0) {
            return res.status(404).json({ status: false, message: 'المستخدم غير موجود' });
        }
        const newStatus = result[0].status === 'suspended' ? 'active' : 'suspended';
        db.query('UPDATE users SET status = ? WHERE id = ?', [newStatus, id], (err) => {
            if (err) {
                return res.status(500).json({ status: false, message: 'فشل تغيير الحالة' });
            }
            res.json({ status: true, message: `تم ${newStatus === 'active' ? 'تفعيل' : 'توقيف'} المستخدم بنجاح` });
        });
    });
});

/**
 * POST /api/admin/users/:id/recharge – شحن رصيد المستخدم
 */
app.post('/api/admin/users/:id/recharge', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    const { amount, note } = req.body;
    if (!amount || amount <= 0) {
        return res.status(400).json({ status: false, message: 'المبلغ يجب أن يكون أكبر من صفر' });
    }

    db.beginTransaction((err) => {
        if (err) {
            return res.status(500).json({ status: false, message: 'خطأ في بدء المعاملة' });
        }
        db.query('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, id], (err, result) => {
            if (err || result.affectedRows === 0) {
                return db.rollback(() => res.status(500).json({ status: false, message: 'فشل شحن الرصيد' }));
            }
            const transSql = 'INSERT INTO transactions (user_id, amount, type, description) VALUES (?, ?, "recharge", ?)';
            db.query(transSql, [id, amount, note || 'شحن رصيد من لوحة الإدارة'], (err) => {
                if (err) {
                    return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تسجيل المعاملة' }));
                }
                db.commit(() => {
                    res.json({ status: true, message: `تم شحن ${amount} ر.ي بنجاح للمستخدم` });
                });
            });
        });
    });
});

/**
 * DELETE /api/admin/users/:id – حذف مستخدم
 */
app.delete('/api/admin/users/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    db.query('DELETE FROM users WHERE id = ?', [id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل حذف المستخدم' });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ status: false, message: 'المستخدم غير موجود' });
        }
        res.json({ status: true, message: 'تم حذف المستخدم بنجاح' });
    });
});

// ================================================================
// 4. نقاط نهاية الكروت (CRUD + بحث + تصفية + دفعات + حذف متعدد + استيراد)
// ================================================================

/**
 * GET /api/admin/cards – جلب الكروت مع بحث وتصفية
 */
app.get('/api/admin/cards', authenticateAdmin, (req, res) => {
    const { search, category, status } = req.query;
    let sql = 'SELECT * FROM cards WHERE 1=1';
    const params = [];
    if (search) {
        sql += ' AND (card_code LIKE ? OR category LIKE ?)';
        const s = `%${search}%`;
        params.push(s, s);
    }
    if (category) {
        sql += ' AND category = ?';
        params.push(category);
    }
    if (status) {
        sql += ' AND status = ?';
        params.push(status);
    }
    sql += ' ORDER BY id DESC';
    db.query(sql, params, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results);
    });
});

/**
 * GET /api/admin/cards/:id – جلب كرت محدد
 */
app.get('/api/admin/cards/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM cards WHERE id = ?', [id], (err, result) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        if (result.length === 0) return res.status(404).json({ status: false, message: 'الكرت غير موجود' });
        res.json(result[0]);
    });
});

/**
 * POST /api/admin/cards – إضافة كرت فردي
 */
app.post('/api/admin/cards', authenticateAdmin, (req, res) => {
    const { category, status, receiver_phone } = req.body;
    if (!category) {
        return res.status(400).json({ status: false, message: 'الفئة مطلوبة' });
    }
    const cardCode = generateCardCode();
    const sql = 'INSERT INTO cards (category, card_code, status, receiver_phone) VALUES (?, ?, ?, ?)';
    db.query(sql, [category, cardCode, status || 'available', receiver_phone || null], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل إضافة الكرت' });
        }
        res.json({ status: true, message: 'تم إضافة الكرت بنجاح', id: result.insertId });
    });
});

/**
 * POST /api/admin/cards/bulk – إضافة دفعة كروت (توليد تلقائي)
 */
app.post('/api/admin/cards/bulk', authenticateAdmin, (req, res) => {
    const { category, count } = req.body;
    if (!category || !count || count < 1) {
        return res.status(400).json({ status: false, message: 'الفئة والعدد المطلوبين (العدد > 0)' });
    }
    const numCount = parseInt(count);
    if (isNaN(numCount) || numCount < 1) {
        return res.status(400).json({ status: false, message: 'العدد يجب أن يكون رقماً صحيحاً موجباً' });
    }
    const values = [];
    for (let i = 0; i < numCount; i++) {
        const cardCode = `WIFI-${Date.now()}-${Math.floor(Math.random() * 100000)}-${i}`;
        values.push([category, cardCode, 'available', new Date()]);
    }
    const sql = 'INSERT INTO cards (category, card_code, status, created_at) VALUES ?';
    db.query(sql, [values], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل إضافة الدفعة' });
        }
        res.json({ status: true, message: `تمت إضافة ${numCount} كرت بنجاح` });
    });
});

/**
 * POST /api/admin/cards/bulk-import – إضافة كروت بالنسخ واللصق (بدون توليد)
 * @body { category, cardCodes: [code1, code2, ...] }
 */
app.post('/api/admin/cards/bulk-import', authenticateAdmin, (req, res) => {
    const { category, cardCodes } = req.body;
    if (!category || !cardCodes || !Array.isArray(cardCodes) || cardCodes.length === 0) {
        return res.status(400).json({ status: false, message: 'الفئة وقائمة الأكواد مطلوبة' });
    }

    // تنظيف الأكواد (إزالة المسافات والأسطر الفارغة)
    const cleanCodes = cardCodes
        .map(code => code.trim())
        .filter(code => code.length > 0);

    if (cleanCodes.length === 0) {
        return res.status(400).json({ status: false, message: 'لا توجد أكواد صالحة للإضافة' });
    }

    // التحقق من تكرار الأكواد (اختياري)
    // يمكن إضافة تحقق إضافي لتجنب إدراج أكواد مكررة

    const values = [];
    for (const code of cleanCodes) {
        values.push([category, code, 'available', new Date()]);
    }

    const sql = 'INSERT INTO cards (category, card_code, status, created_at) VALUES ?';
    db.query(sql, [values], (err, result) => {
        if (err) {
            console.error('❌ خطأ في إضافة الكروت عبر النسخ واللصق:', err);
            return res.status(500).json({ status: false, message: 'فشل إضافة الكروت: ' + err.message });
        }
        res.json({
            status: true,
            message: `تم إضافة ${cleanCodes.length} كرت بنجاح`,
            addedCount: cleanCodes.length
        });
    });
});

/**
 * PUT /api/admin/cards/:id – تحديث كرت
 */
app.put('/api/admin/cards/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    const { category, status, receiver_phone } = req.body;
    const sql = 'UPDATE cards SET category = ?, status = ?, receiver_phone = ? WHERE id = ?';
    db.query(sql, [category, status || 'available', receiver_phone || null, id], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل تحديث الكرت' });
        }
        res.json({ status: true, message: 'تم تحديث الكرت بنجاح' });
    });
});

/**
 * DELETE /api/admin/cards/:id – حذف كرت فردي
 */
app.delete('/api/admin/cards/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    db.query('DELETE FROM cards WHERE id = ?', [id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل حذف الكرت' });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ status: false, message: 'الكرت غير موجود' });
        }
        res.json({ status: true, message: 'تم حذف الكرت بنجاح' });
    });
});

/**
 * POST /api/admin/cards/bulk-delete – حذف كروت متعددة
 */
app.post('/api/admin/cards/bulk-delete', authenticateAdmin, (req, res) => {
    const { cardIds } = req.body;
    if (!cardIds || !Array.isArray(cardIds) || cardIds.length === 0) {
        return res.status(400).json({ status: false, message: 'يرجى تحديد الكروت المراد حذفها' });
    }
    const placeholders = cardIds.map(() => '?').join(',');
    const sql = `DELETE FROM cards WHERE id IN (${placeholders})`;
    db.query(sql, cardIds, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل حذف الكروت المحددة' });
        }
        res.json({ status: true, message: `تم حذف ${result.affectedRows} كرت بنجاح` });
    });
});

/**
 * DELETE /api/admin/cards/all – حذف جميع الكروت
 */
app.delete('/api/admin/cards/all', authenticateAdmin, (req, res) => {
    db.query('DELETE FROM cards', (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل حذف جميع الكروت' });
        }
        res.json({ status: true, message: `تم حذف ${result.affectedRows} كرت بنجاح` });
    });
});

// ================================================================
// 5. نقاط نهاية الفئات (CRUD كامل مع عدد الكروت التابعة)
// ================================================================

/**
 * GET /api/admin/categories – جلب جميع الفئات مع عدد الكروت لكل فئة
 */
app.get('/api/admin/categories', authenticateAdmin, (req, res) => {
    const sql = `
        SELECT c.*, 
        (SELECT COUNT(*) FROM cards WHERE category = c.name) as card_count 
        FROM categories c 
        ORDER BY c.id DESC
    `;
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results);
    });
});

/**
 * GET /api/admin/categories/:id – جلب فئة محددة
 */
app.get('/api/admin/categories/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM categories WHERE id = ?', [id], (err, result) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        if (result.length === 0) return res.status(404).json({ status: false, message: 'الفئة غير موجودة' });
        res.json(result[0]);
    });
});

/**
 * POST /api/admin/categories – إضافة فئة جديدة
 */
app.post('/api/admin/categories', authenticateAdmin, (req, res) => {
    const { name, price } = req.body;
    if (!name || price === undefined || price < 0) {
        return res.status(400).json({ status: false, message: 'الاسم والسعر مطلوبان (السعر >= 0)' });
    }
    db.query('INSERT INTO categories (name, price) VALUES (?, ?)', [name, price], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل إضافة الفئة' });
        }
        res.json({ status: true, message: 'تمت إضافة الفئة بنجاح', id: result.insertId });
    });
});

/**
 * PUT /api/admin/categories/:id – تحديث فئة
 */
app.put('/api/admin/categories/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    const { name, price } = req.body;
    if (!name || price === undefined || price < 0) {
        return res.status(400).json({ status: false, message: 'الاسم والسعر مطلوبان (السعر >= 0)' });
    }
    db.query('UPDATE categories SET name = ?, price = ? WHERE id = ?', [name, price, id], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل تحديث الفئة' });
        }
        res.json({ status: true, message: 'تم تحديث الفئة بنجاح' });
    });
});

/**
 * DELETE /api/admin/categories/:id – حذف فئة (مع حذف الكروت التابعة)
 */
app.delete('/api/admin/categories/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    db.query('SELECT name FROM categories WHERE id = ?', [id], (err, result) => {
        if (err || result.length === 0) {
            return res.status(404).json({ status: false, message: 'الفئة غير موجودة' });
        }
        const categoryName = result[0].name;
        db.query('DELETE FROM cards WHERE category = ?', [categoryName], (err) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ status: false, message: 'فشل حذف الكروت التابعة' });
            }
            db.query('DELETE FROM categories WHERE id = ?', [id], (err) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ status: false, message: 'فشل حذف الفئة' });
                }
                res.json({ status: true, message: 'تم حذف الفئة والكروت التابعة لها بنجاح' });
            });
        });
    });
});

// ================================================================
// 6. نقاط نهاية المعاملات (عرض مع فلترة وتصدير وحذف الكل)
// ================================================================

/**
 * GET /api/admin/transactions – جلب المعاملات مع فلترة
 */
app.get('/api/admin/transactions', authenticateAdmin, (req, res) => {
    const { type, date } = req.query;
    let sql = 'SELECT t.*, u.name as user_name FROM transactions t LEFT JOIN users u ON t.user_id = u.id WHERE 1=1';
    const params = [];
    if (type) {
        sql += ' AND t.type = ?';
        params.push(type);
    }
    if (date) {
        sql += ' AND DATE(t.created_at) = ?';
        params.push(date);
    }
    sql += ' ORDER BY t.created_at DESC LIMIT 500';
    db.query(sql, params, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results);
    });
});

/**
 * GET /api/admin/transactions/export – تصدير المعاملات إلى JSON (لتحويل لاحق إلى CSV)
 */
app.get('/api/admin/transactions/export', authenticateAdmin, (req, res) => {
    const sql = 'SELECT t.*, u.name as user_name FROM transactions t LEFT JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC LIMIT 1000';
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results);
    });
});

/**
 * DELETE /api/admin/transactions/all – حذف جميع المعاملات
 */
app.delete('/api/admin/transactions/all', authenticateAdmin, (req, res) => {
    db.query('DELETE FROM transactions', (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل حذف المعاملات' });
        }
        res.json({ status: true, message: `تم حذف ${result.affectedRows} معاملة بنجاح` });
    });
});

// ================================================================
// 7. نقاط نهاية التقارير (مرنة)
// ================================================================

/**
 * GET /api/admin/reports – إنشاء تقارير مخصصة
 */
app.get('/api/admin/reports', authenticateAdmin, (req, res) => {
    const { type, user, dateFrom, dateTo } = req.query;
    let sql = 'SELECT t.*, u.name as user_name FROM transactions t LEFT JOIN users u ON t.user_id = u.id WHERE 1=1';
    const params = [];

    if (user) {
        sql += ' AND u.name LIKE ?';
        params.push(`%${user}%`);
    }
    if (dateFrom) {
        sql += ' AND DATE(t.created_at) >= ?';
        params.push(dateFrom);
    }
    if (dateTo) {
        sql += ' AND DATE(t.created_at) <= ?';
        params.push(dateTo);
    }
    if (type && type !== 'all') {
        sql += ' AND t.type = ?';
        params.push(type);
    }
    sql += ' ORDER BY t.created_at DESC';
    db.query(sql, params, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results);
    });
});

// ================================================================
// 8. نقاط نهاية المديرين (CRUD كامل مع منع حذف النفس)
// ================================================================

/**
 * GET /api/admin/admins – جلب جميع المديرين
 */
app.get('/api/admin/admins', authenticateAdmin, (req, res) => {
    db.query('SELECT id, username, created_at FROM admins ORDER BY id DESC', (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results);
    });
});

/**
 * GET /api/admin/admins/:id – جلب مدير محدد
 */
app.get('/api/admin/admins/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    db.query('SELECT id, username FROM admins WHERE id = ?', [id], (err, result) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        if (result.length === 0) return res.status(404).json({ status: false, message: 'المدير غير موجود' });
        res.json(result[0]);
    });
});

/**
 * POST /api/admin/admins – إضافة مدير جديد
 */
app.post('/api/admin/admins', authenticateAdmin, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ status: false, message: 'اسم المستخدم وكلمة المرور مطلوبان' });
    }
    try {
        const hashed = await bcrypt.hash(password, 10);
        db.query('INSERT INTO admins (username, password) VALUES (?, ?)', [username, hashed], (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ status: false, message: 'فشل إضافة المدير' });
            }
            res.json({ status: true, message: 'تمت إضافة المدير بنجاح', id: result.insertId });
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ status: false, message: 'خطأ في الخادم' });
    }
});

/**
 * PUT /api/admin/admins/:id – تحديث مدير
 */
app.put('/api/admin/admins/:id', authenticateAdmin, async (req, res) => {
    const { id } = req.params;
    const { username, password } = req.body;
    let sql = 'UPDATE admins SET username = ?';
    const params = [username];
    if (password) {
        const hashed = await bcrypt.hash(password, 10);
        sql += ', password = ?';
        params.push(hashed);
    }
    sql += ' WHERE id = ?';
    params.push(id);
    db.query(sql, params, (err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل تحديث المدير' });
        }
        res.json({ status: true, message: 'تم تحديث المدير بنجاح' });
    });
});

/**
 * DELETE /api/admin/admins/:id – حذف مدير (يمنع حذف النفس)
 */
app.delete('/api/admin/admins/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    if (parseInt(id) === req.adminId) {
        return res.status(400).json({ status: false, message: 'لا يمكن حذف حسابك الحالي' });
    }
    db.query('DELETE FROM admins WHERE id = ?', [id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل حذف المدير' });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ status: false, message: 'المدير غير موجود' });
        }
        res.json({ status: true, message: 'تم حذف المدير بنجاح' });
    });
});

// ================================================================
// 9. نقاط نهاية مؤقتة (للاختبار – يمكن حذفها بعد الاستخدام)
// ================================================================

/**
 * (مؤقت) POST /api/admin/create-admin – إنشاء مدير جديد
 */
app.post('/api/admin/create-admin', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ status: false, message: 'بيانات ناقصة' });
    }
    try {
        const hashed = await bcrypt.hash(password, 10);
        console.log('🔑 [Admin] التجزئة الجديدة:', hashed);

        // حذف المدير القديم إن وجد
        db.query('DELETE FROM admins WHERE username = ?', [username], (err) => {
            // إدراج المدير الجديد
            db.query('INSERT INTO admins (username, password) VALUES (?, ?)', [username, hashed], (err, result) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ status: false, message: 'فشل إنشاء المدير' });
                }
                console.log('✅ [Admin] تم إنشاء المدير بنجاح');
                res.json({
                    status: true,
                    message: 'تم إنشاء المدير بنجاح',
                    hash: hashed
                });
            });
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ status: false, message: 'خطأ في التشفير' });
    }
});

/**
 * (مؤقت) POST /api/admin/reset-password – إعادة تعيين كلمة مرور المدير
 */
app.post('/api/admin/reset-password', async (req, res) => {
    const { username, newPassword } = req.body;
    if (!username || !newPassword) {
        return res.status(400).json({ status: false, message: 'بيانات ناقصة' });
    }
    try {
        const hashed = await bcrypt.hash(newPassword, 10);
        db.query('UPDATE admins SET password = ? WHERE username = ?', [hashed, username], (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ status: false, message: 'خطأ في التحديث' });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ status: false, message: 'المستخدم غير موجود' });
            }
            console.log('✅ [Admin] تم تحديث كلمة المرور بنجاح');
            res.json({ status: true, message: 'تم تحديث كلمة المرور بنجاح' });
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ status: false, message: 'خطأ في التشفير' });
    }
});

// ================================================================
// 10. تشغيل الخادم
// ================================================================

app.listen(ADMIN_PORT, () => {
    console.log(`\n🚀 [Admin] خادم الإدارة شغال على http://localhost:${ADMIN_PORT}`);
    console.log('📡 نقاط النهاية الإدارية المتاحة:');
    console.log('   ─── المصادقة ───');
    console.log('   POST /api/admin/login');
    console.log('   ─── الإحصائيات ───');
    console.log('   GET  /api/admin/stats');
    console.log('   ─── المستخدمين ───');
    console.log('   GET  /api/admin/users (مع بحث)');
    console.log('   GET  /api/admin/users/:id');
    console.log('   POST /api/admin/users');
    console.log('   PUT  /api/admin/users/:id');
    console.log('   PUT  /api/admin/users/:id/toggle-status');
    console.log('   POST /api/admin/users/:id/recharge');
    console.log('   DELETE /api/admin/users/:id');
    console.log('   ─── الكروت ───');
    console.log('   GET  /api/admin/cards (مع بحث وتصفية)');
    console.log('   GET  /api/admin/cards/:id');
    console.log('   POST /api/admin/cards');
    console.log('   POST /api/admin/cards/bulk (توليد تلقائي)');
    console.log('   POST /api/admin/cards/bulk-import (نسخ ولصق)');
    console.log('   PUT  /api/admin/cards/:id');
    console.log('   DELETE /api/admin/cards/:id');
    console.log('   POST /api/admin/cards/bulk-delete');
    console.log('   DELETE /api/admin/cards/all');
    console.log('   ─── الفئات ───');
    console.log('   GET  /api/admin/categories');
    console.log('   GET  /api/admin/categories/:id');
    console.log('   POST /api/admin/categories');
    console.log('   PUT  /api/admin/categories/:id');
    console.log('   DELETE /api/admin/categories/:id');
    console.log('   ─── المعاملات ───');
    console.log('   GET  /api/admin/transactions (مع فلترة)');
    console.log('   GET  /api/admin/transactions/export');
    console.log('   DELETE /api/admin/transactions/all (✅ جديد)');
    console.log('   ─── التقارير ───');
    console.log('   GET  /api/admin/reports');
    console.log('   ─── المديرين ───');
    console.log('   GET  /api/admin/admins');
    console.log('   GET  /api/admin/admins/:id');
    console.log('   POST /api/admin/admins');
    console.log('   PUT  /api/admin/admins/:id');
    console.log('   DELETE /api/admin/admins/:id');
    console.log('   ─── نقاط مؤقتة (احذفها بعد الاستخدام) ───');
    console.log('   POST /api/admin/create-admin');
    console.log('   POST /api/admin/reset-password');
    console.log('\n✅ [Admin] خادم الإدارة جاهز للاستخدام');
});