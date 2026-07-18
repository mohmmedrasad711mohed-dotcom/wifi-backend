// ================================================================
// server.js – الخادم المتكامل (مستخدم + إدارة)
// يدعم جميع عمليات CRUD، نظام المخزون، المعاملات، التقارير
// متوافق مع البيئات السحابية (Railway, Aiven) عبر متغيرات البيئة و SSL
// ================================================================

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== الإعدادات الأساسية ====================
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // خدمة الملفات الثابتة (لوحة الإدارة)

// ==================== توجيه /admin إلى /admin.html ====================
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ==================== اتصال قاعدة البيانات (مع SSL) ====================
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'wifi_app_db',
    port: process.env.DB_PORT || 3306,
    // تفعيل SSL إذا كان المتغير موجوداً أو إذا كان المضيف من Aiven
    ssl: (process.env.DB_SSL === 'true' || (process.env.DB_HOST && process.env.DB_HOST.includes('aivencloud.com')))
        ? { rejectUnauthorized: false } // السماح بالشهادات الذاتية (آمن في Aiven)
        : false
});

db.connect((err) => {
    if (err) {
        console.error('❌ فشل الاتصال بقاعدة البيانات:', err);
        process.exit(1);
    }
    console.log('✅ تم الاتصال بقاعدة البيانات');
});

const JWT_SECRET = process.env.JWT_SECRET || 'wifi_app_super_secret_key';

// ==================== دوال مساعدة ====================
function generateAccountNumber() {
    return Math.floor(1000000000 + Math.random() * 9000000000).toString();
}

function generateCardCode() {
    return `WIFI-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
}

// ================================================================
// وسيط المصادقة للإدارة
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
// 1. نقاط نهاية المستخدم
// ================================================================

// ---------------------------------------------
// 1.1 تسجيل حساب جديد
// ---------------------------------------------
app.post('/api/register', async (req, res) => {
    const { name, phone, password } = req.body;
    if (!name || !phone || !password) {
        return res.status(400).json({ status: false, message: 'جميع الحقول مطلوبة' });
    }

    try {
        const checkSql = 'SELECT * FROM users WHERE phone = ?';
        db.query(checkSql, [phone], async (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ status: false, message: 'خطأ في الخادم' });
            }
            if (results.length > 0) {
                return res.status(400).json({ status: false, message: 'رقم الهاتف مسجل بالفعل' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            let accountNumber;
            let isUnique = false;
            let attempts = 0;
            while (!isUnique && attempts < 10) {
                accountNumber = generateAccountNumber();
                const checkAccountSql = 'SELECT * FROM users WHERE account_number = ?';
                const accountCheck = await new Promise((resolve, reject) => {
                    db.query(checkAccountSql, [accountNumber], (err, result) => {
                        if (err) reject(err);
                        else resolve(result);
                    });
                });
                if (accountCheck.length === 0) {
                    isUnique = true;
                }
                attempts++;
            }
            if (!isUnique) {
                return res.status(500).json({ status: false, message: 'فشل توليد رقم حساب فريد' });
            }

            const insertSql = 'INSERT INTO users (name, phone, password, balance, account_number) VALUES (?, ?, ?, 0, ?)';
            db.query(insertSql, [name, phone, hashedPassword, accountNumber], (err, result) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ status: false, message: 'فشل في إنشاء الحساب' });
                }
                res.status(201).json({
                    status: true,
                    message: 'تم إنشاء الحساب بنجاح',
                    userId: result.insertId,
                    accountNumber: accountNumber
                });
            });
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ status: false, message: 'خطأ أثناء التشفير' });
    }
});

// ---------------------------------------------
// 1.2 تسجيل الدخول
// ---------------------------------------------
app.post('/api/login', (req, res) => {
    const { phone, password } = req.body;
    if (!phone || !password) {
        return res.status(400).json({ status: false, message: 'جميع الحقول مطلوبة' });
    }

    const sql = 'SELECT * FROM users WHERE phone = ?';
    db.query(sql, [phone], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'خطأ في الخادم' });
        }
        if (results.length === 0) {
            return res.status(401).json({ status: false, message: 'رقم الهاتف غير مسجل' });
        }
        const user = results[0];
        try {
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ status: false, message: 'كلمة السر غير صحيحة' });
            }
            const token = jwt.sign({ id: user.id, phone: user.phone }, JWT_SECRET, { expiresIn: '7d' });
            res.json({
                status: true,
                message: 'تم تسجيل الدخول بنجاح',
                token: token,
                user: {
                    id: user.id,
                    name: user.name,
                    phone: user.phone,
                    balance: user.balance || 0,
                    accountNumber: user.account_number
                }
            });
        } catch (error) {
            console.error(error);
            res.status(500).json({ status: false, message: 'خطأ أثناء التحقق' });
        }
    });
});

// ---------------------------------------------
// 1.3 شراء كروت (مع نظام المخزون)
// ---------------------------------------------
app.post('/api/purchase-card', async (req, res) => {
    const { userId, category, quantity = 1, receiverPhone } = req.body;

    if (!userId || !category || quantity < 1) {
        return res.status(400).json({ status: false, message: 'بيانات غير صالحة' });
    }

    db.beginTransaction((err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'خطأ في بدء المعاملة' });
        }

        // 1. جلب الفئة وسعرها
        const categorySql = 'SELECT * FROM categories WHERE name = ? OR id = ? FOR UPDATE';
        db.query(categorySql, [category, category], (err, catResults) => {
            if (err) {
                return db.rollback(() => res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' }));
            }
            if (catResults.length === 0) {
                return db.rollback(() => res.status(404).json({ status: false, message: 'الفئة غير موجودة' }));
            }

            const categoryData = catResults[0];
            const price = parseFloat(categoryData.price) || 0;
            const totalCost = price * quantity;

            // 2. التحقق من وجود كروت متاحة في المخزون
            const checkStockSql = `
                SELECT COUNT(*) as available_count 
                FROM cards 
                WHERE category = ? AND user_id IS NULL AND status = 'available'
            `;
            db.query(checkStockSql, [category], (err, stockResult) => {
                if (err) {
                    return db.rollback(() => res.status(500).json({ status: false, message: 'خطأ في التحقق من المخزون' }));
                }

                const availableCount = stockResult[0]?.available_count || 0;
                if (availableCount < quantity) {
                    return db.rollback(() => res.status(400).json({
                        status: false,
                        message: `لا يوجد كروت كافية من فئة "${category}". المتاح: ${availableCount}، المطلوب: ${quantity}`
                    }));
                }

                // 3. جلب رصيد المستخدم
                const userSql = 'SELECT balance FROM users WHERE id = ? FOR UPDATE';
                db.query(userSql, [userId], (err, userResults) => {
                    if (err) {
                        return db.rollback(() => res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' }));
                    }
                    if (userResults.length === 0) {
                        return db.rollback(() => res.status(404).json({ status: false, message: 'المستخدم غير موجود' }));
                    }

                    const currentBalance = parseFloat(userResults[0].balance) || 0;
                    if (currentBalance < totalCost) {
                        return db.rollback(() => res.status(400).json({ status: false, message: 'الرصيد غير كافٍ' }));
                    }

                    const newBalance = currentBalance - totalCost;

                    // 4. تحديث رصيد المستخدم
                    const updateBalanceSql = 'UPDATE users SET balance = ? WHERE id = ?';
                    db.query(updateBalanceSql, [newBalance, userId], (err) => {
                        if (err) {
                            return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تحديث الرصيد' }));
                        }

                        // 5. حجز الكروت من المخزون
                        const reserveCardsSql = `
                            UPDATE cards 
                            SET user_id = ?, sold_at = NOW(), status = 'sold', receiver_phone = ?
                            WHERE category = ? AND user_id IS NULL AND status = 'available'
                            LIMIT ?
                        `;
                        db.query(reserveCardsSql, [userId, receiverPhone || null, category, quantity], (err, result) => {
                            if (err) {
                                return db.rollback(() => {
                                    console.error('خطأ في حجز الكروت:', err);
                                    res.status(500).json({ status: false, message: 'فشل حجز الكروت، تم التراجع' });
                                });
                            }

                            if (result.affectedRows < quantity) {
                                return db.rollback(() => res.status(400).json({
                                    status: false,
                                    message: `تم حجز ${result.affectedRows} كرت فقط، المطلوب ${quantity}`
                                }));
                            }

                            // 6. جلب الكروت المحجوزة
                            const getCardsSql = `
                                SELECT card_code FROM cards 
                                WHERE user_id = ? AND sold_at = NOW() AND status = 'sold'
                                ORDER BY id DESC LIMIT ?
                            `;
                            db.query(getCardsSql, [userId, quantity], (err, cardResults) => {
                                if (err) {
                                    return db.rollback(() => res.status(500).json({ status: false, message: 'خطأ في جلب الكروت' }));
                                }

                                const cardCodes = cardResults.map(row => row.card_code);

                                // 7. تسجيل المعاملة
                                const description = `شراء باقة ${category} (عدد ${quantity})` + (receiverPhone ? ` مرسلة إلى ${receiverPhone}` : '');
                                const transSql = 'INSERT INTO transactions (user_id, amount, type, description, created_at) VALUES (?, ?, ?, ?, NOW())';
                                db.query(transSql, [userId, totalCost, 'purchase', description], (err) => {
                                    if (err) {
                                        return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تسجيل المعاملة' }));
                                    }

                                    db.commit((err) => {
                                        if (err) {
                                            return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تأكيد المعاملة' }));
                                        }

                                        res.status(200).json({
                                            status: true,
                                            message: `تم شراء ${quantity} بطاقة/باقة بنجاح`,
                                            purchasedCards: cardCodes,
                                            newBalance: newBalance,
                                            receiverPhone: receiverPhone || null
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
});

// ---------------------------------------------
// 1.4 تحويل الرصيد
// ---------------------------------------------
app.post('/api/transfer', async (req, res) => {
    const { senderId, receiverAccount, amount, note } = req.body;

    if (!senderId || !receiverAccount || !amount || amount <= 0) {
        return res.status(400).json({ status: false, message: 'بيانات غير صالحة' });
    }

    db.beginTransaction((err) => {
        if (err) {
            return res.status(500).json({ status: false, message: 'خطأ في بدء المعاملة' });
        }

        const senderSql = 'SELECT id, name, balance FROM users WHERE id = ? FOR UPDATE';
        db.query(senderSql, [senderId], (err, senderResults) => {
            if (err) {
                return db.rollback(() => res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' }));
            }
            if (senderResults.length === 0) {
                return db.rollback(() => res.status(404).json({ status: false, message: 'المستخدم المرسل غير موجود' }));
            }
            const sender = senderResults[0];
            const senderBalance = parseFloat(sender.balance) || 0;
            if (senderBalance < amount) {
                return db.rollback(() => res.status(400).json({ status: false, message: 'الرصيد غير كافٍ' }));
            }

            const receiverSql = 'SELECT id, name FROM users WHERE account_number = ? FOR UPDATE';
            db.query(receiverSql, [receiverAccount], (err, receiverResults) => {
                if (err) {
                    return db.rollback(() => res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' }));
                }
                if (receiverResults.length === 0) {
                    return db.rollback(() => res.status(404).json({ status: false, message: 'المستقبل غير موجود (رقم حساب خاطئ)' }));
                }
                const receiver = receiverResults[0];
                if (receiver.id === senderId) {
                    return db.rollback(() => res.status(400).json({ status: false, message: 'لا يمكن التحويل لنفس الحساب' }));
                }

                const updateSenderSql = 'UPDATE users SET balance = balance - ? WHERE id = ?';
                db.query(updateSenderSql, [amount, senderId], (err) => {
                    if (err) {
                        return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تحديث رصيد المرسل' }));
                    }

                    const updateReceiverSql = 'UPDATE users SET balance = balance + ? WHERE id = ?';
                    db.query(updateReceiverSql, [amount, receiver.id], (err) => {
                        if (err) {
                            return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تحديث رصيد المستقبل' }));
                        }

                        const transSql = 'INSERT INTO transactions (user_id, amount, type, description, created_at) VALUES (?, ?, ?, ?, NOW())';
                        db.query(transSql, [senderId, -amount, 'transfer', `تحويل إلى ${receiver.name} (رقم حساب ${receiverAccount})${note ? ' - ' + note : ''}`], (err) => {
                            if (err) {
                                return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تسجيل معاملة المرسل' }));
                            }
                            db.query(transSql, [receiver.id, amount, 'transfer', `استلام تحويل من ${sender.name} (رقم حساب)${note ? ' - ' + note : ''}`], (err) => {
                                if (err) {
                                    return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تسجيل معاملة المستقبل' }));
                                }

                                db.commit((err) => {
                                    if (err) {
                                        return db.rollback(() => res.status(500).json({ status: false, message: 'فشل تأكيد المعاملة' }));
                                    }
                                    res.status(200).json({
                                        status: true,
                                        message: 'تم التحويل بنجاح',
                                        newBalance: senderBalance - amount
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

// ---------------------------------------------
// 1.5 إرسال الكروت عبر واتساب
// ---------------------------------------------
app.post('/api/send-whatsapp', (req, res) => {
    const { cardCodes, phone } = req.body;
    if (!cardCodes || !Array.isArray(cardCodes) || cardCodes.length === 0 || !phone) {
        return res.status(400).json({ status: false, message: 'البيانات ناقصة' });
    }

    console.log(`📤 جاري إرسال ${cardCodes.length} كود إلى ${phone}:`);
    cardCodes.forEach((code, index) => {
        console.log(`   ${index+1}- ${code}`);
    });

    const updatePromises = cardCodes.map((code) => {
        return new Promise((resolve, reject) => {
            const sql = 'UPDATE cards SET receiver_phone = ? WHERE card_code = ?';
            db.query(sql, [phone, code], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    });

    Promise.all(updatePromises)
        .then(() => {
            res.status(200).json({
                status: true,
                message: `تم إرسال ${cardCodes.length} كود إلى ${phone} عبر واتساب (محاكاة)`
            });
        })
        .catch((err) => {
            console.error(err);
            res.status(500).json({ status: false, message: 'فشل تحديث أرقام المستلمين' });
        });
});

// ---------------------------------------------
// 1.6 إرسال كود كرت محدد
// ---------------------------------------------
app.post('/api/send-card', async (req, res) => {
    const { cardCode, phoneNumber } = req.body;
    if (!cardCode || !phoneNumber) {
        return res.status(400).json({ status: false, message: 'البيانات ناقصة' });
    }

    const cardSql = 'SELECT * FROM cards WHERE card_code = ?';
    db.query(cardSql, [cardCode], (err, results) => {
        if (err) {
            return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        }
        if (results.length === 0) {
            return res.status(404).json({ status: false, message: 'الكود غير موجود' });
        }

        const updateSql = 'UPDATE cards SET receiver_phone = ? WHERE card_code = ?';
        db.query(updateSql, [phoneNumber, cardCode], (err) => {
            if (err) {
                return res.status(500).json({ status: false, message: 'فشل تحديث رقم المستلم' });
            }
            console.log(`📤 إرسال الكود ${cardCode} إلى رقم ${phoneNumber}`);
            res.status(200).json({
                status: true,
                message: `تم إرسال الكود ${cardCode} إلى ${phoneNumber}`
            });
        });
    });
});

// ---------------------------------------------
// 1.7 جلب مشتريات المستخدم
// ---------------------------------------------
app.get('/api/my-cards/:userId', (req, res) => {
    const { userId } = req.params;
    const sql = 'SELECT * FROM cards WHERE user_id = ? ORDER BY sold_at DESC';
    db.query(sql, [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results);
    });
});

// ---------------------------------------------
// 1.8 جلب الفئات (للمستخدم)
// ---------------------------------------------
app.get('/api/packages', (req, res) => {
    const sql = 'SELECT * FROM categories ORDER BY price ASC';
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results);
    });
});

// ---------------------------------------------
// 1.9 جلب بيانات المستخدم
// ---------------------------------------------
app.get('/api/user/:userId', (req, res) => {
    const { userId } = req.params;
    const sql = 'SELECT id, name, phone, balance, account_number FROM users WHERE id = ?';
    db.query(sql, [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json(null);
        }
        if (results.length === 0) {
            return res.status(404).json(null);
        }
        res.json(results[0]);
    });
});

// ---------------------------------------------
// 1.10 جلب مستخدم بواسطة رقم الحساب
// ---------------------------------------------
app.get('/api/user/account/:accountNumber', (req, res) => {
    const { accountNumber } = req.params;
    const sql = 'SELECT id, name, phone, balance, account_number FROM users WHERE account_number = ?';
    db.query(sql, [accountNumber], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json(null);
        }
        if (results.length === 0) {
            return res.status(404).json(null);
        }
        res.json(results[0]);
    });
});

// ---------------------------------------------
// 1.11 جلب معاملات المستخدم
// ---------------------------------------------
app.get('/api/transactions/:userId', (req, res) => {
    const { userId } = req.params;
    const sql = 'SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC';
    db.query(sql, [userId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results);
    });
});

// ---------------------------------------------
// 1.12 حذف كرت (للمستخدم)
// ---------------------------------------------
app.delete('/api/cards/:cardId', (req, res) => {
    const { cardId } = req.params;
    const sql = 'DELETE FROM cards WHERE id = ?';
    db.query(sql, [cardId], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ status: false, message: 'الكرت غير موجود' });
        }
        res.json({ status: true, message: 'تم حذف الكرت بنجاح' });
    });
});

// ---------------------------------------------
// 1.13 حذف جميع كروت المستخدم
// ---------------------------------------------
app.delete('/api/cards/user/:userId', (req, res) => {
    const { userId } = req.params;
    const sql = 'DELETE FROM cards WHERE user_id = ?';
    db.query(sql, [userId], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        }
        res.json({
            status: true,
            message: `تم حذف ${result.affectedRows} كرت بنجاح`,
            deletedCount: result.affectedRows
        });
    });
});

// ================================================================
// 2. نقاط نهاية الإدارة (Admin) – محمية بـ authenticateAdmin
// ================================================================

// ---------------------------------------------
// 2.1 تسجيل دخول الإدارة
// ---------------------------------------------
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
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

// ---------------------------------------------
// 2.2 إحصائيات لوحة التحكم
// ---------------------------------------------
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

// ---------------------------------------------
// 2.3 إدارة المستخدمين (CRUD + بحث + توقيف + شحن)
// ---------------------------------------------
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

app.get('/api/admin/users/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    const sql = 'SELECT id, name, phone, balance, account_number, status FROM users WHERE id = ?';
    db.query(sql, [id], (err, result) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        if (result.length === 0) return res.status(404).json({ status: false, message: 'المستخدم غير موجود' });
        res.json(result[0]);
    });
});

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

// ---------------------------------------------
// 2.4 إدارة الكروت (بحث، تصفية، إضافة، تعديل، حذف، دفعات، استيراد)
// ---------------------------------------------
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

app.get('/api/admin/cards/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM cards WHERE id = ?', [id], (err, result) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        if (result.length === 0) return res.status(404).json({ status: false, message: 'الكرت غير موجود' });
        res.json(result[0]);
    });
});

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

app.post('/api/admin/cards/bulk-import', authenticateAdmin, (req, res) => {
    const { category, cardCodes } = req.body;
    if (!category || !cardCodes || !Array.isArray(cardCodes) || cardCodes.length === 0) {
        return res.status(400).json({ status: false, message: 'الفئة وقائمة الأكواد مطلوبة' });
    }

    const cleanCodes = cardCodes.map(code => code.trim()).filter(code => code.length > 0);
    if (cleanCodes.length === 0) {
        return res.status(400).json({ status: false, message: 'لا توجد أكواد صالحة للإضافة' });
    }

    const values = cleanCodes.map(code => [category, code, 'available', new Date()]);
    const sql = 'INSERT INTO cards (category, card_code, status, created_at) VALUES ?';
    db.query(sql, [values], (err, result) => {
        if (err) {
            console.error('❌ خطأ في إضافة الكروت عبر النسخ واللصق:', err);
            return res.status(500).json({ status: false, message: 'فشل إضافة الكروت: ' + err.message });
        }
        res.json({ status: true, message: `تم إضافة ${cleanCodes.length} كرت بنجاح`, addedCount: cleanCodes.length });
    });
});

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

app.delete('/api/admin/cards/all', authenticateAdmin, (req, res) => {
    db.query('DELETE FROM cards', (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل حذف جميع الكروت' });
        }
        res.json({ status: true, message: `تم حذف ${result.affectedRows} كرت بنجاح` });
    });
});

// ---------------------------------------------
// 2.5 إدارة الفئات (CRUD)
// ---------------------------------------------
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

app.get('/api/admin/categories/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM categories WHERE id = ?', [id], (err, result) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        if (result.length === 0) return res.status(404).json({ status: false, message: 'الفئة غير موجودة' });
        res.json(result[0]);
    });
});

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

// ---------------------------------------------
// 2.6 المعاملات (فلترة، تصدير، حذف الكل)
// ---------------------------------------------
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

app.delete('/api/admin/transactions/all', authenticateAdmin, (req, res) => {
    db.query('DELETE FROM transactions', (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل حذف المعاملات' });
        }
        res.json({ status: true, message: `تم حذف ${result.affectedRows} معاملة بنجاح` });
    });
});

// ---------------------------------------------
// 2.7 التقارير (مرنة)
// ---------------------------------------------
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

// ---------------------------------------------
// 2.8 إدارة المديرين (CRUD)
// ---------------------------------------------
app.get('/api/admin/admins', authenticateAdmin, (req, res) => {
    db.query('SELECT id, username, created_at FROM admins ORDER BY id DESC', (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results);
    });
});

app.get('/api/admin/admins/:id', authenticateAdmin, (req, res) => {
    const { id } = req.params;
    db.query('SELECT id, username FROM admins WHERE id = ?', [id], (err, result) => {
        if (err) return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        if (result.length === 0) return res.status(404).json({ status: false, message: 'المدير غير موجود' });
        res.json(result[0]);
    });
});

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

// ---------------------------------------------
// 2.9 نقاط نهاية مؤقتة (للاختبار – يمكن حذفها بعد الاستخدام)
// ---------------------------------------------
app.post('/api/admin/create-admin', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ status: false, message: 'بيانات ناقصة' });
    }
    try {
        const hashed = await bcrypt.hash(password, 10);
        console.log('🔑 [Admin] التجزئة الجديدة:', hashed);
        db.query('DELETE FROM admins WHERE username = ?', [username], (err) => {
            db.query('INSERT INTO admins (username, password) VALUES (?, ?)', [username, hashed], (err, result) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ status: false, message: 'فشل إنشاء المدير' });
                }
                console.log('✅ [Admin] تم إنشاء المدير بنجاح');
                res.json({ status: true, message: 'تم إنشاء المدير بنجاح', hash: hashed });
            });
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ status: false, message: 'خطأ في التشفير' });
    }
});

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
// تشغيل الخادم
// ================================================================
app.listen(PORT, () => {
    console.log(`🚀 الخادم شغال على http://localhost:${PORT}`);
    console.log('📡 نقاط النهاية المتاحة:');
    console.log('   ─── المستخدم ───');
    console.log('   POST /api/register');
    console.log('   POST /api/login');
    console.log('   POST /api/purchase-card (مع نظام المخزون)');
    console.log('   POST /api/transfer');
    console.log('   POST /api/send-whatsapp');
    console.log('   POST /api/send-card');
    console.log('   GET  /api/my-cards/:userId');
    console.log('   GET  /api/packages');
    console.log('   GET  /api/user/:userId');
    console.log('   GET  /api/user/account/:accountNumber');
    console.log('   GET  /api/transactions/:userId');
    console.log('   DELETE /api/cards/:cardId');
    console.log('   DELETE /api/cards/user/:userId');
    console.log('   ─── الإدارة (محمية) ───');
    console.log('   POST /api/admin/login');
    console.log('   GET  /api/admin/stats');
    console.log('   GET  /api/admin/users (مع بحث)');
    console.log('   GET  /api/admin/users/:id');
    console.log('   POST /api/admin/users');
    console.log('   PUT  /api/admin/users/:id');
    console.log('   PUT  /api/admin/users/:id/toggle-status');
    console.log('   POST /api/admin/users/:id/recharge');
    console.log('   DELETE /api/admin/users/:id');
    console.log('   GET  /api/admin/cards (مع فلتر)');
    console.log('   GET  /api/admin/cards/:id');
    console.log('   POST /api/admin/cards');
    console.log('   POST /api/admin/cards/bulk (توليد تلقائي)');
    console.log('   POST /api/admin/cards/bulk-import (نسخ ولصق)');
    console.log('   PUT  /api/admin/cards/:id');
    console.log('   DELETE /api/admin/cards/:id');
    console.log('   POST /api/admin/cards/bulk-delete');
    console.log('   DELETE /api/admin/cards/all');
    console.log('   GET  /api/admin/categories');
    console.log('   GET  /api/admin/categories/:id');
    console.log('   POST /api/admin/categories');
    console.log('   PUT  /api/admin/categories/:id');
    console.log('   DELETE /api/admin/categories/:id');
    console.log('   GET  /api/admin/transactions (مع فلترة)');
    console.log('   GET  /api/admin/transactions/export');
    console.log('   DELETE /api/admin/transactions/all');
    console.log('   GET  /api/admin/reports');
    console.log('   GET  /api/admin/admins');
    console.log('   GET  /api/admin/admins/:id');
    console.log('   POST /api/admin/admins');
    console.log('   PUT  /api/admin/admins/:id');
    console.log('   DELETE /api/admin/admins/:id');
    console.log('   ─── نقاط مؤقتة ───');
    console.log('   POST /api/admin/create-admin');
    console.log('   POST /api/admin/reset-password');
    console.log('\n✅ الخادم جاهز للاستخدام');
});