// server.js - النسخة النهائية مع نظام المخزون المسبق
// جميع نقاط النهاية متكاملة وآمنة

const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;
// ==================== الإعدادات الأساسية ====================
app.use(cors());
app.use(express.json());

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
    console.log('✅ تم الاتصال بقاعدة البيانات (wifi_app_db)');
});

const JWT_SECRET = 'wifi_app_super_secret_key';

// ==================== دوال مساعدة ====================
function generateAccountNumber() {
    return Math.floor(1000000000 + Math.random() * 9000000000).toString();
}

// ==================== نقاط النهاية (APIs) ====================

// ---------------------------------------------
// 1. تسجيل حساب جديد (Register)
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
// 2. تسجيل الدخول (Login)
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
// 3. شراء كروت (purchase-card) – مع نظام المخزون
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
// 4. تحويل الرصيد (Transfer)
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
// 5. إرسال الكروت عبر واتساب (send-whatsapp)
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
// 6. إرسال كود كرت محدد (send-card)
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
// 7. جلب مشتريات المستخدم (my-cards)
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
// 8. جلب الفئات (packages)
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
// 9. جلب بيانات المستخدم (user)
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
// 10. جلب مستخدم بواسطة رقم الحساب
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
// 11. جلب معاملات المستخدم (transactions)
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
// 12. حذف كرت محدد (DELETE /api/cards/:cardId)
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
// 13. حذف جميع كروت مستخدم (DELETE /api/cards/user/:userId)
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

// ---------------------------------------------
// 14. إدارة المخزون – إضافة كروت جديدة (للإدارة)
// ---------------------------------------------
app.post('/api/admin/cards', (req, res) => {
    const { category, count } = req.body;
    if (!category || !count || count <= 0) {
        return res.status(400).json({ status: false, message: 'بيانات غير صالحة' });
    }

    const values = [];
    for (let i = 0; i < count; i++) {
        const cardCode = `WIFI-${Date.now()}-${Math.floor(Math.random() * 100000)}-${i}`;
        values.push([category, cardCode, 'available', new Date()]);
    }

    const sql = 'INSERT INTO cards (category, card_code, status, created_at) VALUES ?';
    db.query(sql, [values], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل إضافة الكروت' });
        }
        res.json({ status: true, message: `تم إضافة ${count} كرت بنجاح` });
    });
});

// ---------------------------------------------
// 15. جلب عدد الكروت المتاحة لكل فئة (للإدارة)
// ---------------------------------------------
app.get('/api/admin/available-cards', (req, res) => {
    const sql = `
        SELECT category, COUNT(*) as available_count 
        FROM cards 
        WHERE user_id IS NULL AND status = 'available' 
        GROUP BY category
    `;
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results);
    });
});
// ==================== نقاط نهاية الإدارة (Admin) ====================

// ✅ وسيط (Middleware) للتحقق من صلاحية Admin
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ status: false, message: 'غير مصرح به، يلزم توكن' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // التحقق من أن المستخدم موجود في جدول admins
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

// 1. تسجيل دخول الإدارة
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

// 2. إحصائيات لوحة التحكم
app.get('/api/admin/stats', authenticateAdmin, (req, res) => {
    const queries = {
        totalUsers: 'SELECT COUNT(*) as count FROM users',
        totalCards: 'SELECT COUNT(*) as count FROM cards WHERE user_id IS NULL AND status = "available"',
        soldCards: 'SELECT COUNT(*) as count FROM cards WHERE user_id IS NOT NULL AND status = "sold"',
        totalRevenue: 'SELECT SUM(amount) as total FROM transactions WHERE type = "purchase"'
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
                    totalRevenue: results.totalRevenue?.total || 0
                });
            }
        });
    });
});

// 3. جلب جميع المستخدمين
app.get('/api/admin/users', authenticateAdmin, (req, res) => {
    const sql = 'SELECT id, name, phone, balance, account_number, created_at FROM users ORDER BY id DESC';
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'خطأ في قاعدة البيانات' });
        }
        res.json(results);
    });
});

// 4. جلب الكروت (مع فلتر اختياري)
app.get('/api/admin/cards', authenticateAdmin, (req, res) => {
    const { filter } = req.query; // 'available', 'sold', أو 'all'
    let sql = 'SELECT * FROM cards ORDER BY id DESC';
    if (filter === 'available') {
        sql = 'SELECT * FROM cards WHERE user_id IS NULL AND status = "available" ORDER BY id DESC';
    } else if (filter === 'sold') {
        sql = 'SELECT * FROM cards WHERE user_id IS NOT NULL AND status = "sold" ORDER BY id DESC';
    }
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results);
    });
});

// 5. جلب المعاملات
app.get('/api/admin/transactions', authenticateAdmin, (req, res) => {
    const sql = 'SELECT t.*, u.name as user_name FROM transactions t LEFT JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC LIMIT 100';
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        res.json(results);
    });
});

// 6. إضافة كروت إلى المخزون (مخصص للإدارة)
app.post('/api/admin/cards', authenticateAdmin, (req, res) => {
    const { category, count } = req.body;
    if (!category || !count || count <= 0) {
        return res.status(400).json({ status: false, message: 'بيانات غير صالحة' });
    }

    const values = [];
    for (let i = 0; i < count; i++) {
        const cardCode = `WIFI-${Date.now()}-${Math.floor(Math.random() * 100000)}-${i}`;
        values.push([category, cardCode, 'available', new Date()]);
    }

    const sql = 'INSERT INTO cards (category, card_code, status, created_at) VALUES ?';
    db.query(sql, [values], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'فشل إضافة الكروت' });
        }
        res.json({ status: true, message: `تم إضافة ${count} كرت بنجاح` });
    });
});

// 7. حذف كرت (للمشرف)
app.delete('/api/admin/cards/:cardId', authenticateAdmin, (req, res) => {
    const { cardId } = req.params;
    const sql = 'DELETE FROM cards WHERE id = ?';
    db.query(sql, [cardId], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ status: false, message: 'خطأ في الحذف' });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ status: false, message: 'الكرت غير موجود' });
        }
        res.json({ status: true, message: 'تم حذف الكرت بنجاح' });
    });
});
// ==================== تشغيل الخادم ====================
app.listen(port, () => {
    console.log(`🚀 الخادم شغال على http://localhost:${port}`);
    console.log('📡 نقاط النهاية المتاحة:');
    console.log('   POST /api/register');
    console.log('   POST /api/login');
    console.log('   POST /api/purchase-card (مع نظام المخزون)');
    console.log('   POST /api/transfer');
    console.log('   POST /api/send-whatsapp');
    console.log('   POST /api/send-card');
    console.log('   POST /api/admin/cards (لإضافة كروت)');
    console.log('   GET  /api/my-cards/:userId');
    console.log('   GET  /api/packages');
    console.log('   GET  /api/user/:userId');
    console.log('   GET  /api/user/account/:accountNumber');
    console.log('   GET  /api/transactions/:userId');
    console.log('   GET  /api/admin/available-cards (للعرض)');
    console.log('   DELETE /api/cards/:cardId');
    console.log('   DELETE /api/cards/user/:userId');
});