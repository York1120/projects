/**
 * 班级排座位系统 - 后端服务器
 * 基于 Node.js + Express + SQLite (sql.js)
 * 支持多用户，每个用户有独立数据
 */
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const initSqlJs = require('sql.js');
const multer = require('multer');
const XLSX = require('xlsx');

const app = express();
const PORT = process.env.DEPLOY_RUN_PORT || process.env.PORT || 5000;

// ========== 数据目录 ==========
const isProd = process.env.COZE_PROJECT_ENV === 'PROD';
const DATA_DIR = isProd ? '/tmp/seating-data' : path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, 'seating.db');

// ========== Session 管理 ==========
const sessions = new Map(); // token -> { userId, username, expiresAt }

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function createSession(userId, username) {
  const token = generateToken();
  sessions.set(token, {
    userId,
    username,
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7天过期
  });
  return token;
}

function getSession(token) {
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    return null;
  }
  return session;
}

function deleteSession(token) {
  sessions.delete(token);
}

// ========== 密码哈希 ==========
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function verifyPassword(password, salt, hash) {
  return hashPassword(password, salt) === hash;
}

// ========== 数据库辅助函数 ==========
let db;

function run(sql, params = []) {
  db.run(sql, params);
  saveDb();
}

function get(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return undefined;
}

function all(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}

function saveDb() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

// ========== 初始化数据库 ==========
async function initDb() {
  const SQL = await initSqlJs();
  
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  // 创建用户表
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
    )
  `);
  
  // 创建配置表（带用户关联）
  db.run(`
    CREATE TABLE IF NOT EXISTS config (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      rows INTEGER NOT NULL DEFAULT 6,
      cols INTEGER NOT NULL DEFAULT 6,
      podium TEXT NOT NULL DEFAULT 'top',
      updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
      UNIQUE(user_id)
    )
  `);
  
  // 创建座位表（带用户关联）
  db.run(`
    CREATE TABLE IF NOT EXISTS seats (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      row_index INTEGER NOT NULL,
      col_index INTEGER NOT NULL,
      student_name TEXT,
      updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
      UNIQUE(user_id, row_index, col_index)
    )
  `);
  
  // 创建学生表（带用户关联）
  db.run(`
    CREATE TABLE IF NOT EXISTS students (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
      UNIQUE(user_id, name)
    )
  `);

  // 迁移旧数据：如果存在没有 user_id 的旧数据，创建默认用户并迁移
  try {
    const oldConfig = db.prepare('SELECT id FROM config WHERE user_id IS NULL').get();
    if (oldConfig) {
      // 创建默认用户
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = hashPassword('123456', salt);
      db.run('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)', ['default', hash, salt]);
      const defaultUser = db.prepare('SELECT id FROM users WHERE username = ?').get(['default']);
      
      if (defaultUser) {
        // 迁移旧数据
        db.run('UPDATE config SET user_id = ? WHERE user_id IS NULL', [defaultUser.id]);
        db.run('UPDATE seats SET user_id = ? WHERE user_id IS NULL', [defaultUser.id]);
        db.run('UPDATE students SET user_id = ? WHERE user_id IS NULL', [defaultUser.id]);
        saveDb();
        console.log('已迁移旧数据到默认用户，用户名: default，密码: 123456');
      }
    }
  } catch (e) {
    // 旧数据不存在，忽略
  }
  
  saveDb();
}

// ========== 认证中间件 ==========
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const session = getSession(token);
  
  if (!session) {
    return res.status(401).json({ success: false, message: '请先登录', needLogin: true });
  }
  
  req.user = { id: session.userId, username: session.username };
  next();
}

// ========== 中间件 ==========
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

// ========== 认证 API ==========

/**
 * 用户注册
 */
app.post('/api/auth/register', (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ success: false, message: '用户名和密码不能为空' });
    }
    
    if (username.length < 2 || username.length > 20) {
      return res.status(400).json({ success: false, message: '用户名需要2-20个字符' });
    }
    
    if (password.length < 4) {
      return res.status(400).json({ success: false, message: '密码至少4个字符' });
    }
    
    // 检查用户名是否已存在
    const existing = get('SELECT id FROM users WHERE username = ?', [username]);
    if (existing) {
      return res.status(400).json({ success: false, message: '用户名已存在' });
    }
    
    // 创建用户
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword(password, salt);
    
    run('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)', [username, hash, salt]);
    
    res.json({ success: true, message: '注册成功，请登录' });
  } catch (err) {
    console.error('注册失败:', err);
    res.status(500).json({ success: false, message: '注册失败: ' + err.message });
  }
});

/**
 * 用户登录
 */
app.post('/api/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ success: false, message: '用户名和密码不能为空' });
    }
    
    const user = get('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) {
      return res.status(400).json({ success: false, message: '用户名或密码错误' });
    }
    
    if (!verifyPassword(password, user.salt, user.password_hash)) {
      return res.status(400).json({ success: false, message: '用户名或密码错误' });
    }
    
    const token = createSession(user.id, user.username);
    
    res.json({
      success: true,
      message: '登录成功',
      data: {
        token,
        username: user.username
      }
    });
  } catch (err) {
    console.error('登录失败:', err);
    res.status(500).json({ success: false, message: '登录失败' });
  }
});

/**
 * 获取当前用户信息
 */
app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({
    success: true,
    data: {
      id: req.user.id,
      username: req.user.username
    }
  });
});

/**
 * 用户登出
 */
app.post('/api/auth/logout', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) {
    deleteSession(token);
  }
  res.json({ success: true, message: '已登出' });
});

// ========== 用户数据初始化 ==========
function initUserData(userId, rows = 6, cols = 6) {
  // 检查是否已有配置
  const existing = get('SELECT id FROM config WHERE user_id = ?', [userId]);
  if (!existing) {
    run('INSERT INTO config (user_id, rows, cols, podium) VALUES (?, ?, ?, ?)', [userId, rows, cols, 'top']);
    
    // 初始化空座位
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        run('INSERT INTO seats (user_id, row_index, col_index) VALUES (?, ?, ?)', [userId, r, c]);
      }
    }
  }
}

// ========== 业务 API（需认证）==========

/**
 * 获取完整配置
 */
app.get('/api/config', authMiddleware, (req, res) => {
  try {
    initUserData(req.user.id);
    
    const config = get('SELECT rows, cols, podium FROM config WHERE user_id = ?', [req.user.id]);
    if (!config) {
      return res.json({
        success: true,
        data: { rows: 6, cols: 6, podium: 'top', grid: [], students: [] }
      });
    }
    
    const seats = all('SELECT row_index, col_index, student_name FROM seats WHERE user_id = ? ORDER BY row_index, col_index', [req.user.id]);
    const students = all('SELECT name FROM students WHERE user_id = ? ORDER BY name', [req.user.id]);

    const grid = Array.from({ length: config.rows }, () => Array(config.cols).fill(null));
    seats.forEach(seat => {
      if (seat.row_index < config.rows && seat.col_index < config.cols) {
        grid[seat.row_index][seat.col_index] = seat.student_name || null;
      }
    });

    res.json({
      success: true,
      data: {
        rows: config.rows,
        cols: config.cols,
        podium: config.podium,
        grid,
        students: students.map(s => s.name)
      }
    });
  } catch (err) {
    console.error('获取配置失败:', err);
    res.status(500).json({ success: false, message: '服务器错误' });
  }
});

/**
 * 保存完整配置
 */
app.post('/api/config', authMiddleware, (req, res) => {
  try {
    const { rows, cols, podium, grid, students } = req.body;

    if (!rows || !cols || rows < 1 || rows > 30 || cols < 1 || cols > 30) {
      return res.status(400).json({ success: false, message: '行列数需在 1-30 之间' });
    }
    const validPodiums = ['top', 'bottom', 'left', 'right'];
    if (podium && !validPodiums.includes(podium)) {
      return res.status(400).json({ success: false, message: '讲台位置无效' });
    }

    const finalRows = rows;
    const finalCols = cols;
    const finalPodium = podium || 'top';

    // 更新或创建 config
    const existing = get('SELECT id FROM config WHERE user_id = ?', [req.user.id]);
    if (existing) {
      run('UPDATE config SET rows = ?, cols = ?, podium = ?, updated_at = datetime(\'now\', \'localtime\') WHERE user_id = ?',
        [finalRows, finalCols, finalPodium, req.user.id]);
    } else {
      run('INSERT INTO config (user_id, rows, cols, podium) VALUES (?, ?, ?, ?)', [req.user.id, finalRows, finalCols, finalPodium]);
    }

    // 重建座位表
    run('DELETE FROM seats WHERE user_id = ?', [req.user.id]);
    for (let r = 0; r < finalRows; r++) {
      for (let c = 0; c < finalCols; c++) {
        const name = (grid && grid[r] && grid[r][c]) ? String(grid[r][c]).trim() : null;
        run('INSERT INTO seats (user_id, row_index, col_index, student_name) VALUES (?, ?, ?, ?)', [req.user.id, r, c, name || null]);
      }
    }

    // 重建学生名单
    run('DELETE FROM students WHERE user_id = ?', [req.user.id]);
    if (students && Array.isArray(students)) {
      students.forEach(name => {
        if (name && name.trim()) {
          try {
            run('INSERT INTO students (user_id, name) VALUES (?, ?)', [req.user.id, name.trim()]);
          } catch(e) { /* 忽略重复 */ }
        }
      });
    }

    res.json({ success: true, message: '保存成功' });
  } catch (err) {
    console.error('保存配置失败:', err);
    res.status(500).json({ success: false, message: '保存失败: ' + err.message });
  }
});

/**
 * 随机排座
 */
app.post('/api/random-assign', authMiddleware, (req, res) => {
  try {
    const unseated = all("SELECT name FROM students WHERE user_id = ? AND name NOT IN (SELECT student_name FROM seats WHERE user_id = ? AND student_name IS NOT NULL)", [req.user.id, req.user.id]);
    
    if (unseated.length === 0) {
      return res.json({ success: true, message: '没有未安排的学生', assigned: 0 });
    }

    const emptySeats = all('SELECT row_index, col_index FROM seats WHERE user_id = ? AND student_name IS NULL ORDER BY row_index, col_index', [req.user.id]);
    
    if (emptySeats.length === 0) {
      return res.json({ success: true, message: '没有空位', assigned: 0 });
    }

    const shuffledStudents = [...unseated.map(s => s.name)];
    const shuffledSeats = [...emptySeats];
    
    for (let i = shuffledStudents.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffledStudents[i], shuffledStudents[j]] = [shuffledStudents[j], shuffledStudents[i]];
    }
    for (let i = shuffledSeats.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffledSeats[i], shuffledSeats[j]] = [shuffledSeats[j], shuffledSeats[i]];
    }

    const count = Math.min(shuffledStudents.length, shuffledSeats.length);
    for (let i = 0; i < count; i++) {
      run('UPDATE seats SET student_name = ?, updated_at = datetime(\'now\', \'localtime\') WHERE user_id = ? AND row_index = ? AND col_index = ?',
        [shuffledStudents[i], req.user.id, shuffledSeats[i].row_index, shuffledSeats[i].col_index]);
    }

    res.json({ success: true, message: `已随机安排 ${count} 位同学`, assigned: count });
  } catch (err) {
    console.error('随机排座失败:', err);
    res.status(500).json({ success: false, message: '随机排座失败' });
  }
});

/**
 * 导入 Excel 学生名单
 */
app.post('/api/import/excel', authMiddleware, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: '请上传文件' });
    }

    const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
    const firstSheet = workbook.Sheets[workbook.SheetNames[0]];
    const data = XLSX.utils.sheet_to_json(firstSheet, { header: 1 });

    const names = [];
    for (const row of data) {
      if (!Array.isArray(row)) continue;
      for (const cell of row) {
        if (cell && String(cell).trim()) {
          const name = String(cell).trim();
          if (!names.includes(name)) names.push(name);
        }
      }
    }

    if (names.length === 0) {
      return res.json({ success: false, message: '未找到学生姓名' });
    }

    let imported = 0;
    names.forEach(name => {
      try {
        run('INSERT INTO students (user_id, name) VALUES (?, ?)', [req.user.id, name]);
        imported++;
      } catch(e) { /* 忽略重复 */ }
    });

    res.json({
      success: true,
      message: `成功导入 ${imported} 位学生（共识别 ${names.length} 人，${names.length - imported} 人已存在）`,
      imported,
      total: names.length
    });
  } catch (err) {
    console.error('导入失败:', err);
    res.status(500).json({ success: false, message: '导入失败: ' + err.message });
  }
});

/**
 * 按姓名导入学生
 */
app.post('/api/import/students', authMiddleware, (req, res) => {
  try {
    const { names } = req.body;
    if (!names || !Array.isArray(names) || names.length === 0) {
      return res.status(400).json({ success: false, message: '请提供学生姓名列表' });
    }

    let imported = 0;
    names.forEach(name => {
      if (name && name.trim()) {
        try {
          run('INSERT INTO students (user_id, name) VALUES (?, ?)', [req.user.id, name.trim()]);
          imported++;
        } catch(e) { /* 忽略重复 */ }
      }
    });

    res.json({ success: true, message: `成功导入 ${imported} 位学生`, imported });
  } catch (err) {
    console.error('导入失败:', err);
    res.status(500).json({ success: false, message: '导入失败: ' + err.message });
  }
});

/**
 * 添加单个学生
 */
app.post('/api/students', authMiddleware, (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ success: false, message: '姓名不能为空' });
    }
    run('INSERT OR IGNORE INTO students (user_id, name) VALUES (?, ?)', [req.user.id, name.trim()]);
    res.json({ success: true, message: `已添加「${name.trim()}」` });
  } catch (err) {
    res.status(500).json({ success: false, message: '添加失败' });
  }
});

/**
 * 删除单个学生
 */
app.delete('/api/students/:name', authMiddleware, (req, res) => {
  try {
    const name = decodeURIComponent(req.params.name);
    run('DELETE FROM students WHERE user_id = ? AND name = ?', [req.user.id, name]);
    run('UPDATE seats SET student_name = NULL WHERE user_id = ? AND student_name = ?', [req.user.id, name]);
    res.json({ success: true, message: `已移除「${name}」` });
  } catch (err) {
    res.status(500).json({ success: false, message: '删除失败' });
  }
});

/**
 * 清空所有数据
 */
app.post('/api/clear-all', authMiddleware, (req, res) => {
  try {
    run('DELETE FROM students WHERE user_id = ?', [req.user.id]);
    run('UPDATE seats SET student_name = NULL WHERE user_id = ?', [req.user.id]);
    res.json({ success: true, message: '已清空所有数据' });
  } catch (err) {
    res.status(500).json({ success: false, message: '清空失败' });
  }
});

/**
 * 导出数据
 */
app.get('/api/export', authMiddleware, (req, res) => {
  try {
    const config = get('SELECT rows, cols, podium FROM config WHERE user_id = ?', [req.user.id]);
    const seats = all('SELECT row_index, col_index, student_name FROM seats WHERE user_id = ? AND student_name IS NOT NULL ORDER BY row_index, col_index', [req.user.id]);
    const students = all('SELECT name FROM students WHERE user_id = ? ORDER BY name', [req.user.id]);

    const exportData = {
      exportTime: new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
      username: req.user.username,
      rows: config?.rows || 6,
      cols: config?.cols || 6,
      podium: config?.podium || 'top',
      seating: seats.map(s => ({
        row: s.row_index + 1,
        col: s.col_index + 1,
        name: s.student_name
      })),
      unseated: students.map(s => s.name)
    };

    res.json({ success: true, data: exportData });
  } catch (err) {
    res.status(500).json({ success: false, message: '导出失败' });
  }
});

// ========== SPA 降级处理 ==========
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ========== 启动 ==========
initDb().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`======================================`);
    console.log(`  🏫 班级排座位系统 已启动`);
    console.log(`  🌐 本地访问: http://localhost:${PORT}`);
    console.log(`  👥 支持多用户，每个用户独立数据`);
    console.log(`  💾 数据存储: SQLite (data/seating.db)`);
    console.log(`======================================`);
  });
}).catch(err => {
  console.error('数据库初始化失败:', err);
  process.exit(1);
});
