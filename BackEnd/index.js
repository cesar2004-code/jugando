const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
    return;
  }
  console.log('Connected to the database.');
});

// Registro de usuarios
app.post('/register', async (req, res) => {
  const { nombre, email, contraseña } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(contraseña, 10);
    const query = 'INSERT INTO usuarios (nombre, email, contraseña) VALUES (?, ?, ?)';
    db.query(query, [nombre, email, hashedPassword], (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Error al registrar usuario' });
      }
      res.status(201).json({ message: 'Usuario registrado con éxito' });
    });
  } catch (err) {
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

// Login de usuarios
app.post('/login', (req, res) => {
  const { email, contraseña } = req.body;
  const query = 'SELECT * FROM usuarios WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(400).json({ error: 'Usuario no encontrado' });
    }
    const user = results[0];
    const isMatch = await bcrypt.compare(contraseña, user.contraseña);
    if (!isMatch) {
      return res.status(400).json({ error: 'Contraseña incorrecta' });
    }
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });
    res.json({ token });
  });
});

// Eliminar usuario
app.delete('/delete/:id', (req, res) => {
  const { id } = req.params;
  const query = 'DELETE FROM usuarios WHERE id = ?';
  db.query(query, [id], (err, result) => {
    if (err) {
      return res.status(500).json({ error: 'Error al eliminar el usuario' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    res.json({ message: 'Usuario eliminado con éxito' });
  });
});

// Editar usuario
app.put('/edit/:id', async (req, res) => {
  const { id } = req.params;
  const { nombre, email, contraseña } = req.body;
  try {
    let query = 'UPDATE usuarios SET nombre = ?, email = ?';
    const params = [nombre, email];

    if (contraseña) {
      const hashedPassword = await bcrypt.hash(contraseña, 10);
      query += ', contraseña = ?';
      params.push(hashedPassword);
    }
    query += ' WHERE id = ?';
    params.push(id);

    db.query(query, params, (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Error al editar el usuario' });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }
      res.json({ message: 'Usuario actualizado con éxito' });
    });
  } catch (err) {
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

app.listen(3001, () => {
  console.log('Server running on port 3001');
});
