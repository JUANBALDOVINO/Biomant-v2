const express = require('express');
const mysql2 = require('mysql2');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRA = process.env.JWT_EXPIRA || '8h';

if (!JWT_SECRET) {
    console.error('Falta JWT_SECRET en el archivo .env (ver instrucciones de instalación).');
    process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());

// Configuración de la conexión a MySQL en XAMPP
const db = mysql2.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'biomant'
});

db.connect((err) => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err);
        return;
    }
    console.log('¡Conectado exitosamente a la base de datos de XAMPP!');
});

// Panel visual de inventario (el propio index.html redirige al login si no hay sesión)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Vista de login
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Iniciar servidor
const PORT = 3000;

// =============================================================================
// AUTENTICACIÓN Y ROLES
// =============================================================================

const ROLES = ['Administrador', 'Tecnico'];

// Hash de relleno: permite comparar siempre contra un hash, exista o no el
// correo, para que el tiempo de respuesta no revele qué correos están registrados.
const HASH_RELLENO = bcrypt.hashSync('relleno-no-es-una-clave-real', 10);

// Exige una sesión válida (cabecera Authorization: Bearer <token>)
function verificarToken(req, res, next) {
    const cabecera = req.headers.authorization || '';
    const [esquema, token] = cabecera.split(' ');

    if (esquema !== 'Bearer' || !token) {
        res.status(401).json({ error: 'Debes iniciar sesión' });
        return;
    }

    jwt.verify(token, JWT_SECRET, (err, payload) => {
        if (err) {
            res.status(401).json({ error: 'Sesión inválida o vencida' });
            return;
        }

        req.usuario = {
            id_usuario: payload.id_usuario,
            nombre: payload.nombre,
            correo: payload.correo,
            rol: payload.rol
        };
        next();
    });
}

// Exige además rol Administrador. Siempre se usa DESPUÉS de verificarToken.
function soloAdministrador(req, res, next) {
    if (!req.usuario || req.usuario.rol !== 'Administrador') {
        res.status(403).json({ error: 'Esta acción es solo para el rol Administrador' });
        return;
    }
    next();
}

// Iniciar sesión: devuelve un token JWT y los datos básicos del usuario
app.post('/api/login', (req, res) => {
    const { correo, password } = req.body || {};

    if (!correo || !password) {
        res.status(400).json({ error: 'Ingresa tu correo y tu contraseña' });
        return;
    }

    const query = 'SELECT id_usuario, nombre, correo, password, rol FROM usuarios WHERE correo = ?';

    db.query(query, [String(correo).trim().toLowerCase()], (err, results) => {
        if (err) {
            console.error('Error al consultar el usuario:', err);
            res.status(500).json({ error: 'Error al iniciar sesión' });
            return;
        }

        const encontrado = results[0];
        const hash = encontrado ? encontrado.password : HASH_RELLENO;

        bcrypt.compare(String(password), hash, (errHash, coincide) => {
            if (errHash) {
                console.error('Error al verificar la contraseña:', errHash);
                res.status(500).json({ error: 'Error al iniciar sesión' });
                return;
            }

            if (!encontrado || !coincide) {
                res.status(401).json({ error: 'Correo o contraseña incorrectos' });
                return;
            }

            const usuario = {
                id_usuario: encontrado.id_usuario,
                nombre: encontrado.nombre,
                correo: encontrado.correo,
                rol: encontrado.rol
            };

            const token = jwt.sign(usuario, JWT_SECRET, { expiresIn: JWT_EXPIRA });
            res.json({ token, usuario });
        });
    });
});

// Listar usuarios (solo Administrador). Nunca devuelve el hash.
app.get('/api/usuarios', verificarToken, soloAdministrador, (req, res) => {
    const query = 'SELECT id_usuario, nombre, correo, rol, creado_en FROM usuarios ORDER BY nombre';

    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al listar usuarios:', err);
            res.status(500).json({ error: 'Error al obtener los usuarios' });
            return;
        }
        res.json(results);
    });
});

// Crear un usuario (solo Administrador). La contraseña se guarda con bcrypt.
app.post('/api/usuarios', verificarToken, soloAdministrador, (req, res) => {
    const { nombre, correo, password, rol } = req.body || {};
    const faltantes = ['nombre', 'correo', 'password', 'rol'].filter(
        (campo) => !req.body || !String(req.body[campo] ?? '').trim()
    );

    if (faltantes.length > 0) {
        res.status(400).json({ error: 'Faltan datos requeridos', campos_faltantes: faltantes });
        return;
    }

    if (!ROLES.includes(rol)) {
        res.status(400).json({ error: `El rol debe ser uno de: ${ROLES.join(', ')}` });
        return;
    }

    if (String(password).length < 8) {
        res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
        return;
    }

    bcrypt.hash(String(password), 10, (errHash, hash) => {
        if (errHash) {
            console.error('Error al cifrar la contraseña:', errHash);
            res.status(500).json({ error: 'Error al registrar el usuario' });
            return;
        }

        const query = 'INSERT INTO usuarios (nombre, correo, password, rol) VALUES (?, ?, ?, ?)';
        const valores = [String(nombre).trim(), String(correo).trim().toLowerCase(), hash, rol];

        db.query(query, valores, (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    res.status(409).json({ error: 'Ya existe un usuario con ese correo' });
                    return;
                }
                console.error('Error al crear el usuario:', err);
                res.status(500).json({ error: 'Error al registrar el usuario' });
                return;
            }

            res.status(201).json({
                mensaje: 'Usuario registrado correctamente',
                id_usuario: result.insertId
            });
        });
    });
});

// =============================================================================
// INVENTARIO DE EQUIPOS
// =============================================================================

// Todo /api/equipos requiere sesión iniciada (cualquier rol).
// Las acciones que modifican el inventario además exigen rol Administrador.
app.use('/api/equipos', verificarToken);

// Campos requeridos para crear o actualizar un equipo
const CAMPOS_EQUIPO = [
    'id_equipo',
    'nombre_equipo',
    'marca',
    'modelo',
    'numero_serie',
    'nivel_riesgo',
    'ubicacion',
    'estado',
    'tipo_categoria'
];

const CAMPOS_ACTUALIZACION = CAMPOS_EQUIPO.filter((campo) => campo !== 'id_equipo');

function validarCamposRequeridos(datos, campos) {
    return campos.filter((campo) => {
        const valor = datos[campo];
        return valor === undefined || valor === null || String(valor).trim() === '';
    });
}

// Ruta para obtener todos los equipos del inventario
app.get('/api/equipos', (req, res) => {
    const query = 'SELECT * FROM equipos';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error al consultar los equipos:', err);
            res.status(500).json({ error: 'Error al obtener el inventario' });
            return;
        }
        res.json(results);
    });
});

// Filtrar equipos por categoría (Biomédico o Tecnología)
// Se declara antes de /:id para evitar que "buscar" se interprete como identificador
app.get('/api/equipos/buscar/categoria/:tipo', (req, res) => {
    const { tipo } = req.params;
    const query = 'SELECT * FROM equipos WHERE tipo_categoria = ?';

    db.query(query, [tipo], (err, results) => {
        if (err) {
            console.error('Error al filtrar equipos por categoría:', err);
            res.status(500).json({ error: 'Error al buscar equipos por categoría' });
            return;
        }
        res.json(results);
    });
});

// Obtener un equipo específico por id_equipo
app.get('/api/equipos/:id', (req, res) => {
    const { id } = req.params;
    const query = 'SELECT * FROM equipos WHERE id_equipo = ?';

    db.query(query, [id], (err, results) => {
        if (err) {
            console.error('Error al consultar el equipo:', err);
            res.status(500).json({ error: 'Error al obtener el equipo' });
            return;
        }

        if (results.length === 0) {
            res.status(404).json({ error: 'Equipo no encontrado' });
            return;
        }

        res.json(results[0]);
    });
});

// Crear un nuevo equipo en el inventario (solo Administrador)
app.post('/api/equipos', soloAdministrador, (req, res) => {
    const faltantes = validarCamposRequeridos(req.body, CAMPOS_EQUIPO);

    if (faltantes.length > 0) {
        res.status(400).json({
            error: 'Faltan datos requeridos',
            campos_faltantes: faltantes
        });
        return;
    }

    const valores = CAMPOS_EQUIPO.map((campo) => req.body[campo]);
    const placeholders = CAMPOS_EQUIPO.map(() => '?').join(', ');
    const query = `INSERT INTO equipos (${CAMPOS_EQUIPO.join(', ')}) VALUES (${placeholders})`;

    db.query(query, valores, (err) => {
        if (err) {
            console.error('Error al crear el equipo:', err);
            res.status(500).json({ error: 'Error al registrar el equipo' });
            return;
        }

        res.status(201).json({
            mensaje: 'Equipo registrado correctamente',
            id_equipo: req.body.id_equipo
        });
    });
});

// Actualizar los datos de un equipo existente (solo Administrador)
app.put('/api/equipos/:id', soloAdministrador, (req, res) => {
    const { id } = req.params;
    const faltantes = validarCamposRequeridos(req.body, CAMPOS_ACTUALIZACION);

    if (faltantes.length > 0) {
        res.status(400).json({
            error: 'Faltan datos requeridos',
            campos_faltantes: faltantes
        });
        return;
    }

    const setClause = CAMPOS_ACTUALIZACION.map((campo) => `${campo} = ?`).join(', ');
    const valores = [...CAMPOS_ACTUALIZACION.map((campo) => req.body[campo]), id];
    const query = `UPDATE equipos SET ${setClause} WHERE id_equipo = ?`;

    db.query(query, valores, (err, result) => {
        if (err) {
            console.error('Error al actualizar el equipo:', err);
            res.status(500).json({ error: 'Error al actualizar el equipo' });
            return;
        }

        if (result.affectedRows === 0) {
            res.status(404).json({ error: 'Equipo no encontrado' });
            return;
        }

        res.status(200).json({
            mensaje: 'Equipo actualizado correctamente',
            id_equipo: id
        });
    });
});

// Eliminar un equipo por su id_equipo (solo Administrador)
app.delete('/api/equipos/:id', soloAdministrador, (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM equipos WHERE id_equipo = ?';

    db.query(query, [id], (err, result) => {
        if (err) {
            console.error('Error al eliminar el equipo:', err);
            res.status(500).json({ error: 'Error al eliminar el equipo' });
            return;
        }

        if (result.affectedRows === 0) {
            res.status(404).json({ error: 'Equipo no encontrado' });
            return;
        }

        res.status(200).json({
            mensaje: 'Equipo eliminado correctamente',
            id_equipo: id
        });
    });
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});