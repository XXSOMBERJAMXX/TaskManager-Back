require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); // Requerir jsonwebtoken
const moment = require('moment');

const app = express();
app.use(express.json());
app.use(cors());

// Conectar a MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log(' Conectado a MongoDB ✅'))
.catch(err => console.error(' Error al conectar MongoDB ❌:', err));

// Modelo de usuario
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  last_login: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Modelo de Task
const taskSchema = new mongoose.Schema({
  nameTask: { type: String, required: true },
  description: { type: String, required: true },
  category: { type: String, required: true },
  status: { type: String, required: true },
  dead_line: { type: Date, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Usuario creador
  group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group' }, // Grupo al que pertenece (opcional)
  assignedTo: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], // Miembros asignados
});
const Task = mongoose.model('Task', taskSchema, 'task');

// Modelo de Rol
const roleSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true }, //  "Admin", "Editor", "Viewer"
  permissions: { type: [String], default: [] }, // ["view_tasks", "edit_tasks"]
});
const Role = mongoose.model('Role', roleSchema);

// Modelo de Grupo
const groupSchema = new mongoose.Schema({
  name: { type: String, required: true }, // Nombre del grupo
  description: { type: String }, // Descripción del grupo
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Usuario que creó el grupo
  members: [
    {
      user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Usuario miembro
      role: { type: mongoose.Schema.Types.ObjectId, ref: 'Role' }, // Rol del usuario en el grupo
    },
  ],
  tasks: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Task' }], // Tareas compartidas en el grupo
});
const Group = mongoose.model('Group', groupSchema);

// Ruta para registrar usuario
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password || username.includes(' ') || email.includes(' ') || password.includes(' ')) {
    return res.status(200).json({ success: false, message: "Todos los campos son obligatorios y no deben contener espacios." });
  }

  try {
    const emailExists = await User.findOne({ email });
    if (emailExists) {
      return res.status(200).json({ success: false, message: "El correo ya está registrado." });
    }

    const usernameExists = await User.findOne({ username });
    if (usernameExists) {
      return res.status(200).json({ success: false, message: "El nombre de usuario ya está en uso." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword, last_login: moment().toDate() });
    await newUser.save();

    res.json({ success: true, message: "Usuario registrado exitosamente" });
  } catch (error) {
    console.error("Error en el servidor:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// Ruta para autenticar usuario
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(200).json({ success: false, message: "Credenciales incorrectas" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(200).json({ success: false, message: "Credenciales incorrectas" });
    }

    user.last_login = moment().toDate();
    await user.save();

    // Generar un token JWT que expira en 10 minutos
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '10m' });

    // Dentro de la ruta /login
    res.json({
      success: true,
      message: "Inicio de sesión exitoso",
      user: {
        id: user._id, // <-- Agregar esta línea
        username: user.username,
        email: user.email,
      },
      token
    });

  } catch (error) {
    console.error("Error en el servidor:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// Middleware para verificar el token en rutas protegidas
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(200).json({ success: false, message: "No se proporcionó un token." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId; // Agregar el userId decodificado al request
    next();
  } catch (error) {
    res.status(200).json({ success: false, message: "Token expirado o inválido." });
  }
};

// Rutas protegidas (ejemplo)
app.get('/protected', verifyToken, (req, res) => {
  res.json({ success: true, message: "Acceso autorizado", userId: req.userId });
});



// Obtener tareas del usuario actual
app.get('/tasks', verifyToken, async (req, res) => {
  try {
    const groupId = req.header('groupId');
    let query = {};

    if (groupId) {
      // Verificar si el usuario es el creador del grupo
      const group = await Group.findById(groupId);
      if (!group) {
        return res.status(200).json({ success: false, message: "Grupo no encontrado" });
      }

      // Si el usuario es el creador del grupo, mostrar todas las tareas del grupo
      if (group.createdBy.toString() === req.userId) {
        query.group = groupId;
      } else {
        // Si no es el creador, mostrar solo las tareas asignadas al usuario
        query = {
          group: groupId,
          $or: [
            { user: req.userId }, // Tareas creadas por el usuario
            { assignedTo: req.userId }, // Tareas asignadas al usuario
          ],
        };
      }
    } else {
      // Si no hay grupo, mostrar solo las tareas del usuario
      query = {
        user: req.userId,
        group: null, // Solo tareas sin grupo
      };
    }

    const tasks = await Task.find(query).sort({ dead_line: 1 });
    res.json({ success: true, tasks });
  } catch (error) {
    console.error("Error al obtener tareas:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// Crear tarea (puede ser en un grupo) o para solo un usuario
app.post('/tasks', verifyToken, async (req, res) => {
  try {
    const { groupId, assignedTo } = req.body;

    if (groupId) {
      // Verificar si el grupo existe
      const group = await Group.findById(groupId);
      if (!group) {
        return res.status(200).json({ success: false, message: "Grupo no encontrado" });
      }

      // Verificar si el usuario es miembro del grupo
      const isMember = group.members.some((member) => member.user.toString() === req.userId);
      if (!isMember) {
        return res.status(200).json({ success: false, message: "No eres miembro de este grupo" });
      }

      // Verificar si el usuario tiene permisos para crear tareas en el grupo
      const member = group.members.find((member) => member.user.toString() === req.userId);
      const role = await Role.findById(member.role);
      if (!role.permissions.includes("create_tasks")) {
        return res.status(200).json({ success: false, message: "No tienes permisos para crear tareas en este grupo" });
      }

      // Verificar que los miembros asignados pertenezcan al grupo
      if (assignedTo) {
        const invalidMembers = assignedTo.filter(
          (userId) => !group.members.some((member) => member.user.toString() === userId)
        );
        if (invalidMembers.length > 0) {
          return res.status(200).json({ success: false, message: "Algunos miembros asignados no pertenecen al grupo" });
        }
      }
    }

    // Crear la tarea
    const newTask = new Task({ ...req.body, user: req.userId });
    await newTask.save();

    // Si la tarea pertenece a un grupo, agregarla al grupo
    if (groupId) {
      await Group.findByIdAndUpdate(groupId, { $push: { tasks: newTask._id } });
    }

    res.json({ success: true, message: "Tarea creada con éxito", task: newTask });
  } catch (error) {
    console.error("Error al crear tarea:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});


// Actualizar tarea verificando pertenencia al grupo y rol del usuario
app.put('/tasks/:id', verifyToken, async (req, res) => {
  try {
    // Obtener la tarea por su ID
    const task = await Task.findOne({ _id: req.params.id });

    // Verificar si la tarea existe
    if (!task) {
      return res.status(200).json({ success: false, message: "Tarea no encontrada" });
    }

    // Verificar si la tarea pertenece a un grupo
    if (!task.group) {
      // Si la tarea no pertenece a un grupo, solo el creador puede modificarla
      if (task.user.toString() !== req.userId) {
        return res.status(200).json({ success: false, message: "No tienes permisos para actualizar esta tarea" });
      }
    } else {
      // Si la tarea pertenece a un grupo, verificar el rol del usuario en el grupo
      const group = await Group.findById(task.group);

      // Verificar si el grupo existe
      if (!group) {
        return res.status(200).json({ success: false, message: "Grupo no encontrado" });
      }

      // Buscar al usuario en los miembros del grupo
      const member = group.members.find((m) => m.user.toString() === req.userId);

      // Verificar si el usuario es miembro del grupo
      if (!member) {
        return res.status(200).json({ success: false, message: "No eres miembro de este grupo" });
      }

      // Obtener el rol del usuario en el grupo
      const role = await Role.findById(member.role);
      console.log(role.permissions);
      // Verificar si el rol tiene permisos para editar tareas
      if (!role.permissions.includes("edit_tasks")) {
        return res.status(200).json({ success: false, message: "No tienes permisos para actualizar esta tarea" });
      }else if (role.permissions.includes("view_tasks")) {
        /*
        if (Object.keys(req.body).length !== 1 || !req.body.status) {
          return res.status(200).json({ success: false, message: "Solo puedes modificar el estado de la tarea" });
        }
        */
      }
    }

    // Si el usuario tiene permisos, actualizar la tarea
    const updatedTask = await Task.findByIdAndUpdate(req.params.id, req.body, { new: true });

    // Responder con la tarea actualizada
    res.json({ success: true, message: "Tarea actualizada", task: updatedTask });
  } catch (error) {
    console.error("Error al actualizar tarea:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});



// Eliminar tarea verificando pertenencia
app.delete('/tasks/:id', verifyToken, async (req, res) => {
  try {
    const task = await Task.findOne({ _id: req.params.id, user: req.userId });
    if (!task) return res.status(200).json({ success: false, message: "Tarea no encontrada" });
    
    await Task.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Tarea eliminada" });
  } catch (error) {
    console.error("Error al eliminar tarea:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// Crear un nuevo grupo
app.post('/groups', verifyToken, async (req, res) => {
  try {
    const { name, description } = req.body;
    const newGroup = new Group({
      name,
      description,
      createdBy: req.userId,
      members: [{ user: req.userId, role: null }], // El creador es miembro por defecto
    });
    await newGroup.save();
    res.json({ success: true, message: "Grupo creado con éxito", group: newGroup });
  } catch (error) {
    console.error("Error al crear grupo:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// Agregar un usuario a un grupo
app.post('/groups/:groupId/add-member', verifyToken, async (req, res) => {
  try {
    const { userId, roleId } = req.body;
    const group = await Group.findById(req.params.groupId);
    if (!group) return res.status(200).json({ success: false, message: "Grupo no encontrado" });

    // Verificar si el usuario ya es miembro
    const isMember = group.members.some((member) => member.user.toString() === userId);
    if (isMember) {
      return res.status(200).json({ success: false, message: "El usuario ya es miembro del grupo" });
    }

    group.members.push({ user: userId, role: roleId });
    await group.save();
    res.json({ success: true, message: "Usuario agregado al grupo" });
  } catch (error) {
    console.error("Error al agregar miembro:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// Obtener todos los grupos de un usuario
app.get('/groups', verifyToken, async (req, res) => {
  try {
    const groups = await Group.find({ "members.user": req.userId }).populate("members.user").populate("members.role");
    res.json({ success: true, groups });
  } catch (error) {
    console.error("Error al obtener grupos:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// Obtener roles
app.get('/roles', verifyToken, async (req, res) => {
  try {
    const roles = await Role.find();
    res.json({ success: true, roles });
  } catch (error) {
    console.error("Error al obtener roles:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// Obtener tareas de un grupo
app.get('/groups/:groupId/tasks', verifyToken, async (req, res) => {
  try {
    const tasks = await Task.find({ group: req.params.groupId });
    res.json({ success: true, tasks });
  } catch (error) {
    console.error("Error al obtener tareas del grupo:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// Eliminar grupo
app.delete('/groups/:groupId', verifyToken, async (req, res) => {
  try {
    const group = await Group.findById(req.params.groupId);
    if (!group) {
      return res.status(200).json({ success: false, message: "Grupo no encontrado" });
    }

    // Verificar si el grupo tiene tareas asociadas
    const tasks = await Task.find({ group: req.params.groupId });
    if (tasks.length > 0) {
      return res.status(200).json({ success: false, message: "No se puede eliminar el grupo porque tiene tareas asociadas" });
    }

    await Group.findByIdAndDelete(req.params.groupId);
    res.json({ success: true, message: "Grupo eliminado" });
  } catch (error) {
    console.error("Error al eliminar grupo:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// Buscar usuario por username
app.get('/users', verifyToken, async (req, res) => {
  try {
    const { username } = req.query;
    if (!username) {
      return res.status(200).json({ success: false, message: "Se requiere un username" });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(200).json({ success: false, message: "Usuario no encontrado" });
    }

    res.json({ success: true, user });
  } catch (error) {
    console.error("Error al buscar usuario:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// Añadir un miembro a un grupo
app.post('/groups/:groupId/add-member', verifyToken, async (req, res) => {
  try {
    const { userId, roleId } = req.body;
    const groupId = req.params.groupId;

    // Verificar si el grupo existe
    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(200).json({ success: false, message: "Grupo no encontrado" });
    }

    // Verificar si el usuario ya es miembro del grupo
    const isAlreadyMember = group.members.some((member) => member.user.toString() === userId);
    if (isAlreadyMember) {
      return res.status(200).json({ success: false, message: "El usuario ya es miembro del grupo" });
    }

    // Añadir el nuevo miembro al grupo
    group.members.push({ user: userId, role: roleId });
    await group.save();

    res.json({ success: true, message: "Miembro añadido al grupo", group });
  } catch (error) {
    console.error("Error al añadir miembro:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// Eliminar un miembro de un grupo
app.delete('/groups/:groupId/remove-member/:userId', verifyToken, async (req, res) => {
  try {
    const { groupId, userId } = req.params;

    // Verificar si el grupo existe
    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(200).json({ success: false, message: "Grupo no encontrado" });
    }

    // Verificar si el usuario es miembro del grupo
    const memberIndex = group.members.findIndex((member) => member.user.toString() === userId);
    if (memberIndex === -1) {
      return res.status(200).json({ success: false, message: "El usuario no es miembro del grupo" });
    }

    // Eliminar el miembro del grupo
    group.members.splice(memberIndex, 1);
    await group.save();

    res.json({ success: true, message: "Miembro eliminado del grupo", group });
  } catch (error) {
    console.error("Error al eliminar miembro:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// Actualizar un grupo existente
app.put('/groups/:groupId', verifyToken, async (req, res) => {
  try {
    const { name, description, members } = req.body;
    const groupId = req.params.groupId;

    // Validar que el grupo exista
    const group = await Group.findById(groupId);
    if (!group) {
      return res.status(200).json({ success: false, message: "Grupo no encontrado" });
    }

    // Validar que el usuario que intenta actualizar el grupo sea el creador
    if (group.createdBy.toString() !== req.userId) {
      return res.status(200).json({ success: false, message: "No tienes permisos para actualizar este grupo" });
    }

    // Actualizar los campos del grupo
    group.name = name || group.name;
    group.description = description || group.description;
    group.members = members || group.members;

    await group.save();

    res.json({ success: true, message: "Grupo actualizado con éxito", group });
  } catch (error) {
    console.error("Error al actualizar grupo:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});


app.get('/groups/:groupId/members', verifyToken, async (req, res) => {
  try {
    const group = await Group.findById(req.params.groupId).populate("members.user");
    if (!group) {
      return res.status(200).json({ success: false, message: "Grupo no encontrado" });
    }

    // Filtrar miembros para excluir al administrador (creador del grupo)
    const members = group.members.filter(
      (member) => member.user._id.toString() !== group.createdBy.toString()
    );

    res.json({ success: true, members });
  } catch (error) {
    console.error("Error al obtener miembros del grupo:", error);
    res.status(500).json({ success: false, message: "Error en el servidor" });
  }
});

// Iniciar servidor
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(` Servidor corriendo en http://localhost:${PORT}`);
});
