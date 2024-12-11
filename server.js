// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const helmet = require('helmet');
const { check, validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');
const mongoose = require('mongoose');
const NodeCache = require('node-cache');
const sanitizer = require('sanitizer');
const winston = require('winston');
const expressWinston = require('express-winston');
const compression = require('compression');
const responseTime = require('response-time');
const hpp = require('hpp');
const { v4: uuidv4 } = require('uuid');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');
const helmetCsp = require('helmet-csp');
const csurf = require('csurf');
require('express-async-errors');

const app = express();
const cache = new NodeCache({ stdTTL: 60 }); // Cache with TTL of 60 seconds

// Security Middlewares
app.use(cors({ origin: 'https://yourdomain.com' })); // Adjust CORS settings as needed
app.use(helmet());
app.use(helmetCsp({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", 'https:', "'unsafe-inline'"],
    imgSrc: ["'self'", 'data:', 'https:'],
    connectSrc: ["'self'", 'https://api.yourdomain.com']
  }
}));
app.use(hpp()); // HTTP parameter pollution protection
app.use(compression()); // Response compression
app.use(responseTime()); // Track response times

// CSRF protection
const csrfProtection = csurf({ cookie: true });
app.use(csrfProtection);

// Logging Middleware
app.use(morgan('combined'));

// Winston Logging Configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.colorize(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

app.use(expressWinston.logger({
  winstonInstance: logger,
  meta: true,
  msg: "HTTP {{req.method}} {{req.url}}",
  expressFormat: true,
  colorize: false,
}));

// Body Parser Middleware
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => logger.info('MongoDB connected'))
  .catch(err => logger.error('MongoDB connection error:', err));

// Define a simple Todo schema
const todoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true }
});

const Todo = mongoose.model('Todo', todoSchema);

// Rate Limiter Middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again after 15 minutes'
});
app.use(limiter);

// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Middleware to Check Authentication
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).send('Access denied. No token provided.');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (ex) {
    res.status(400).send('Invalid token.');
  }
};

// Create Todo
app.post('/todos', authenticateJWT, [
  check('title').isLength({ min: 1 }).withMessage('Title is required'),
  check('description').isLength({ min: 1 }).withMessage('Description is required')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { title, description } = req.body;
  const sanitizedTitle = sanitizer.escape(title);
  const sanitizedDescription = sanitizer.escape(description);

  const todo = new Todo({
    title: sanitizedTitle,
    description: sanitizedDescription
  });

  todo.save()
    .then(savedTodo => res.status(201).json(savedTodo))
    .catch(err => res.status(500).json({ error: err.message }));
});

// Read Todo
app.get('/todos/:id', authenticateJWT, (req, res) => {
  const todoId = req.params.id;

  // Check Cache First
  const cachedTodo = cache.get(todoId);
  if (cachedTodo) {
    return res.json(cachedTodo);
  }

  Todo.findById(todoId)
    .then(todo => {
      if (!todo) return res.status(404).send('Todo not found');
      cache.set(todoId, todo); // Cache the Result
      res.json(todo);
    })
    .catch(err => res.status(500).json({ error: err.message }));
});

// Update Todo
app.put('/todos/:id', authenticateJWT, [
  check('title').isLength({ min: 1 }).withMessage('Title is required'),
  check('description').isLength({ min: 1 }).withMessage('Description is required')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { title, description } = req.body;
  const sanitizedTitle = sanitizer.escape(title);
  const sanitizedDescription = sanitizer.escape(description);

  Todo.findByIdAndUpdate(req.params.id, { title: sanitizedTitle, description: sanitizedDescription }, { new: true })
    .then(updatedTodo => {
      if (!updatedTodo) return res.status(404).send('Todo not found');
      cache.set(req.params.id, updatedTodo); // Update the Cache
      res.json(updatedTodo);
    })
    .catch(err => res.status(500).json({ error: err.message }));
});

// Delete Todo
app.delete('/todos/:id', authenticateJWT, (req, res) => {
  Todo.findByIdAndDelete(req.params.id)
    .then(deletedTodo => {
      if (!deletedTodo) return res.status(404).send('Todo not found');
      cache.del(req.params.id); // Remove from Cache
      res.status(204).send();
    })
    .catch(err => res.status(500).json({ error: err.message }));
});

// User Login Route
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // In a real application, you'd verify the username and password from a database
  if (username === 'user' && password === 'password') {
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).send('Invalid username or password');
  }
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(500).send('Something broke!');
});

// Setup health check endpoint
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// OpenAPI Documentation Middleware
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server is running on port ${PORT}`);
});

app.get('/', (req, res) => {
  res.send('Hello, world!');
});
