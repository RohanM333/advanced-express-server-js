// controllers/todoController.js
const Joi = require('joi');
const { validationResult } = require('express-validator');
const sanitizer = require('sanitizer');
const NodeCache = require('node-cache');
const Todo = require('../models/todo');

const cache = new NodeCache({ stdTTL: 60 });

const todoSchema = Joi.object({
  title: Joi.string().min(1).required(),
  description: Joi.string().min(1).required(),
});

const createTodo = async (req, res) => {
  const { error } = todoSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ errors: error.details });
  }

  const { title, description } = req.body;
  const sanitizedTitle = sanitizer.escape(title);
  const sanitizedDescription = sanitizer.escape(description);

  const todo = new Todo({
    title: sanitizedTitle,
    description: sanitizedDescription
  });

  try {
    const savedTodo = await todo.save();
    res.status(201).json(savedTodo);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// ... (rest of the controller functions)

module.exports = {
  createTodo,
  getTodo,
  updateTodo,
  deleteTodo
};
