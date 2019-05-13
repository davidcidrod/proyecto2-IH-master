const express = require('express')
const bcrypt = require('bcrypt')

const router = express.Router()

const User = require('../models/User')

const { requireAnon, requireUser, requireFields } = require('../middlewares/auth')

const uploadCloud = require('../config/cloudinary')

const saltRounds = 10

//ruta para el signup

//en el get le pasamos lo que debe renderizar en pantalla junto a su layout y data
router.get('/signup', (req, res, next) => {
  const data = {
    message: req.flash('validation')
  }
  res.render('auth/signup', { layout: 'layout-fullpage', data })
})

//post del signup
//requiere ser anonimo, pasamos una imagen por default, recojemos los datos y la foto de perfil si sube alguna.
router.post('/signup', requireAnon, uploadCloud.single('image-perfil'), async (req, res, next) => {
  const { name, mail, password, category } = req.body
  // const { url: imageProfile } = req.file
  let imageProfile
  let longitude = 41.154878
  let latitude = 2.14246
  if (req.file) {
    imageProfile = req.file.url
  }
  //buscamos que el nombre no este usado
  try {
    const result = await User.findOne({ name })
    if (result) {
      req.flash('validation', 'This name is taken')
      res.redirect('/auth/signup')
      return
    }
    //encriptamos y escondemos la contraseña
    const salt = bcrypt.genSaltSync(saltRounds)
    const hashedPassword = bcrypt.hashSync(password, salt)

    const newUser = {
      name,
      mail,
      password: hashedPassword,
      category,
      imageProfile,
      location: {
        type: 'Point',
        coordinates: [longitude, latitude]
      }
    }
    //creamos el nuevo usuario y le damos una sessión y redirijimos a categorias
    const createUser = await User.create(newUser)
    req.session.currentUser = createUser
    res.redirect('/categories')
  } catch (error) {
    next(error)
  }
})

//ruta del login

router.get('/login', requireAnon, (req, res, next) => {
  const data = {
    messages: req.flash('validation')
  }
  console.log(data)
  res.render('auth/login', data)
})
//post del login requiere que sea anonimo y que se rellenen todos los campos
router.post('/login', requireAnon, requireFields, async (req, res, next) => {
  const { mail, password } = req.body
//hacemos las comprobaciones de los campos
  if (!mail || !password) {
    res.redirect('/auth/login')
    return
  }
  try {
    const user = await User.findOne({ mail })
    if (!user) {
      req.flash('validation', 'User name or password are incorrect')
      res.redirect('/auth/login')

      return
    }
//si la contraseña es correcta redirijimos a categorias sino le damos un mensaje de fallo
    if (bcrypt.compareSync(password, user.password)) {
      req.session.currentUser = user
      res.redirect('/categories')
    } else {
      req.flash('validation', 'Username or password are incorrect')
      res.redirect('/auth/login')
      console.log('Fallo password')
    }
  } catch (error) {
    next(error)
  }
})
//logout, cerramos la sessión para ello requiere que este logeado
router.post('/logout', requireUser, async (req, res) => {
  delete req.session.currentUser

  res.redirect('/')
})

module.exports = router
