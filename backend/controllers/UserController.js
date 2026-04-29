const User = require('../models/User')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const createUserToken = require('../helpers/create-user-token')
const getTokens = require('../helpers/get-tokens')
const { decode } = require('jsonwebtoken')

module.exports = class UserController {
    static async register(req, res) {
      const{name,email,phone,password,confirmpassword} = req.body
      if(!name){
        res.status(422).json({message: 'Nome é obrigatório'})
        return
      }
      if(!email){
        res.status(422).json({message:'Email é obrigatório'})
        return
      }
      if(!phone){
        res.status(422).json({message: 'Telefone é obrigatório'})
        return
      }
      if(!password){
        res.status(422).json({message: 'Senha é obrigatória'})
        return
      }
      if(!confirmpassword){
        res.status(422).json({message: 'Confirmar a senha é obrigatório'})
        return
      }
      if(password !== confirmpassword){
        res.status(422).json({message:'As senhas não batem'})
        return
      }
      const userExists = await User.findOne({email : email})

      if(userExists){
        res.status(422).json({message: 'O usuário já existe em nossos registros'})
        return
      }

      const salt = await bcrypt.genSalt(12)
      const passwordHash = await bcrypt.hash(password, salt)

      const user = new User({
        name,
        email,
        phone,
        password:passwordHash
      })

      try {
        const newUser = await user.save()
        await createUserToken(newUser, req, res)
      } catch (error) {
        res.status(503).json({message:error})
      }
    }

    static async login(req, res){
      const{email, password} = req.body

      if(!email){
        res.status(422).json({message:'Email é obrigatório'})
        return
      }

      if(!password){
        res.status(422).json({message: 'Senha é obrigatória'})
        return
      }
      const userExists = await User.findOne({email:email})

      if(!userExists){
        res.status(401).json({message:'Não autorizado, sem registro'})
        return
      }

      const checkPassword = await bcrypt.compare(password, userExists.password)

      if(!checkPassword){
        res.status(401).json({message:'Não autorizado, sem registro'})
        return
      }

      await createUserToken(userExists, req, res)
    }

    static async checkUser(req,res){
      let currentUser

      console.log(req.headers.authorization)

      if(req.headers.authorization){
        const token = getToken(req)
        const decodedToken = jwt.verify(token, 'fatec-turma6-a2026')
       
        currentUser = await User.findById(decode.id)
        currentUser.password = undefined
      }else{
        currentUser = null
      }

      res.status(200).send(currentUser)
    }

    static async getUserByID(req, res){
      const id = req.params.id

      const user = await User.findById(id)

      if(!user){
        res.status(404).json({message: 'Usuário não encontrado'})
        return
      }

      res.status(200).json(user)
    }

    static async editUser(req,res){
      res.status(200).json({message:'Usuário atualizado com sucesso'})
    }
}

