const User = require('../models/User')
const bcrypt = require('bcrypt')
const createUserToken = require('../helpers/create-user-token')

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
}

