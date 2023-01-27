const passport = require('passport')
const bcrypt =require('bcrypt')

const LocalStrategy = require('passport-local').Strategy

async function initialize(passport, getUserByName,getUserById) {
    const authenticateUser = (name, password, done) => {
        const user = getUserByName(name)
        if (user == null) {
            return done(null, false, { message: 'Wrong Password !' })
        }

        try {
            if (password==user.password) {
                return done(null, user)
            }
            else {
                return done(null, false, { message: 'Wrong Password !' })
            }
        } catch (e) {
            return done(e);
        }
    }
    passport.use(new LocalStrategy({ usernameField: 'name' }, authenticateUser))
    passport.serializeUser((user, done) => done(null,user.id))
    passport.deserializeUser((id, done) =>{ return done(null,getUserById(id))})
}


module.exports= initialize
