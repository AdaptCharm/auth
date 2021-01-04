/*
Manages users & login sessions.
+ NOTE REQUIRES A COOKIE PARSER & MONGO DATABASE.


Packages required:
+ ms
+ is_js
+ argon2
+ ua-parser-js
+ nanoid/generate
+ crypto (inbuilt)

*/


/********************************************* CONFIGURATION **********************************************/


const defaultMaxActive = "30 days"


const defaultResetKeyExpires = "1 day"


const hashConfig = {
  type: 2,
  timeCost: 3,
  saltLength: 28,
  memoryCost: 97656,
  hashLength: 73,
  parallelism: 1
}





/********************************************* SETUP FUNCTIONS **********************************************/


//Load required packages.
const ms = require("ms")
const is = require("is_js")
const argon2 = require("argon2")
const parser = require("ua-parser-js")
const nanoid = require("nanoid/generate")
const crypto = require("crypto")


//Export primary function.
module.exports = Auth
module.exports.users = {
  id: String,
  email: String,
  password: String,
  password_reset: {
    key: String,
    created: Date,
    done: Boolean
  }
}
module.exports.login_sessions = {
  id: String,
  status: String,
  user: String,
  last_active: Date,
  device: {
    type: {type: String},
    browser: String,
    os: String,
    country: String,
    ip: String,
    user_agent: String,
  }
}





/********************************************* PRIMARY FUNCTIONS **********************************************/


/*
The authentication handler class.
*/
function Auth(options = {}) {
  if(!(this instanceof Auth)) { return new Auth(...arguments) }
  options.maxLastActive = ms(options.maxLastActive || defaultMaxActive)
  options.resetKeyExpires = ms(options.resetKeyExpires || defaultResetKeyExpires)
  var users = options.db.users, login_sessions = options.db.login_sessions


  /********************** CORE FUNCTIONS **********************/


  /*
  Signs up a user.
  */
  this.signUp = async function(email, password, extra, req, res) {
    if(!email || !is.email(email)) { throw new Error("Please provide a valid email address") }
    if(!password || password.length < 6) { throw new Error("Please provide at least a 6 character long password") }
    email = String(email).toLowerCase()

    //Check if a user with this email already exists.
    if(await users.countDocuments({email: email}).limit(1)) {
      throw new Error("A user with this email already exists")
    }

    //Create a user.
    var user = {
      id: generate("usr_"),
      email: email,
      password: await argon2.hash(password, hashConfig),
    }
    if(extra) { user = Object.assign(user, extra) }
    await new users(user).save()

    //Create a login session & set details.
    return await createLoginSession(user, req, res)
  }



  /*
  Signs in a user.
  */
  this.signIn = async function(email, password, req, res) {
    if(!email || !is.email(email)) { throw new Error("Please provide a valid email address") }
    if(!password) { throw new Error("Please provide your password") }
    email = String(email).toLowerCase()

    //Fetch user from database.
    var user = await users.findOne({email: email}).sort({created: -1}).lean()
    if(!user || user.disabled) { throw new Error("No user with this email address exists") }

    //Validate password.
    if(!await argon2.verify(user.password, password)) {
      throw new Error("This password is incorrect")
    }

    //Create a login session & set details.
    return await createLoginSession(user, req, res)
  }



  /*
  Creates a password reset key to be emailed.
  */
  this.forgotPassword = async function(email) {
    if(!email || !is.email(email)) { throw new Error("Please provide a valid email address") }
    email = email.toLowerCase()

    //Get user and set a password reset key.
    var resetKey = generate("rst_key_")
    var user = await db.users.findOneAndUpdate({email: email}, {password_reset: {key: resetKey, created: new Date(), done: false}}, {new: true})
    if(!user) { return res.status(400).json({error: "No user with this email address exists"}) }

    return {resetKey, user}
  }



  /*
  Resets the password using the password reset key.
  */
  this.resetPassword = async function(key, newPassword, req, res) {
    if(!key) { throw new Error("This password reset link has expired. Please request another.") }
    if(!newPassword || newPassword.length < 6) { throw new Error("Please provide at least a 6 character long password") }

    //Get user & make sure key hasn't expired.
    var user = await db.users.findOne({"password_reset.key": req.body.key, "password_reset.done": false})
    if(!user || (new Date() - user.password_reset.created) > options.resetKeyExpires) { throw new Error("This password reset link has expired. Please request another.") }

    //Update password.
    newPassword = await argon2.hash(newPassword, hashConfig)
    await db.users.updateOne({id: user.id}, {password: newPassword, "password_reset.done": true})
    user.password = newPassword, user.password_reset.done = true

    return await createLoginSession(user, req, res)
  }



  /*
  Changes a password.
  */
  this.changePassword = async function(userID, newPassword, req, res) {
    if(!userID && req && req.user) { userID = req.user.id }
    if(!userID) { throw new Error("Please sign in first") }
    if(!newPassword || newPassword.length < 6) { throw new Error("Please provide at least a 6 character long password") }

    //Set the new password.
    newPassword = await argon2.hash(newPassword, hashConfig)
    await users.updateOne({id: userID}, {password: newPassword}).sort({created: -1})
    if(req && req.user && userID == req.user.id) { req.user.password = newPassword }

    return true
  }



  /*
  Creates a login session post sign up or sign in.
  */
  var createLoginSession = async function(user, req, res) {

    //Create a login session & save it.
    var parsed = (req ? parser(req.headers["user-agent"]) : false)
    var ssn = {
      id: generate("ssn_"),
      status: "active",
      user: user.id,
      last_active: new Date(),
      device: {
        type: (parsed && parsed.device && parsed.device.type) || "desktop",
        browser: parsed && parsed.browser && parsed.browser.name,
        os: parsed && parsed.os && parsed.os.name,
        country: req && req.headers["cf-ipcountry"],
        ip: req && (req.headers["cf-connecting-ip"] || req.ip),
        user_agent: req && req.headers["user-agent"],
      }
    }
    await new login_sessions(ssn).save()

    //Set session cookie & info.
    if(res) {
      if(res.cookies && res.cookies.set) { res.cookies.set("ssn", ssn.id) }
      else if(res.cookie) { res.cookie("ssn", ssn.id, {maxAge: 3.154e+10, path: "/"}) }
    }
    if(req) { req.session = req.ssn = ssn, req.user = user }

    return {user, session: ssn}
  }
  this.createLoginSession = createLoginSession



  /*
  Signs out a user.
  */
  this.signOut = async function(sessionID, req, res) {
    if(req && req.ssn && !sessionID) { sessionID = req.ssn.id }
    if(!sessionID) { return true }

    //Update session status.
    await login_sessions.updateOne({id: sessionID}, {status: "signed_out"}).sort({created: -1})

    //Delete session cookie & data.
    if(res) {
      if(res.cookies && res.cookies.delete) { res.cookies.delete("ssn") }
      else { res.clearCookie("ssn", {path: "/"}) }
    }
    delete req.ssn; delete req.session; delete req.user

    return true
  }



  /*
  Authenticates a login session.
  */
  this.authenticate = async function(sessionID, cookieNotSigned, req, res) {
    if(!sessionID && req && (req.cookies || req.signedCookies)) { sessionID = (cookieNotSigned ? req.cookies.ssn : req.signedCookies.ssn) }
    if(!sessionID) { throw new Error("Not signed in") }

    //Get session & update last active.
    var ssn = await login_sessions.findOneAndUpdate({id: sessionID, status: "active"}, {last_active: new Date()}, {new: false}).sort({created: -1}).lean()
    if(!ssn || !ssn.user || (new Date() - ssn.last_active) > options.maxLastActive) {

      //Sign out user if last active is older than max.
      if(ssn && ssn.last_active && (new Date() - ssn.last_active) > options.maxLastActive) {
        await login_sessions.updateOne({id: sessionID}, {status: "signed_out", last_active: ssn.last_active}).sort({created: -1}).lean()
      }

      //Remove session cookie & throw error.
      if(res) {
        if(res.cookies && res.cookies.delete) { res.cookies.delete("ssn") }
        else { res.clearCookie("ssn", {path: "/"}) }
      }

      throw new Error("Not signed in")
    }

    //Get user.
    var user = await users.findOne({id: ssn.user}).sort({created: -1}).lean()
    if(!user || user.disabled) {
      //Remove session cookie & throw error.
      if(res) {
        if(res.cookies && res.cookies.delete) { res.cookies.delete("ssn") }
        else { res.clearCookie("ssn", {path: "/"}) }
      }

      throw new Error("Not signed in")
    }

    if(req) { req.session = req.ssn = ssn, req.user = user }
    return {user, session: ssn}
  }





  /********************** APP FUNCTIONS **********************/


  /*
  Handles authentication for express.
  */
  var auth = this
  this.app = function(options = {}) {
    return async function(req, res, next) {
      try {

        //Create copy of auth functions.
        req.auth = {
          signIn: function(email, password) { return auth.signIn(email, password, req, res) },
          signUp: function(email, password, extra) { return auth.signUp(email, password, extra, req, res) },
          signOut: function(sessionID) { return auth.signOut(sessionID, req, res) },
          forgotPassword: function(email) { return auth.forgotPassword(email) },
          resetPassword: function(key, newPassword) { return auth.resetPassword(key, newPassword, req, res) },
          changePassword: function(newPassword, userID) { return auth.changePassword(userID, newPassword, req, res) },
          authenticate: function(sessionID) { return auth.authenticate(sessionID, options.cookieNotSigned, req, res) },
          createLoginSession: function(user) { return auth.createLoginSession(user, req, res) }
        }

        //Try signing in.
        var cookie = (req.signedCookies && req.signedCookies.ssn), signedIn = false
        if(options.cookieNotSigned) { cookie = req.cookies && req.cookies.ssn }
        if(cookie) {
          try {
            await req.auth.authenticate()
            signedIn = true
          } catch (e) {}
        }

        //Pass execution to signed out function if one exists.
        if(!signedIn && options.signedOut) {
          return options.signedOut(req, res, next)
        }

        next()
      }
      catch (e) { next(e) }
    }
  }


}





/********************************************* HELPER FUNCTIONS **********************************************/


/*
Generates random IDs.
*/
function generate(prefix = "", min, max) {
  var length = {min: min || 21, max: max || 29}
  if(["key_", "ssn_", "nonce_"].includes(prefix)) { length = {min: 30, max: 38} }
  else if(prefix == "rst_key_") { length = {min: 60, max: 80} }
  if(min) { length.min = min }
  if(max) { length.max = max }

  var random = parseInt(crypto.randomBytes(8).toString("hex"), 16) / Math.pow(2, 64)
  var randomLength = Math.floor(random * (length.max - length.min + 1) + length.min)
  return prefix + nanoid("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", randomLength)
}
