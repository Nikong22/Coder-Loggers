const util = require('util');
const {normalize, schema} = require('normalizr');
const express = require('express');
const handlebars = require('express-handlebars');
const mongoose = require('mongoose');
const generador = require('./generador/productos');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const advancedOptions = {useNewUrlParser: true, useUnifiedTopology: true};
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const routes = require('./routes'); 
const {obtenerUsuario, obtenerUsuarioId, passwordValida} = require('./utils/util');
const bCrypt = require('bCrypt');
const FacebookStrategy = require('passport-facebook').Strategy;
const {fork} = require('child_process');
const cluster = require('cluster');
const winston = require('winston')
const compression = require('compression')


//Para convertir en HTTPS
//const https = require('https');
const fs = require('fs'); 
const httpsOptions = {
    key: fs.readFileSync('./sslcert/cert.key'),
    cert: fs.readFileSync('./sslcert/cert.pem')
}


const app = express();
let PORT = 8080;
const router = express.Router();
const http = require('http').Server(app);
const io = require('socket.io')(http);
const usuarios = [];
let FORK_O_CLUSTER = 'FORK'

const variablesFacebook = {
  clientID: '4623989377730633',
  clientSecret: '093f6bb8b562debced4c4de04697dd42'
}


app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(compression())
app.use('/api', router);
const cookieParser = require('cookie-parser');
app.use(cookieParser("clave-secreta"));

app.use(session({
  store: MongoStore.create({
      mongoUrl: 'mongodb+srv://nikong:nikong22!@cluster0.z6il9.mongodb.net/myFirstDatabase?retryWrites=true&w=majority',
      mongoOptions: advancedOptions
  }),
  secret: 'secreto',
  resave: false,
  saveUninitialized: false,
   cookie: { maxAge: 10000 }
}));

app.use(passport.initialize());
app.use(passport.session());

app.use('/', (req, res, next) => {
  if (req.isAuthenticated()) {
    const username = req.user.name ? req.user.name : req.user.username
    const avatar = req.user.avatar
    res.cookie('username', username,  { signed: false, maxAge: 5000 } );
    res.cookie('avatar', avatar,  { signed: false, maxAge: 5000 } );
  }
  express.static('public')(req, res, next);
});

const productos = [

];

const mensajes = [

];

const chat = {
  id: 123,
  mensajes: mensajes
};

function print(objeto) {
  logger.info(util.inspect(objeto,false,12,true))
}

const URI = 'mongodb://localhost:27017/comercio';

const MensajeSchema = mongoose.Schema({
  autor: {
      id: String,
      nombre: String,
      apellido: String,
      edad: Number,
      alias: String,
      avatar: String
  },
  texto: {type: String, require: true, minLength: 1, maxLength: 25},
  fecha: {type: String, require: true, minLength: 1},
});
const MensajeDB = mongoose.model('mensajes', MensajeSchema)

mongoose.connect(URI, 
    { 
      serverSelectionTimeoutMS: 1000
    }, 
    (error) => {
        if (error) {
            throw  'Error al conectarse a la base de datos';
        } else {
          ProductoDB.find({})
          .then((productosDB) => {
            for (let producto of productosDB) {
              productos.push(producto)
            }
            // console.log(productos)
          })
          MensajeDB.find({})
          .then((mensajesDB) => {
            for (let mensaje of mensajesDB) {
                mensajes.push(mensaje)
            }
          })
        }
  });

  const ProductoSchema = mongoose.Schema({
    id: {type: Number, require: true},
    title: {type: String, require: true, minLength: 1, maxLength: 50},
    price: {type: String, require: true, minLength: 1, maxLength: 25},
    thumbnail: {type: String, require: true, minLength: 1},
  });
  const ProductoDB = mongoose.model('productos', ProductoSchema)

  const UserSchema = mongoose.Schema({
    id: {type: Number, require: true},
    username: {type: String, require: false, minLength: 1, maxLength: 20},
    password: {type: String, require: false, minLength: 1},
    name: {type: String, require: false, minLength: 1},
    avatar: {type: String, require: false, minLength: 1},
  });
  const User = mongoose.model('usuarios', UserSchema)

/*  const UsuarioSchema = mongoose.Schema({
    usuario: {type: String, require: true, minLength: 1, maxLength: 20},
    email: {type: String, require: true, minLength: 1},
    photo: {type: String, require: true},
  });
  const User = mongoose.model('usuarios', UsuarioSchema)*/

  const infoAndWarnFilter = winston.format((info, opts) => { 
    return info.level === 'info' || info.level === 'warn' ? info : false
  })
  const logger = winston.createLogger({
    level: 'error',
    transports: [
      new winston.transports.Console({level:'verbose'}),
      new winston.transports.File({filename:'error.log', level: 'error'}),
      new winston.transports.File({filename:'warn.log', level: 'warn', format: winston.format.combine(
        infoAndWarnFilter(),
        winston.format.timestamp(),
        winston.format.printf(i => {
          return `${i.level.toUpperCase()}: ${i.timestamp} ${i.message}`;
        })
      )}),
    ]
  })
  
  logger.log('silly', "127.0.0.1 - log silly")
  logger.log('debug', "127.0.0.1 - log debug")
  logger.log('verbose', "127.0.0.1 - log verbose")
  logger.log('info', "127.0.0.1 - log info")
  logger.log('warn', "127.0.0.1 - log warn")
  logger.log('error', "127.0.0.1 - log error")
  
  logger.info("127.0.0.1 - log info 2")
  logger.warn("127.0.0.1 - log warn 2")
  logger.error("127.0.0.1 - log error 2")

router.get('/', (req,res)=>{
  const objRes = 
  {msg: "Sitio principal de productos"};
  res.json(objRes);
});

router.get("/productos/listar", (req, res) => {
    if (productos.length = 0) {
        return res.status(404).json({ error: "no hay productos cargados" });
      }
    ProductoDB.find({})
    .then((productosDB) => {
      for (let producto of productosDB) {
        productos.push(producto)
      }
      logger.info(productos)
      res.json(productos);
    })
});
  
router.get("/productos/listar/:id", (req, res) => {
    const { id } = req.params;
    const producto = productos.find((producto) => producto.id == id);
    if (!producto) {
        return res.status(404).json({ error: "producto no encontrado" });
      }
    res.json(producto);
});
  
router.put("/productos/actualizar/:id", (req, res) => {
  const { id } = req.params;
  let { title, price, thumbnail } = req.body;
  let producto = productos.find((producto) => producto.id == id);
  if (!producto) {
    return res.status(404).json({ msg: "Usuario no encontrado" });
  }
  (producto.title = title), (producto.price = price), (producto.thumbnail = thumbnail);
ProductoDB.updateOne({ "_id": id}, {'title': title, 'price': price, 'thumbnail':thumbnail})
.then(productos=>{
    logger.info('Producto acutalizado')
    res.status(200).json(producto);
})
});

router.delete("/productos/borrar/:id", (req, res) => {
  const { id } = req.params;
  const producto = productos.find((producto) => producto.id == id);

  if (!producto) {
    return res.status(404).json({ msg: "Usuario no encontrado" });
  }

  const index = productos.findIndex((producto) => producto.id == id);
  productos.splice(index, 1);
      ProductoDB.deleteOne({id: id})
      .then(()=>{
        logger.info('producto borrado')
        })
    res.status(200).end();
});

app.engine(
    "hbs",
    handlebars({
        extname: ".hbs",
        defaultLayout: "index.hbs",
        layoutsDir: __dirname + "/views/layouts",
        partialsDir: __dirname + "/views/partials"
    })
);

app.set('views', './views'); // especifica el directorio de vistas
app.set('view engine', 'hbs'); // registra el motor de plantillas

app.get('/productos/vista', function(req, res) {
  logger.info(productos)
  let tieneDatos;
  if(productos.length > 0){
    tieneDatos = true
  }else{
    tieneDatos = false
  }
  res.render('main', { productos: productos, listExists: tieneDatos });
});

io.on('connection', (socket) => {
  logger.info('alguien se está conectado...');
    
    io.sockets.emit('listar', productos);
    
    socket.on('notificacion', (titulo, precio, imagen) => {
      const producto = {
        title: titulo,
        price: precio,
        thumbnail: imagen,
      };

      logger.info(producto)

      ProductoDB.create(producto,(error, productoDB)=>{
        if (error) {
            throw "Error al grabar productos " + error;
        } else {
          productos.push(productoDB);
          io.sockets.emit('listar', productos)
        }
      });
    })
    
    logger.info('normalizr:')
    logger.info(mensajes)

    const mensajeSchema = new schema.Entity('mensajes');

    const chatSchema = new schema.Entity('chat',{
        mensajes: [mensajeSchema]
    });
    
    const normalizedChat = normalize(chat, chatSchema);
    
    // print(normalizedChat);
    logger.info('Longitud antes de normalizar:', JSON.stringify(chat).length);
    logger.info('Longitud después de normalizar:', JSON.stringify(normalizedChat).length);
    io.sockets.emit('mensajes', mensajes, JSON.stringify(chat).length, JSON.stringify(normalizedChat).length);
        
    socket.on('nuevo', (mensaje)=>{
      MensajeDB.insertMany(mensaje,(error)=>{
        if (error) {
            throw "Error al grabar mensajes " + error;
        } else {
          mensajes.push(mensaje);

          logger.info('Longitud antes de normalizar:', JSON.stringify(chat).length);
          logger.info('Longitud después de normalizar:', JSON.stringify(normalizedChat).length);
          io.sockets.emit('mensajes', mensajes, JSON.stringify(chat).length, JSON.stringify(normalizedChat).length);
          logger.info(`Mensajes grabados...`);
        }
      });
  })
});

//FAKER
app.get('/productos/vista-test', (req,res)=>{
  let productos = [];
  let cant = req.query.cant || 10;
  if (cant == 0) {
    return res.status(404).json({ error: "no hay productos cargados" });
  }
  for (let i=0; i<cant; i++) {
      let producto = generador.get();
      producto.id = i + 1;
      productos.push(producto);
  }
 
  res.send(productos);
});

app.post('/doInicio', (req,res)=>{
  const username = req.body.usuario
  logger.info(req.body);
  logger.info(req.params);
  logger.info(req.query);
  res.cookie('username', username,  { signed: false, maxAge: 5000 } );
  res.redirect('/');
});

//login
app.get('/inicio', (req,res)=>{
  res.render('inicio');
});
app.get('/salir', (req,res)=>{
  const username = req.cookies.username
  res.clearCookie('username');
  res.render('salir', { username: username });
});

//session
app.get('/con-session', (req,res)=>{
  if (req.session.contador) {
      req.session.contador++;
      res.send(`Ud. ha visitado el sitio ${req.session.contador} veces`);
  } else {
      req.session.contador = 1;
      res.send('Bienvenido!');
  }
});

app.get('/logout-session', (req,res)=>{
  req.session.destroy(err=>{
      if (err){
          res.json({status: 'Logout error', body: err});
      } else {
          res.send('Logout ok!');
      }
  });
});

//passport

passport.use('login', new LocalStrategy({
  passReqToCallback: true
},
  function(req, username, password, done){
    User.findOne({ 'username' : username },
      function (err, user){
        if (err)
          return done(err);
        if (!user){
          logger.error('user not found ' +username);
          return done(null, false,
            logger.error('message', 'user not found'));
          }
        if(!isValidPassword(user, password)){
          logger.error('Invalid password');
          return done (null, false,
            logger.error('mensage', 'Invalid Password'));
          }
        return done (null, user);
      }
     );
    })
  );

  const isValidPassword = function(user, password){
    return bCrypt.compareSync(password, user.password);
  }
  
passport.use('signup', new LocalStrategy({
    passReqToCallback: true
  },
  function (req, username, password, done){
    findOrCreateUser = function(){
      User.findOne({'username' : username}, function(err, user) {
        if (err){
          logger.error('Error en SignUp: ' +err);
          return done(err);
        }
        if (user) {
          logger.warn('User already exists');
          return done (null, false,
            logger.warn('message', 'User Already Exists'));
        } else {
          var newUser = new User();
          newUser.username = username;
          newUser.password = createHash(password);
          newUser.email = req.body.email;
          newUser.firstName = req.body.firstName;
          newUser.lastName = req.body.lastName;
          newUser.save(function(err){
            if (err){
              logger.error('Error in Saving user: '+err);
              throw err;
            }
            logger.info('User Registration succesful');
            return done(null, newUser);
          });
        }
      });
    }
    process.nextTick(findOrCreateUser);
  })
)
var createHash = function(password){
  return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
}
  

/*passport.serializeUser(function(user, done) {
  done(null, user._id);
});*/
  
/*passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user){
    done(err, user);
  });
});*/
  

app.get('/test', (req,res)=>{
    res.send('Server levantado...');
});

app.get('/login', routes.getLogin);
app.post('/login', passport.authenticate('login', {failureRedirect: '/faillogin'}), routes.postLogin);
app.get('/faillogin', routes.getFailLogin);

app.get('/signup', routes.getSignUp);
app.post('/signup', passport.authenticate('signup', {failureRedirect: '/failsignup'}), routes.postSignUp);
app.get('/failsignup', routes.getFailSignUp);

app.get('/logout', routes.getLogout);

app.get('/ruta-protegida', checkAuthentication, routes.getRutaProtegida);

app.get('/datos', routes.getDatos);


function checkAuthentication(req, res, next){
    if (req.isAuthenticated()){
        next();
    } else {
        res.redirect('/');
    }
}

//facebook

passport.use(new FacebookStrategy({
  clientID: variablesFacebook.clientID,
  clientSecret: variablesFacebook.clientSecret,
  callbackURL: `https://localhost:${PORT}/auth/facebook/data`,
  profileFields: ['id', 'displayName', 'picture.type(large)', 'email', 'birthday', 'friends', 'first_name', 'last_name', 'middle_name', 'gender', 'link']
},
function(accessToken, refreshToken, profile, cb) {
    let indice = usuarios.findIndex(e=>e.id == profile.id);
    if (indice == -1) {
      let newUser = User.findOne({ 'id' : profile.id },
        function (err, user){
          if (err)
            return done(err);
          if (!user){
            let newUser = new User();
            newUser.id = profile.id;
            newUser.name = profile.displayName;
            newUser.avatar = profile.photos[0].value;
            newUser.save(function(err){
              if (err){
                logger.error('Error in Saving user: '+err);
                throw err;
              }
              logger.info('User Registration succesful');
            });
            usuarios.push(newUser);
            user = newUser
          }
          return cb(null, user);
        }
      );
      // console.log('prueba')
       logger.info(newUser)
      // return cb(null, newUser);
    } else {
      logger.info('encontré', usuarios[indice]);
        return cb(null, usuarios[indice])
    }
}
)
);

logger.info(variablesFacebook)
process.argv.forEach((val, index) => {
  if(index == 2){//PORT
    logger.info(`PORT: ${val}`)
    PORT = val
  }
  if(index == 3){//FACEBOOK_CLIENT_ID
    logger.info(`FACEBOOK_CLIENT_ID: ${val}`)
    variablesFacebook.clientID = val
  }
  if(index == 4){//FACEBOOK_CLIENT_SECRET
    logger.info(`FACEBOOK_CLIENT_SECRET: ${val}`)
    variablesFacebook.clientSecret = val
  }
  if(index == 5){//FORK_O_CLUSTER
    logger.info(`FORK_O_CLUSTER: ${val}`)
    FORK_O_CLUSTER = val
  }
})
logger.info(variablesFacebook)


let server;

const numCPUs = require('os').cpus().length
if(FORK_O_CLUSTER == 'FORK'){
  //server = https.createServer(httpsOptions, app).listen(PORT, () => { console.log('Server corriendo en ' + PORT) })
  server = http.listen(PORT, () => logger.info(`escuchando en puerto ${PORT}`));
}else{
  if(cluster.isMaster){
    logger.info(`master ${process.pid} running`)
    for(let i = 0; i < numCPUs; i++){
      cluster.fork()
    }
  
    cluster.on('exit', (worker, code, signal) => {
      logger.info(`worker ${worker.process.pid} died`)
    })
  }else{
    logger.info(`worker ${process.pid} started`)
  
    //server = https.createServer(httpsOptions, app).listen(PORT, () => { console.log('Server corriendo en ' + PORT) })
    server = http.listen(PORT, () => logger.info(`escuchando en puerto ${PORT}`));
  }
}

passport.serializeUser((user, done)=>{
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  logger.info('deserializeUser')
  logger.info(id)
  let usuario = usuarios[usuarios.findIndex(e=>e.id == id)];
  logger.info(usuario)
  if(usuario){
    done(null, usuario);
  }else{
    User.findById(id, function(err, user){
      done(err, user);
    });
  }
});


app.get('/auth/facebook',
passport.authenticate('facebook'));

app.get('/auth/facebook/data', passport.authenticate('facebook', { failureRedirect: '/error-login.html' }),
  function(req, res) {
    // Successful authentication, redirect home.
    logger.info('facebook data')
    logger.info(req.user)
    res.cookie('username', req.user.name,  { signed: false, maxAge: 5000 } );
    res.cookie('avatar', req.user.avatar,  { signed: false, maxAge: 5000 } );
    res.redirect('/index.html');
  }
);

app.get('/data', (req,res) => {
  if (req.isAuthenticated()) {
      let user = req.user;
      res.json({user});
  } else {
      res.redirect('/index.html');
  }
});

app.get('/randoms', (req,res) => {
  const cant = req.query.cant ? req.query.cant : 100000000
  logger.info(`cantidad: ${cant}`)
  const computo = fork('./random.js');
  computo.send(cant);
  computo.on('message', valores => res.end(mostrarValores(valores)));
});

const mostrarValores = (valores) => {
  let resultado = ''
  for (const valor of Object.entries(valores)) {
    resultado += valor[0] + ': ' + valor[1] + '\n'
  }
  return resultado
}

app.get('/comprobar', (req,res) => {
  res.json('no se bloquea');
});

app.get('/info', (req,res) => {
  const argumentos = []
  process.argv.forEach((val, index) => {
    if(index > 1){
      argumentos.push(val)
    }
  })
  res.json(`argumentos de entrada: ${argumentos} - S.O.: ${process.platform} - Version Node ${process.version} - Uso memoria: ${process.memoryUsage()} - Path: ${process.cwd()} - Process ${process.pid} - Carpeta ${process.cwd()} - Procesadores ${numCPUs}` )
  
});

app.get('*', routes.failRoute);