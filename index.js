//Define the include function for absolute file name
global.base_dir = __dirname;
global.abs_path = function(path) {
	return base_dir + path;
}
global.include = function(file) {
	return require(abs_path('/' + file));
}


require('dotenv').config(); // FOR ENV ENVIORMENT 


const express = require('express');
const router = include('routes/router');
const port = process.env.PORT || 3000; // place port in variable 
const app = express(); 
app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));
app.use(express.static(__dirname + "/public"));
app.use('/',router);


app.listen(port, function (err) {
    console.log("Node application listening on port "+ port);
    if (err)
        console.log(err);
})