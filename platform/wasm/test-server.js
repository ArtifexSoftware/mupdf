"use strict";

const http = require("http");
const express = require("express");

let app = express();

// Use Cross-Origin headers so browsers allow SharedArrayBuffer
app.use(function(req, res, next) {
	res.header("Cross-Origin-Opener-Policy", "same-origin");
	res.header("Cross-Origin-Embedder-Policy", "require-corp");
	next();
});

// TODO - Add some logging on each request

// Serve all static files in this folder
app.use(express.static("."));

let server = http.createServer(app);
server.listen(8000, "0.0.0.0");
