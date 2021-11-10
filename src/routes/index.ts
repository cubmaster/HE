import express from "express";

export class IndexRouter{
   public router = express.Router();

   constructor() {
      this.router.get('/', function(req, res, next) {
         res.sendfile('index.html',null);

      });
   }

}
