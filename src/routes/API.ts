import express from 'express'
import * as mongoose from "mongoose";
import { Jwt} from '../utilities/jwt'

import cors from 'cors'


export class APIRouter{
    public  router = express.Router();
    constructor() {


        this.router.param('obj', function (req, res, next, obj) {
            req['Schema'] = mongoose.model(obj);
            next();
        });

        this.router.param('id', function (req, res, next, id) {
            if (id == 'save' || id == 'list' || id == 'create' || id == 'delete') {

                next();
            } else {

                req['Schema'].findById(id, function (err, obj) {
                    if (err == null)
                        req['Object'] = obj;
                    next();
                });

            }

        });


        this.router.route('/:obj/create')
            .post(function (req, res) {
                if (!req.body) {
                    throw new Error('Invalid Body');
                }

                let obj = new req['Schema'](req.body);

                obj.save(function (err, data) {
                    if (err) {
                        throw new Error(err);
                    }
                    res.json(data);
                });
            }, cors());

        this.router.route('/:obj/:id/delete')
            .post(function (req, res) {
                req['Schema'].remove({_id: req['Object']._id}, function (err) {
                    if (err) {
                        res.status(500);
                        return res.send(err);
                    }
                });

            });


//if Object schema has a roles property then it's a secure object and user must have role in correct
//context to access it
        this.router.route('/:obj/list')
            .post(function (req, res) {

                let fil = {};
                if (!!req.body && !!req.body.filter)
                    fil = req.body.filter;
                req['Object'] = new req['Schema']();


                if (req['Object'] != undefined && req['Object']._doc.hasOwnProperty("Roles")) {
                    let user = Jwt.currentUser(req);
                    let userRoleID = [];
                    for (let i = 0; i < user.roles.length; i++) {
                        if (user.roles[i].Right == req.body.filter.mode)
                            userRoleID.push(user.roles[i]._id);
                    }


                    fil['Roles'] = {$in: userRoleID};
                    req['Schema'].find(fil,
                        function (err, List) {
                            if (err){
                                res.status(500);
                                return res.send(err);
                            }

                            res.json(List);
                        });
                } else {

                    req['Schema'].find(fil,
                        function (err, List) {
                            if (err){
                                res.status(500);
                                return res.send(err);
                            }
                            res.json(List);
                        });
                }

            }, cors());

        this.router.route('/:obj/:id/save')
            .post(function (req, res) {

                let query = {'_id': req['Object'].id};
                delete req.body._id;
                delete req.body.__v;
                req['Schema'].findOneAndUpdate(query, req.body, {upsert: true}, function (err, obj) {
                    if (err){
                        res.status(500);
                        return res.send(err);
                    }
                    return res.status(200).send(obj);
                });


            });

        this.router.route('/:obj/:id')
            .delete(function (req, res) {

                req['Schema'].findByIdAndRemove(req['Object'].id, null, function (err) {
                    if (err){
                        res.status(500);
                        return res.send(err);
                    }
                    return res.status(200);
                });

            });

        this.router.route('/:obj/:id')
            .get(function (req, res) {
                return res.json(req['Object']);
            });
    }
}
