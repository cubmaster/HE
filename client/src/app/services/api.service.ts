import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs/internal/Observable';

import { environment } from "../../environments/environment";
import {IBase} from "../models/Base";


@Injectable({
  providedIn: 'root'
})
export class ApiService {

  private URL: string = environment.api;
  private httpOptions = {
    headers: new HttpHeaders({
      'Content-Type': 'application/json'
    })
  };


  constructor(private http: HttpClient) { }

  list(obj: IBase, filter: object = {}): Observable<any> {

    const targetUrl = this.URL + obj.classname.toLowerCase() + '/list'
    console.log(targetUrl);
    return this.http.post<any>(targetUrl, filter, this.httpOptions);
  }

  create(obj: IBase) {

    const targetUrl = this.URL + obj.classname.toLowerCase() + '/create'
    console.log(targetUrl);
    return this.http.post<any>(targetUrl, obj);
  }
  get(obj: IBase) {

    const targetUrl = this.URL + obj.classname.toLowerCase() + '/' + obj._id;
    console.log(targetUrl);
    return this.http.get<any>(targetUrl);
  }
  save(obj:IBase){
    const targetUrl = this.URL + obj.classname.toLowerCase() + '/' + obj._id + '/save';
    console.log(targetUrl);
    return this.http.post<any>(targetUrl,obj);
  }

  exec(obj: IBase) {

    const targetUrl = this.URL + 'exec';

    return this.http.post(targetUrl, obj);
  }

  delete(obj:IBase){
    const targetURL = this.URL + obj.classname.toLowerCase() + '/' + obj._id ;
    return this.http.delete(targetURL);
  }

}
