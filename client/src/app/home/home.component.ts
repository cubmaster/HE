import { Component, OnInit } from '@angular/core';
import {ApiService} from "../services/api.service";
import {IBase} from "../models/Base";
import {CryptoService} from "../services/crypto.service";
@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.sass']
})
export class HomeComponent implements OnInit {


  constructor(private api: ApiService) { }



  ngOnInit(): void {


  }


}
