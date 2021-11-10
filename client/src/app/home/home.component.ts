import { Component, OnInit } from '@angular/core';
import {Notebook} from "../models/notebook";
import {ApiService} from "../services/api.service";
import {IBase} from "../models/Base";

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.sass']
})
export class HomeComponent implements OnInit {


  public noteBooks:Notebook[];
  constructor(private api: ApiService) { }



  ngOnInit(): void {


  }


}
