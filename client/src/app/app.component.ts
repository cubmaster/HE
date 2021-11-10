// @ts-ignore
import {AfterViewInit, Component, OnInit} from '@angular/core';
import {NavigationStart, Router} from "@angular/router";


@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.sass']
})
export class AppComponent  {
  public currentPath:string;
  constructor(public router: Router) {
   this.router.events.subscribe((event) => {

       if (event instanceof NavigationStart) {
          this.currentPath = event.url;
       }
     }
   );

  }

}
