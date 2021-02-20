import { Input } from '@angular/core';
import { Component, EventEmitter, OnInit } from '@angular/core';
import { BsModalRef } from 'ngx-bootstrap/modal';
import { User } from 'src/app/_models/User';

@Component({
  selector: 'app-roles-modal',
  templateUrl: './roles-modal.component.html',
  styleUrls: ['./roles-modal.component.css']
})
export class RolesModalComponent implements OnInit {
  @Input() updateSelectedRoles = new EventEmitter();
  user: User;
  roles: any[];
  
  constructor(private bsModalRef: BsModalRef) { }

  ngOnInit(): void {
  }

  updateRoles() {
    this.updateSelectedRoles.emit(this.roles);
  }

}
