/*
  Rules declare what kinds of queries can be run by a user or a group. 
  Reject bad operations before a query is executed

  It's an abstract synonym of allowed permissions for certain query action
  with certain resource.

  Rules consist of constant name and permissions

 */

package regrant

import (
  // "errors"
)

type Rule struct {
  Name string `gorethink:"name"`
  Permissions PermissionMode `gorethink:"permissions"`
}

