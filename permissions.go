package regrant

import (
  "errors"
  // "fmt"
)

// PermissionMode permission mode
type PermissionMode int

const (
  // Nothing predefined permission mode, nothing can do
  Nothing PermissionMode = 0
  // Create predefined permission mode, create content
  Create PermissionMode = 1
  // Read predefined permission mode, read content
  Read PermissionMode = 1 << 1
  // Update predefined permission mode, change content
  Update PermissionMode = 1 << 2
  // Delete predefined permission mode, delete content
  Delete PermissionMode = 1 << 3
  // Write predefined permission mode, create+update+delete
  Write PermissionMode = Create | Update | Delete
  // CRUD predefined permission mode, create+read+update+delete
  CRUD PermissionMode = Create | Read | Update | Delete
  // Execute predefined permission mode, web actions with no affect to resources
  Execute PermissionMode = 1 << 4
)

type Access struct {
  Owner PermissionMode  `gorethink:"owner"`
  Group PermissionMode  `gorethink:"group"`
  All PermissionMode    `gorethink:"all"`
}

type Permissions struct {
  Owner string    `gorethink:"owner"`
  Group string    `gorethink:"group"`
  Access          `gorethink:"access"`
}

func correctPermissionMode(perm PermissionMode) bool {
  switch perm {
    case 0:     // No permissions
        return true
    case Create:
        return true
    case Read:
        return true
    case Update:
        return true
    case Delete:
        return true
    case CRUD:
        return true
    case Write:
        return true
    case Write | Execute:
        return true
    case Read | Execute:
        return true
    case CRUD | Execute:
        return true
    case Execute:
        return true
    default:  // Incorrect permissions
        return false
    }
}

func correctPermissionHash(perm PermissionMode) bool {
  if perm > -1 && perm < 31 {
    return true
    } else {
      return false
    }
}

func Init(perm PermissionMode) (PermissionMode, error) {
  if !correctPermissionHash(perm) {return 0, errors.New("Incorrect PermissionMode to Init")}
  return perm, nil
}

func (r *PermissionMode) Init(perm PermissionMode) error {
  if !correctPermissionHash(perm) {*r = 0; return errors.New("Incorrect PermissionMode to Init")}
  *r = perm
  return nil
}

func (r PermissionMode) IsGranted(perm PermissionMode) bool {
  if (r == 0) {return false}
  return perm == (r & perm)
}

func (r *PermissionMode) Deny(perm PermissionMode) error {
  if !correctPermissionMode(perm) {
    // fmt.Println("Cann't deny:",*r,perm)
    return errors.New("Incorrect PermissionMode to Deny")
  }
  t := *r & perm
  if (*r == 0 || t == 0) {return nil}
  *r = *r ^ t
  return nil
}

func (r *PermissionMode) Allow(perm PermissionMode) error {
  if !correctPermissionMode(perm) {
    return errors.New("Incorrect PermissionMode to Allow")
  }
  *r = *r | perm
  return nil
}

// Access templates

func (p *Permissions) Anyone(perm PermissionMode) error {
  if !correctPermissionMode(perm) {
    return errors.New("Incorrect PermissionMode")
  }
  p.Access.Owner.Allow(perm)
  p.Access.Group.Allow(perm)
  p.Access.All.Allow(perm)
  return nil
}

func (p *Permissions) OwnerAndGroup(perm PermissionMode) error {
  if !correctPermissionMode(perm) {
    return errors.New("Incorrect PermissionMode")
  }
  p.Access.Owner.Allow(perm)
  p.Access.Group.Allow(perm)
  p.Access.All.Deny(perm)
  return nil
}

func (p *Permissions) OnlyOwner(perm PermissionMode) error {
  if !correctPermissionMode(perm) {
    return errors.New("Incorrect PermissionMode")
  }
  p.Access.Owner.Allow(perm)
  p.Access.Group.Deny(perm)
  p.Access.All.Deny(perm)
  return nil
}

func (p *Permissions) Nobody(perm PermissionMode) error {
  if !correctPermissionMode(perm) {
    return errors.New("Incorrect PermissionMode")
  }
  p.Access.Owner.Deny(perm)
  p.Access.Owner.Allow(Read)  // Owner always has read permission
  p.Access.Group.Deny(perm)
  p.Access.All.Deny(perm)
  return nil
}

// Permissions methods

func (p *Permissions) Default() {
  p.Anyone(Read)
  p.OwnerAndGroup(Write | Execute)
  // p.Nobody(Execute)
}

type SetConfig struct {
  Owner PermissionMode
  Group PermissionMode
  All PermissionMode
}

func correctPermConf(pc SetConfig) bool {
  return correctPermissionMode(pc.Owner) &&
    correctPermissionMode(pc.Group) &&
    correctPermissionMode(pc.All)
}

func (p *Permissions) Set(conf SetConfig) error {
  if !correctPermConf(conf) {
    return errors.New("Incorrect permissions to set up")
  }
  p.Access.Owner.Init(conf.Owner)
  p.Access.Owner.Allow(Read)  // Owner always has read permission
  p.Access.Group.Init(conf.Group)
  p.Access.All.Init(conf.All)
  return nil
}

func contains(s []string, e string) bool {
    for _, a := range s {
        if a == e {
            return true
        }
    }
    return false
}

func (p Permissions) IsGranted(user *User, perm PermissionMode) (bool, error) {
  if user == nil {
    return false, errors.New("User wasn't inited")
  }
  if !correctPermissionMode(perm) {
    return false, errors.New("Incorrect PermissionMode")
  }
  if p.Owner == user.UID {
    // fmt.Println("Owner:", p.Access.Owner & perm)
    return perm == (p.Access.Owner & perm), nil
  }
  if contains(user.Groups, p.Group) {
    // fmt.Println("Group:", p.Access.Group & perm)
    return perm == (p.Access.Group & perm), nil
  }
  // fmt.Println("All:", p.Access.All & perm)
  return perm == (p.Access.All & perm), nil
}


