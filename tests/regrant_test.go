package tests

import (
  "testing"
  "reflect"
  "fmt"
  "time"
  "bytes"
  r "gopkg.in/dancannon/gorethink.v2"
  rg "github.com/karantin2020/regrant"
  re "github.com/karantin2020/recongo"
)

func init() {
  
}

func expect(t *testing.T, a interface{}, b interface{}) {
  if a != b {
    t.Errorf("Expected %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
  }
}

func refute(t *testing.T, a interface{}, b interface{}) {
  if a == b {
    t.Errorf("Did not expect %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
  }
}

// ==============TEST PERMISSIONS============== //

func Test_PermissionsInit(t *testing.T) {
  p, err := rg.Init(rg.Create | rg.Read | rg.Update)
  expect(t, p, rg.Create | rg.Read | rg.Update)
  expect(t, p, rg.PermissionMode(7))
  expect(t, err, nil)
  fmt.Println(p)

  err = p.Init(rg.Create | rg.Read | rg.Update)
  expect(t, p, rg.Create | rg.Read | rg.Update)
  expect(t, p, rg.PermissionMode(7))
  expect(t, err, nil)
  fmt.Println(p)
}

func Test_PermissionsAllow(t *testing.T) {
  p := rg.PermissionMode(0)
  err := p.Allow(rg.Create)
  expect(t, p, rg.Create)
  expect(t, p, rg.PermissionMode(1))
  expect(t, err, nil)
  fmt.Println(p)
}

func Test_PermissionsAllowBad(t *testing.T) {
  p := rg.PermissionMode(0)
  err := p.Allow(12)
  expect(t, p, rg.PermissionMode(0))
  refute(t, err, nil)
  fmt.Println(p)
}

func Test_PermissionsDeny(t *testing.T) {
  p := rg.PermissionMode(rg.Create | rg.Read | rg.Update)
  err := p.Deny(rg.Create)
  expect(t, p, rg.Read | rg.Update)
  expect(t, p, rg.PermissionMode(rg.Read | rg.Update))
  expect(t, err, nil)
  fmt.Println(p)
}

func Test_IsGranted(t *testing.T) {
  p := rg.PermissionMode(rg.Create | rg.Read | rg.Update)
  ok := p.IsGranted(rg.Create | rg.Read)
  expect(t, ok, true)
  fmt.Println(p)

  ok = p.IsGranted(rg.Delete | rg.Read)
  expect(t, ok, false)
  fmt.Println(p)
}

// ==============TEST USER============== //

func Test_NewUserNoClient(t *testing.T) {
  var bus rg.UserStore
  u, err := bus.NewUser("newUser", "empty")
  refute(t, err, nil)
  if err != nil {return}
  refute(t, u, rg.User{})
  expect(t, u.Name, "newUser")
  expect(t, bytes.Equal(u.Password, []byte("empty")), true)
  fmt.Println(u)
}

var (
  us *rg.UserStore
  host = "172.17.0.2:28015"
  db = "regrant_test"
  table = "regrant_users"
)

func cleanDB() {
  s, err := r.Connect(r.ConnectOpts{
    Address: host,
    Database: db,
  })
  if (err != nil) { panic(err) }
  session := s
  r.DBDrop(db).Exec(session)
}

func Test_PrepareClient(t *testing.T) {
  // var err error
  cleanDB()
  client, err := re.NewClient(re.Connection{host,"test"})
  if err != nil {
    panic(err)
  }
  us, err = rg.NewUserStore(client, db, table, time.Hour * 24 * 30 * 12, func (psw string) []byte {return []byte(psw + "1")})
  expect(t, err, nil)
  if err != nil {
    panic(err)
  }
}

func Test_NewUser(t *testing.T) {
  u, err := us.NewUser("newUser", "empty")
  expect(t, err, nil)
  if err != nil {return}
  refute(t, u, rg.User{})
  expect(t, u.Name, "newUser")
  expect(t, bytes.Equal(u.Password, []byte("empty1")), true)
  fmt.Printf("%+v\n",u)
}

func Test_NewUserTheSame(t *testing.T) {
  u, err := us.NewUser("newUser", "empty")
  refute(t, err, nil)
  fmt.Printf("%+v\n",err)
  if err != nil {return}
  refute(t, u, rg.User{})
  expect(t, u.Name, "newUser")
  expect(t, bytes.Equal(u.Password, []byte("empty1")), true)
  fmt.Printf("%+v",u)
}

func Test_GetUser(t *testing.T) {
  u, err := us.GetUser("newuser", "empty")
  expect(t, err, nil)
  fmt.Printf("%+v\n",u)
  if err != nil {return}
  refute(t, u, rg.User{})
  expect(t, u.Name, "newUser")
  expect(t, bytes.Equal(u.Password, []byte("empty1")), true)
}

func Test_NewUserEmptyPsw(t *testing.T) {
  u, err := us.NewUser("321世界|}{^&*^%$", "")
  expect(t, err, nil)
  fmt.Printf("%+v\n",err)
  if err != nil {return}
  refute(t, u, rg.User{})
  expect(t, u.Name, "321世界|}{^&*^%$")
  expect(t, bytes.Equal(u.Password, []byte("1")), true)
  fmt.Printf("%+v\n",u)
}

// Test Permissions

func Test_DefaultPermissions(t *testing.T) {
  p := &rg.Permissions{"default", "default", rg.Access{}}
  p.Default()
  expect(t, p.Access.Owner, rg.CRUD | rg.Execute)
  expect(t, p.Access.Group, rg.CRUD | rg.Execute)
  expect(t, p.Access.All, rg.Read)
  fmt.Printf("%+v\n",*p)
}

func Test_SetPermissions(t *testing.T) {
  p := &rg.Permissions{"test", "test", rg.Access{}}
  err := p.Set(rg.SetConfig{
    rg.Read | rg.Write,
    rg.Read | rg.Write,
    rg.Read,
  })
  expect(t, err, nil)
  expect(t, p.Access.Owner, rg.Read | rg.Write)
  expect(t, p.Access.Group, rg.Read | rg.Write)
  expect(t, p.Access.All, rg.Read)
  fmt.Printf("%+v\n",*p)
}

func Test_Anyone(t *testing.T) {
  p := &rg.Permissions{"test", "test", rg.Access{}}
  err := p.Anyone( rg.Read )
  expect(t, err, nil)
  expect(t, p.Access.Owner, rg.Read)
  expect(t, p.Access.Group, rg.Read)
  expect(t, p.Access.All, rg.Read)
  fmt.Printf("%+v\n",*p)
}

func Test_AnyoneIncorrect(t *testing.T) {
  p := &rg.Permissions{"test", "test", rg.Access{}}
  err := p.Anyone( 3 )
  refute(t, err, nil)
  expect(t, p.Access.Owner, rg.Nothing)
  expect(t, p.Access.Group, rg.Nothing)
  expect(t, p.Access.All, rg.Nothing)
  fmt.Printf("%+v\n",*p)
}

func Test_OwnerAndGroup(t *testing.T) {
  p := &rg.Permissions{"test", "test", rg.Access{}}
  err := p.Anyone( rg.Read )
  expect(t, err, nil)
  err = p.OwnerAndGroup( rg.Write )
  expect(t, err, nil)
  expect(t, p.Access.Owner, rg.Read | rg.Write)
  expect(t, p.Access.Group, rg.Read | rg.Write)
  expect(t, p.Access.All, rg.Read)
  fmt.Printf("%+v\n",*p)
}

func Test_OwnerAndGroupIncorrect(t *testing.T) {
  p := &rg.Permissions{"test", "test", rg.Access{}}
  err := p.OwnerAndGroup( rg.Read | rg.Update )
  refute(t, err, nil)
  err = p.OwnerAndGroup( 65 )
  refute(t, err, nil)
  expect(t, p.Access.Owner, rg.Nothing)
  expect(t, p.Access.Group, rg.Nothing)
  expect(t, p.Access.All, rg.Nothing)
  fmt.Printf("%+v\n",*p)
}

func Test_OnlyOwner(t *testing.T) {
  p := &rg.Permissions{"test", "test", rg.Access{}}
  err := p.Anyone( rg.Read )
  expect(t, err, nil)
  err = p.OnlyOwner( rg.Write )
  expect(t, err, nil)
  expect(t, p.Access.Owner, rg.Read | rg.Write)
  expect(t, p.Access.Group, rg.Read)
  expect(t, p.Access.All, rg.Read)
  fmt.Printf("%+v\n",*p)
}

func Test_OnlyOwnerReadWrite(t *testing.T) {
  p := &rg.Permissions{"test", "test", rg.Access{}}
  err := p.OnlyOwner( rg.Read | rg.Write )
  expect(t, err, nil)
  expect(t, p.Access.Owner, rg.Read | rg.Write)
  expect(t, p.Access.Group, rg.Nothing)
  expect(t, p.Access.All, rg.Nothing)
  fmt.Printf("%+v\n",*p)
}

func Test_OnlyOwnerIncorrect(t *testing.T) {
  p := &rg.Permissions{"test", "test", rg.Access{}}
  err := p.OnlyOwner( rg.Read | rg.Update )
  refute(t, err, nil)
  err = p.OnlyOwner( 65 )
  refute(t, err, nil)
  expect(t, p.Access.Owner, rg.Nothing)
  expect(t, p.Access.Group, rg.Nothing)
  expect(t, p.Access.All, rg.Nothing)
  fmt.Printf("%+v\n",*p)
}

func Test_Nobody(t *testing.T) {
  p := &rg.Permissions{"test", "test", rg.Access{}}
  err := p.Anyone( rg.Read | rg.Write )
  expect(t, err, nil)
  err = p.Nobody( rg.Read | rg.Write )
  expect(t, err, nil)
  expect(t, p.Access.Owner, rg.Read)
  expect(t, p.Access.Group, rg.Nothing)
  expect(t, p.Access.All, rg.Nothing)
  fmt.Printf("%+v\n",*p)
}

func Test_NobodyIncorrect(t *testing.T) {
  p := &rg.Permissions{"test", "test", rg.Access{}}
  err := p.Nobody( rg.Read | rg.Write )
  expect(t, err, nil)
  err = p.Nobody( 65 )
  refute(t, err, nil)
  expect(t, p.Access.Owner, rg.Read)
  expect(t, p.Access.Group, rg.Nothing)
  expect(t, p.Access.All, rg.Nothing)
  fmt.Printf("%+v\n",*p)
}

func Test_NobodyMoreDenied(t *testing.T) {
  p := &rg.Permissions{"test", "test", rg.Access{}}
  err := p.Anyone( rg.Read )
  expect(t, err, nil)
  err = p.Nobody( rg.Write )
  expect(t, err, nil)
  err = p.Nobody( rg.Read | rg.Write )
  expect(t, err, nil)
  expect(t, p.Access.Owner, rg.Read)
  expect(t, p.Access.Group, rg.Nothing)
  expect(t, p.Access.All, rg.Nothing)
  fmt.Printf("%+v\n",*p)
}

func Test_UserIsGranted(t *testing.T) {
  p := &rg.Permissions{"newuser", "newuser", rg.Access{}}
  err := p.Anyone( rg.Read )
  expect(t, err, nil)
  err = p.OwnerAndGroup( rg.Write )
  expect(t, err, nil)
  err = p.OnlyOwner( rg.Execute )
  expect(t, err, nil)
  var u *rg.User
  u, err = us.GetUser("newuser", "empty")
  expect(t, err, nil)
  perm := rg.CRUD
  var ok bool
  ok, err = p.IsGranted(u,perm)
  expect(t, err, nil)
  expect(t, ok, true)
  fmt.Printf("%+v\n",*p)
  fmt.Printf("%+v\n",*u)
}

func Test_UserIsGrantedNoAccess(t *testing.T) {
  p := &rg.Permissions{"default", "default", rg.Access{}}
  p.Default()
  u, err := us.GetUser("newuser", "empty")
  expect(t, err, nil)
  perm := rg.CRUD
  var ok bool
  ok, err = p.IsGranted(u,perm)
  expect(t, err, nil)
  expect(t, ok, false)
  fmt.Printf("%+v\n",*p)
  fmt.Printf("%+v\n",*u)
}


