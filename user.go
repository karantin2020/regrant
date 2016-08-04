package regrant

import (
  "time"
  "errors"
  "strings"
  "bytes"
  // "fmt"
  r "gopkg.in/dancannon/gorethink.v2"
  re "github.com/karantin2020/recongo"
)

type User struct {
  Name string         `gorethink:"name"`
  Password []byte     `gorethink:"password,omitempty"`
  AccessToken string  `gorethink:"access_token,omitempty"`
  UID  string         `gorethink:"uid"`   // User ID
  GID  string         `gorethink:"gid"`   // Group ID
  RID string          `gorethink:"role"`   // Role ID
  Groups  []string    `gorethink:"groups"`
  Roles  []string     `gorethink:"roles"`
  Created time.Time   `gorethink:"created"`
  /*
  Active codes are:
  0 - inactive
  1 - active
  3 - reserved
   */
  Active int            `gorethink:"active"`
  PswExpires time.Time  `gorethink:"pswExpires"`
  userStore *UserStore  `gorethink:"us,omitempty"`
}

// type User struct {
//   *UserCore
//   Profile interface{}
// }

type UserStore struct {
  client *re.Client
  db, table string
  pswExpirationTime time.Duration
  hashFunc func (string) []byte
}

func NewUserStore(  initclient *re.Client, 
                    initdb, inittable string,
                    pswExpirationTime time.Duration,
                    fn func (string) []byte  ) (*UserStore, error) {
  var userStore *UserStore
  if initclient == nil || initdb == "" || inittable == "" {
    return userStore, errors.New("Wrong init parameters")
  }
  userStore = &UserStore{initclient,initdb,inittable,pswExpirationTime,fn}
  if fn == nil {
    userStore.hashFunc = func (psw string) []byte {return []byte(psw)}
  }
  if userStore.client.DBTest(initdb) != nil || userStore.client.TableTest(inittable) != nil {
    r.DBCreate(initdb).Exec(initclient.Session)
    r.DB(initdb).TableCreate(
      inittable,
      r.TableCreateOpts{PrimaryKey:"uid"},
    ).Exec(initclient.Session)
  }
  initclient.SetDB(initdb)
  initclient.Table(inittable)
  
  return userStore, nil
}

func (us *UserStore) NewUser(name, password string) (*User, error) {
  if us.client == nil {
    return nil, errors.New("No client was inited")
  }
  user := &User{
    Name: name,
    UID: strings.ToLower(name),
    GID: strings.ToLower(name),
    Groups: []string{strings.ToLower(name)},
    Password: us.hashFunc(password),
    Created: time.Now().UTC(),
    Active: 0,
    PswExpires: time.Now().Add(us.pswExpirationTime).UTC(),
    userStore: us,
  }
  _, err := r.DB(us.db).Table(us.table).Insert(
      user, 
      r.InsertOpts{
        Durability: "hard", 
        ReturnChanges: false,
      },
    ).RunWrite(us.client.Session)
  if err != nil {
    return nil, errors.New("User was not created because of incorrect input data")
  }
  return user, nil
}

func (us *UserStore) GetUser(name, password string) (*User, error) {
  if us.client == nil {
    return nil, errors.New("No client was inited")
  }
  user := &User{}
  err := us.client.Table(us.table).Get(name, user)
  if err != nil {
    return nil, err
  }
  if !bytes.Equal(user.Password, us.hashFunc(password)) {
    return nil, errors.New("Incorrect username or password")
  }
  user.userStore = us
  if time.Now().After(user.PswExpires) {
    return user, errors.New("Need update password")
  }
  return user, nil
}

type GrantedCB func (*User) (bool, error)

func CreateIsGranted(
    db string, 
    permissions int, 
    path ...string,
  ) GrantedCB {
  return func (u *User) (bool, error) {

    return false, nil
  }
}

// func (u *User) IsGranted(path ...string) (bool, error) {
//   if us.client == nil {
//     return false, errors.New("No client was inited")
//   }
//   if path.len == 1 {

//   }
//   err := us.client.Table(us.table).Get(name, user)
//   if err != nil {
//     return nil, err
//   }
//   if user.Password != us.hashFunc(password) {
//     return nil, errors.New("Incorrect username or password")
//   }
//   user.userStore = us
//   return user, nil
// }
