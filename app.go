package main

import (
	"database/sql"
	"encoding/gob"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/patrickmn/go-cache"
)
import "net/http/pprof"

var (
	db    *sql.DB
	store *sessions.CookieStore
	ca    *cache.Cache
)

type User struct {
	ID          int
	AccountName string
	NickName    string
	Email       string
}

type Profile struct {
	UserID    int
	FirstName string
	LastName  string
	Sex       string
	Birthday  mysql.NullTime
	Pref      string
	UpdatedAt time.Time
}

type Entry struct {
	ID        int
	UserID    int
	Private   bool
	Title     string
	Content   string
	CreatedAt time.Time
}

type Comment struct {
	ID        int
	EntryID   int
	UserID    int
	Comment   string
	CreatedAt time.Time
}

type Friend struct {
	ID        int
	CreatedAt time.Time
}

type Footprint struct {
	UserID    int
	OwnerID   int
	CreatedAt time.Time
	Updated   time.Time
}

var prefs = []string{"未入力",
	"北海道", "青森県", "岩手県", "宮城県", "秋田県", "山形県", "福島県", "茨城県", "栃木県", "群馬県", "埼玉県", "千葉県", "東京都", "神奈川県", "新潟県", "富山県",
	"石川県", "福井県", "山梨県", "長野県", "岐阜県", "静岡県", "愛知県", "三重県", "滋賀県", "京都府", "大阪府", "兵庫県", "奈良県", "和歌山県", "鳥取県", "島根県",
	"岡山県", "広島県", "山口県", "徳島県", "香川県", "愛媛県", "高知県", "福岡県", "佐賀県", "長崎県", "熊本県", "大分県", "宮崎県", "鹿児島県", "沖縄県"}

var (
	ErrAuthentication   = errors.New("Authentication error.")
	ErrPermissionDenied = errors.New("Permission denied.")
	ErrContentNotFound  = errors.New("Content not found.")
)

func authenticate(w http.ResponseWriter, r *http.Request, email, passwd string) {
	query := `SELECT u.id AS id, u.account_name AS account_name, u.nick_name AS nick_name, u.email AS email
FROM users u
JOIN salts s ON u.id = s.user_id
WHERE u.email = ? AND u.passhash = SHA2(CONCAT(?, s.salt), 512)`
	row := db.QueryRow(query, email, passwd)
	user := User{}
	err := row.Scan(&user.ID, &user.AccountName, &user.NickName, &user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			checkErr(ErrAuthentication)
		}
		checkErr(err)
	}
	session := getSession(w, r)
	session.Values["user_id"] = user.ID
	session.Save(r, w)
}

func getCurrentUser(w http.ResponseWriter, r *http.Request) *User {
	u := context.Get(r, "user")
	if u != nil {
		user := u.(User)
		return &user
	}
	session := getSession(w, r)
	userID, ok := session.Values["user_id"]
	if !ok || userID == nil {
		return nil
	}

	w.Header().Set("Userid", strconv.Itoa(userID.(int)))

	key := "userid-" + strconv.Itoa(userID.(int))
	cuser, found := ca.Get(key)

	if found {
		user := User{}
		user = cuser.(User)
		return &user
	}

	row := db.QueryRow(`SELECT id, account_name, nick_name, email FROM users WHERE id=?`, userID)
	user := User{}
	err := row.Scan(&user.ID, &user.AccountName, &user.NickName, &user.Email)
	if err == sql.ErrNoRows {
		checkErr(ErrAuthentication)
	}
	checkErr(err)
	context.Set(r, "user", user)
	ca.Set(key, user, cache.NoExpiration)

	return &user
}

func authenticated(w http.ResponseWriter, r *http.Request) bool {
	user := getCurrentUser(w, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return false
	}
	return true
}

func getUser(w http.ResponseWriter, userID int) *User {
	key := "user" + strconv.Itoa(userID)
	//cache
	cv, found := ca.Get(key)
	if found {
		user := User{}
		user = cv.(User)
		return &user
	}

	row := db.QueryRow(`SELECT * FROM users WHERE id = ?`, userID)
	user := User{}
	err := row.Scan(&user.ID, &user.AccountName, &user.NickName, &user.Email, new(string))
	if err == sql.ErrNoRows {
		checkErr(ErrContentNotFound)
	}
	checkErr(err)
	ca.Set(key, user, cache.NoExpiration)
	return &user
}

func getUserFromAccount(w http.ResponseWriter, name string) *User {
	row := db.QueryRow(`SELECT * FROM users WHERE account_name = ?`, name)
	user := User{}
	err := row.Scan(&user.ID, &user.AccountName, &user.NickName, &user.Email, new(string))
	if err == sql.ErrNoRows {
		checkErr(ErrContentNotFound)
	}
	checkErr(err)
	return &user
}

func isFriend(w http.ResponseWriter, r *http.Request, anotherID int) bool {
	session := getSession(w, r)
	id := session.Values["user_id"].(int)

	oneId, anotherId := getOrderedOneAnotherId(id, anotherID)
	key := "isFrined_" + strconv.Itoa(oneId) + "_" + strconv.Itoa(anotherId)

	_, found := ca.Get(key)

	////結果があればisFriend = true
	if found {
		return true
	}

	row := db.QueryRow(`SELECT COUNT(1) AS cnt FROM relations WHERE (one = ? AND another = ?)`, oneId, anotherId)
	cnt := new(int)
	err := row.Scan(cnt)
	checkErr(err)

	//結果がある場合はisFriend = true
	if *cnt > 0 {
		ca.Set(key, 1, cache.NoExpiration)
		return true
	}

	return false
}

func isFriendAccount(w http.ResponseWriter, r *http.Request, name string) bool {
	user := getUserFromAccount(w, name)
	if user == nil {
		return false
	}
	return isFriend(w, r, user.ID)
}

func permitted(w http.ResponseWriter, r *http.Request, anotherID int) bool {
	user := getCurrentUser(w, r)
	if anotherID == user.ID {
		return true
	}
	return isFriend(w, r, anotherID)
}

func markFootprint(w http.ResponseWriter, r *http.Request, id int) {
	user := getCurrentUser(w, r)
	if user.ID != id {
		_, err := db.Exec(`replace INTO footprints (user_id,owner_id,created_at) VALUES (?,?, now())`, id, user.ID)
		checkErr(err)
	}
}

func myHandler(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rcv := recover()
			if rcv != nil {
				switch {
				case rcv == ErrAuthentication:
					session := getSession(w, r)
					delete(session.Values, "user_id")
					session.Save(r, w)
					render(w, r, http.StatusUnauthorized, "login.html", struct{ Message string }{"ログインに失敗しました"})
					return
				case rcv == ErrPermissionDenied:
					render(w, r, http.StatusForbidden, "error.html", struct{ Message string }{"友人のみしかアクセスできません"})
					return
				case rcv == ErrContentNotFound:
					render(w, r, http.StatusNotFound, "error.html", struct{ Message string }{"要求されたコンテンツは存在しません"})
					return
				default:
					var msg string
					if e, ok := rcv.(runtime.Error); ok {
						msg = e.Error()
					}
					if s, ok := rcv.(string); ok {
						msg = s
					}
					msg = rcv.(error).Error()
					http.Error(w, msg, http.StatusInternalServerError)
				}
			}
		}()
		fn(w, r)
	}
}

func getSession(w http.ResponseWriter, r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isucon5q-go.session")
	return session
}

func getTemplatePath(file string) string {
	return path.Join("templates", file)
}

func render(w http.ResponseWriter, r *http.Request, status int, file string, data interface{}) {
	fmap := template.FuncMap{
		"getUser": func(id int) *User {
			return getUser(w, id)
		},
		"getCurrentUser": func() *User {
			return getCurrentUser(w, r)
		},
		"isFriend": func(id int) bool {
			return isFriend(w, r, id)
		},
		"prefectures": func() []string {
			return prefs
		},
		"substring": func(s string, l int) string {
			if len(s) > l {
				return s[:l]
			}
			return s
		},
		"split": strings.Split,
		"getEntry": func(id int) Entry {
			row := db.QueryRow(`SELECT * FROM entries WHERE id=?`, id)
			var entryID, userID, private int
			var body string
			var createdAt time.Time
			checkErr(row.Scan(&entryID, &userID, &private, &body, &createdAt))
			return Entry{id, userID, private == 1, strings.SplitN(body, "\n", 2)[0], strings.SplitN(body, "\n", 2)[1], createdAt}
		},
		"numComments": func(id int) int {
			row := db.QueryRow(`SELECT COUNT(*) AS c FROM comments WHERE entry_id = ?`, id)
			var n int
			checkErr(row.Scan(&n))
			return n
		},
	}
	tpl := template.Must(template.New(file).Funcs(fmap).ParseFiles(getTemplatePath(file), getTemplatePath("header.html")))
	w.WriteHeader(status)
	checkErr(tpl.Execute(w, data))
}

func GetLogin(w http.ResponseWriter, r *http.Request) {
	render(w, r, http.StatusOK, "login.html", struct{ Message string }{"高負荷に耐えられるSNSコミュニティサイトへようこそ!"})
}

func PostLogin(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	passwd := r.FormValue("password")
	authenticate(w, r, email, passwd)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func GetLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(w, r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func GetIndex(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	user := getCurrentUser(w, r)

	prof := Profile{}
	row := db.QueryRow(`SELECT * FROM profiles WHERE user_id = ?`, user.ID)
	err := row.Scan(&prof.UserID, &prof.FirstName, &prof.LastName, &prof.Sex, &prof.Birthday, &prof.Pref, &prof.UpdatedAt)
	if err != sql.ErrNoRows {
		checkErr(err)
	}

	rows, err := db.Query(`SELECT * FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5`, user.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	entries := make([]Entry, 0, 5)
	for rows.Next() {
		var id, userID, private int
		var body string
		var createdAt time.Time
		checkErr(rows.Scan(&id, &userID, &private, &body, &createdAt))
		entries = append(entries, Entry{id, userID, private == 1, strings.SplitN(body, "\n", 2)[0], strings.SplitN(body, "\n", 2)[1], createdAt})
	}
	rows.Close()

	rows, err = db.Query(`SELECT c.id AS id, c.entry_id AS entry_id, c.user_id AS user_id, c.comment AS comment, c.created_at AS created_at
FROM comments c
JOIN entries e ON c.entry_id = e.id
WHERE e.user_id = ?
ORDER BY c.created_at DESC
LIMIT 10`, user.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	commentsForMe := make([]Comment, 0, 10)
	for rows.Next() {
		c := Comment{}
		checkErr(rows.Scan(&c.ID, &c.EntryID, &c.UserID, &c.Comment, &c.CreatedAt))
		commentsForMe = append(commentsForMe, c)
	}
	rows.Close()

	//友人の日記を10件取得したい
	rows, err = db.Query(`
SELECT
e.id as id,
e.user_id as user_id,
e.private as private,
e.body as body,
e.created_at as created_at
FROM entries e
inner join relations r
on e.user_id = r.one
where r.another = ?
ORDER BY e.created_at DESC LIMIT 10;
	`, user.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}

	entriesOfFriends := make([]Entry, 0, 10)
	for rows.Next() {
		var id, userID, private int
		var body string
		var createdAt time.Time
		checkErr(rows.Scan(&id, &userID, &private, &body, &createdAt))
		entriesOfFriends = append(entriesOfFriends, Entry{id, userID, private == 1, strings.SplitN(body, "\n", 2)[0], strings.SplitN(body, "\n", 2)[1], createdAt})
	}
	rows.Close()

	//友人のコメントで、かつコメント対象の日記を作成したユーザーと友達のものを最新10件を取得したい
	rows, err = db.Query(`
SELECT
c.ID as id,
c.entry_id as entry_id,
c.user_id as user_id,
c.comment as comment,
c.created_at as created_at
FROM comments c
inner join relations r
on c.user_id = r.one
where r.another = ?
ORDER BY c.created_at DESC LIMIT 10
	`, user.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	commentsOfFriends := make([]Comment, 0, 10)
	for rows.Next() {
		c := Comment{}
		checkErr(rows.Scan(&c.ID, &c.EntryID, &c.UserID, &c.Comment, &c.CreatedAt))
		commentsOfFriends = append(commentsOfFriends, c)
	}
	rows.Close()

	rows, err = db.Query(`SELECT another, created_at FROM relations WHERE one = ? ORDER BY created_at DESC`, user.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	friendsMap := make(map[int]time.Time)
	for rows.Next() {
		var friendID int
		var createdAt time.Time
		checkErr(rows.Scan(&friendID, &createdAt))
		if _, ok := friendsMap[friendID]; !ok {
			friendsMap[friendID] = createdAt
		}
	}
	friends := make([]Friend, 0, len(friendsMap))
	for key, val := range friendsMap {
		friends = append(friends, Friend{key, val})
	}
	rows.Close()

	//友人の最新10件のあしあとを取得
	rows, err = db.Query(`
SELECT
user_id,
owner_id,
created_at
FROM footprints
WHERE user_id = ?
GROUP BY user_id, owner_id
ORDER BY created_at DESC
LIMIT 10`, user.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	footprints := make([]Footprint, 0, 10)
	for rows.Next() {
		fp := Footprint{}
		checkErr(rows.Scan(&fp.UserID, &fp.OwnerID, &fp.CreatedAt))
		footprints = append(footprints, fp)
	}
	rows.Close()

	render(w, r, http.StatusOK, "index.html", struct {
		User              User
		Profile           Profile
		Entries           []Entry
		CommentsForMe     []Comment
		EntriesOfFriends  []Entry
		CommentsOfFriends []Comment
		Friends           []Friend
		Footprints        []Footprint
	}{
		*user, prof, entries, commentsForMe, entriesOfFriends, commentsOfFriends, friends, footprints,
	})
}

func GetProfile(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	account := mux.Vars(r)["account_name"]
	owner := getUserFromAccount(w, account)
	row := db.QueryRow(`SELECT * FROM profiles WHERE user_id = ?`, owner.ID)
	prof := Profile{}
	err := row.Scan(&prof.UserID, &prof.FirstName, &prof.LastName, &prof.Sex, &prof.Birthday, &prof.Pref, &prof.UpdatedAt)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	var query string
	if permitted(w, r, owner.ID) {
		query = `SELECT * FROM entries WHERE user_id = ? ORDER BY created_at LIMIT 5`
	} else {
		query = `SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at LIMIT 5`
	}
	rows, err := db.Query(query, owner.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	entries := make([]Entry, 0, 5)
	for rows.Next() {
		var id, userID, private int
		var body string
		var createdAt time.Time
		checkErr(rows.Scan(&id, &userID, &private, &body, &createdAt))
		entry := Entry{id, userID, private == 1, strings.SplitN(body, "\n", 2)[0], strings.SplitN(body, "\n", 2)[1], createdAt}
		entries = append(entries, entry)
	}
	rows.Close()

	markFootprint(w, r, owner.ID)

	render(w, r, http.StatusOK, "profile.html", struct {
		Owner   User
		Profile Profile
		Entries []Entry
		Private bool
	}{
		*owner, prof, entries, permitted(w, r, owner.ID),
	})
}

func PostProfile(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}
	user := getCurrentUser(w, r)
	account := mux.Vars(r)["account_name"]
	if account != user.AccountName {
		checkErr(ErrPermissionDenied)
	}
	query := `UPDATE profiles
SET first_name=?, last_name=?, sex=?, birthday=?, pref=?, updated_at=CURRENT_TIMESTAMP()
WHERE user_id = ?`
	birth := r.FormValue("birthday")
	firstName := r.FormValue("first_name")
	lastName := r.FormValue("last_name")
	sex := r.FormValue("sex")
	pref := r.FormValue("pref")
	_, err := db.Exec(query, firstName, lastName, sex, birth, pref, user.ID)
	checkErr(err)
	// TODO should escape the account name?
	http.Redirect(w, r, "/profile/"+account, http.StatusSeeOther)
}

func ListEntries(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	account := mux.Vars(r)["account_name"]
	owner := getUserFromAccount(w, account)
	var query string
	if permitted(w, r, owner.ID) {
		query = `SELECT * FROM entries WHERE user_id = ? ORDER BY created_at DESC LIMIT 20`
	} else {
		query = `SELECT * FROM entries WHERE user_id = ? AND private=0 ORDER BY created_at DESC LIMIT 20`
	}
	rows, err := db.Query(query, owner.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	entries := make([]Entry, 0, 20)
	for rows.Next() {
		var id, userID, private int
		var body string
		var createdAt time.Time
		checkErr(rows.Scan(&id, &userID, &private, &body, &createdAt))
		entry := Entry{id, userID, private == 1, strings.SplitN(body, "\n", 2)[0], strings.SplitN(body, "\n", 2)[1], createdAt}
		entries = append(entries, entry)
	}
	rows.Close()

	markFootprint(w, r, owner.ID)

	render(w, r, http.StatusOK, "entries.html", struct {
		Owner   *User
		Entries []Entry
		Myself  bool
	}{owner, entries, getCurrentUser(w, r).ID == owner.ID})
}

func GetEntry(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}
	entryID := mux.Vars(r)["entry_id"]
	row := db.QueryRow(`SELECT * FROM entries WHERE id = ?`, entryID)
	var id, userID, private int
	var body string
	var createdAt time.Time
	err := row.Scan(&id, &userID, &private, &body, &createdAt)
	if err == sql.ErrNoRows {
		checkErr(ErrContentNotFound)
	}
	checkErr(err)
	entry := Entry{id, userID, private == 1, strings.SplitN(body, "\n", 2)[0], strings.SplitN(body, "\n", 2)[1], createdAt}
	owner := getUser(w, entry.UserID)
	if entry.Private {
		if !permitted(w, r, owner.ID) {
			checkErr(ErrPermissionDenied)
		}
	}
	rows, err := db.Query(`SELECT * FROM comments WHERE entry_id = ?`, entry.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	comments := make([]Comment, 0, 10)
	for rows.Next() {
		c := Comment{}
		checkErr(rows.Scan(&c.ID, &c.EntryID, &c.UserID, &c.Comment, &c.CreatedAt))
		comments = append(comments, c)
	}
	rows.Close()

	markFootprint(w, r, owner.ID)

	render(w, r, http.StatusOK, "entry.html", struct {
		Owner    *User
		Entry    Entry
		Comments []Comment
	}{owner, entry, comments})
}

func PostEntry(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	user := getCurrentUser(w, r)
	title := r.FormValue("title")
	if title == "" {
		title = "タイトルなし"
	}
	content := r.FormValue("content")
	var private int
	if r.FormValue("private") == "" {
		private = 0
	} else {
		private = 1
	}
	_, err := db.Exec(`INSERT INTO entries (user_id, private, body) VALUES (?,?,?)`, user.ID, private, title+"\n"+content)
	checkErr(err)
	http.Redirect(w, r, "/diary/entries/"+user.AccountName, http.StatusSeeOther)
}

func PostComment(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	entryID := mux.Vars(r)["entry_id"]
	row := db.QueryRow(`SELECT * FROM entries WHERE id = ?`, entryID)
	var id, userID, private int
	var body string
	var createdAt time.Time
	err := row.Scan(&id, &userID, &private, &body, &createdAt)
	if err == sql.ErrNoRows {
		checkErr(ErrContentNotFound)
	}
	checkErr(err)

	entry := Entry{id, userID, private == 1, strings.SplitN(body, "\n", 2)[0], strings.SplitN(body, "\n", 2)[1], createdAt}
	owner := getUser(w, entry.UserID)
	if entry.Private {
		if !permitted(w, r, owner.ID) {
			checkErr(ErrPermissionDenied)
		}
	}
	user := getCurrentUser(w, r)

	_, err = db.Exec(`INSERT INTO comments (entry_id, user_id, comment) VALUES (?,?,?)`, entry.ID, user.ID, r.FormValue("comment"))
	checkErr(err)
	http.Redirect(w, r, "/diary/entry/"+strconv.Itoa(entry.ID), http.StatusSeeOther)
}

func GetFootprints(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	user := getCurrentUser(w, r)
	footprints := make([]Footprint, 0, 50)
	rows, err := db.Query(`
SELECT
user_id,
owner_id,
created_at
FROM footprints
WHERE user_id = ?
GROUP BY user_id, owner_id
ORDER BY created_at DESC
LIMIT 50`, user.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	for rows.Next() {
		fp := Footprint{}
		checkErr(rows.Scan(&fp.UserID, &fp.OwnerID, &fp.Updated))
		footprints = append(footprints, fp)
	}
	rows.Close()
	render(w, r, http.StatusOK, "footprints.html", struct{ Footprints []Footprint }{footprints})
}
func GetFriends(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	user := getCurrentUser(w, r)
	rows, err := db.Query(`SELECT another, created_at FROM relations WHERE one = ? ORDER BY created_at DESC`, user.ID)
	if err != sql.ErrNoRows {
		checkErr(err)
	}
	friendsMap := make(map[int]time.Time)
	for rows.Next() {
		var friendID int
		var createdAt time.Time
		checkErr(rows.Scan(&friendID, &createdAt))
		if _, ok := friendsMap[friendID]; !ok {
			friendsMap[friendID] = createdAt
		}
	}
	rows.Close()
	friends := make([]Friend, 0, len(friendsMap))
	for key, val := range friendsMap {
		friends = append(friends, Friend{key, val})
	}
	render(w, r, http.StatusOK, "friends.html", struct{ Friends []Friend }{friends})
}

func PostFriends(w http.ResponseWriter, r *http.Request) {
	if !authenticated(w, r) {
		return
	}

	user := getCurrentUser(w, r)
	anotherAccount := mux.Vars(r)["account_name"]
	if !isFriendAccount(w, r, anotherAccount) {
		another := getUserFromAccount(w, anotherAccount)

		_, err := db.Exec(`INSERT INTO relations (one, another) VALUES (?,?), (?, ?)`, user.ID, another.ID, another.ID, user.ID)
		checkErr(err)
		http.Redirect(w, r, "/friends", http.StatusSeeOther)
	}
}

//userIdを2つわたして、oneId < anotherIdの順番で返す
func getOrderedOneAnotherId(userIdOne int, userIdTwo int) (oneId int, anotherId int) {
	if userIdOne < userIdTwo {
		oneId = userIdOne
		anotherId = userIdTwo
	} else {
		oneId = userIdTwo
		anotherId = userIdOne
	}

	return oneId, anotherId
}

func GetInitialize(w http.ResponseWriter, r *http.Request) {
	db.Exec("DELETE FROM relations WHERE id > 500000")
	db.Exec("DELETE FROM footprints WHERE id > 500000")
	db.Exec("DELETE FROM entries WHERE id > 500000")
	db.Exec("DELETE FROM comments WHERE id > 1500000")
	GetCacheLoad(w, r)
}

func AttachProfiler(router *mux.Router) {
	router.HandleFunc("/debug/pprof/", pprof.Index)
	router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	router.HandleFunc("/debug/pprof/profile", pprof.Profile)
	router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	router.HandleFunc("/debug/pprof/block", pprof.Handler("block").ServeHTTP)
	router.HandleFunc("/debug/pprof/heap", pprof.Handler("heap").ServeHTTP)
	router.HandleFunc("/debug/pprof/goroutine", pprof.Handler("goroutine").ServeHTTP)
	router.HandleFunc("/debug/pprof/threadcreate", pprof.Handler("threadcreate").ServeHTTP)
}

func GetCacheSave(w http.ResponseWriter, r *http.Request) {
	//ベンチマークでアクセスされるuser_idの傾向みると500番以下が9割なので500番までのuser_idをcacheしておく
	for i := 1; i < 500; i++ {
		getUser(w, i)
		time.Sleep(4 * time.Millisecond)
	}

	items := ca.Items()
	err := Save("/tmp/go-cache.gob", items)
	checkErr(err)

	count := ca.ItemCount()
	log.Printf("Saved Cache: %v", count)
}

// Encode via Gob to file
func Save(path string, items map[string]cache.Item) error {
	file, err := os.Create(path)
	checkErr(err)
	defer file.Close()

	gob.Register(User{})
	encoder := gob.NewEncoder(file)
	err = encoder.Encode(items)
	checkErr(err)

	return err
}

func GetCacheLoad(w http.ResponseWriter, r *http.Request) {
	items, err := Load("/tmp/go-cache.gob")
	checkErr(err)

	ca = cache.NewFrom(5*time.Minute, 5*time.Minute, items)

	//cv, _ := ca.Get("user1")
	//log.Printf("%v", cv)

	//cv2, _ := ca.Get("user2")
	//log.Printf("%v", cv2)

	count := ca.ItemCount()
	log.Printf("Loaded Cache: %v", count)
}

// Decode Gob file
func Load(path string) (map[string]cache.Item, error) {
	items := map[string]cache.Item{}

	file, err := os.Open(path)
	checkErr(err)
	defer file.Close()

	gob.Register(User{})
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&items)
	checkErr(err)

	return items, err
}

func main() {
	fmt.Println("start")
	//runtime.SetBlockProfileRate(1)
	runtime.GOMAXPROCS(4)

	ca = cache.New(5*time.Minute, 30*time.Second)

	user := os.Getenv("ISUCON5_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCON5_DB_PASSWORD")
	dbname := os.Getenv("ISUCON5_DB_NAME")
	if dbname == "" {
		dbname = "isucon5q"
	}
	ssecret := os.Getenv("ISUCON5_SESSION_SECRET")
	if ssecret == "" {
		ssecret = "beermoris"
	}

	var err error
	db, err = sql.Open("mysql", user+":"+password+"@unix(/var/run/mysqld/mysqld.sock)/"+dbname+"?loc=Local&parseTime=true")
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	store = sessions.NewCookieStore([]byte(ssecret))

	r := mux.NewRouter()
	//AttachProfiler(r)

	l := r.Path("/login").Subrouter()
	l.Methods("GET").HandlerFunc(myHandler(GetLogin))
	l.Methods("POST").HandlerFunc(myHandler(PostLogin))
	r.Path("/logout").Methods("GET").HandlerFunc(myHandler(GetLogout))

	p := r.Path("/profile/{account_name}").Subrouter()
	p.Methods("GET").HandlerFunc(myHandler(GetProfile))
	p.Methods("POST").HandlerFunc(myHandler(PostProfile))

	d := r.PathPrefix("/diary").Subrouter()
	d.HandleFunc("/entries/{account_name}", myHandler(ListEntries)).Methods("GET")
	d.HandleFunc("/entry", myHandler(PostEntry)).Methods("POST")
	d.HandleFunc("/entry/{entry_id}", myHandler(GetEntry)).Methods("GET")

	d.HandleFunc("/comment/{entry_id}", myHandler(PostComment)).Methods("POST")

	r.HandleFunc("/footprints", myHandler(GetFootprints)).Methods("GET")

	r.HandleFunc("/friends", myHandler(GetFriends)).Methods("GET")
	r.HandleFunc("/friends/{account_name}", myHandler(PostFriends)).Methods("POST")

	r.HandleFunc("/save", myHandler(GetCacheSave)).Methods("GET")
	r.HandleFunc("/load", myHandler(GetCacheLoad)).Methods("GET")

	r.HandleFunc("/initialize", myHandler(GetInitialize))
	r.HandleFunc("/", myHandler(GetIndex))
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("../static")))
	log.Fatal(http.ListenAndServe(":8080", r))
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
