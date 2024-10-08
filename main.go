package main

import (
	"context"
	"crypto/sha256"
	//"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	"strings"
	"html/template"

    "go.mongodb.org/mongo-driver/bson/primitive"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"

	//"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/github"
	//"github.com/markbates/goth/providers/google"
	"github.com/markbates/goth/providers/spotify"
	//"github.com/markbates/goth/providers/twitter"
)

var (
	store *sessions.CookieStore
	db *mongo.Database
	client *mongo.Client
)

// Post represents a user post
type Post struct {
    ID           primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    ObfuscatedID string             `bson:"obfuscated_id" json:"obfuscated_id"`
    Text         string             `bson:"text" json:"text"`
    CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
}

func ConnectToDatabase() {
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		log.Fatal("MONGODB_URI is not set in the env vars")
	}

	clientOptions := options.Client().ApplyURI(mongoURI)
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}

	// Ping DB just to check
	if err := client.Ping(context.Background(), nil); err != nil {
		log.Fatalf("Failed to ping MongoDB: %v", err)
	}

	db = client.Database("test")
	fmt.Println("Connected to mongoDB")
}

func InitializeIndexes() {
	postsCollection := db.Collection("posts")

	// Create an index on created_at for sorting (newest first)
	indexModel := mongo.IndexModel{
		Keys: bson.D{{Key: "created_at", Value: -1}}, // Descending order
	}

	_, err := postsCollection.Indexes().CreateOne(context.Background(), indexModel)
	if err != nil {
		log.Fatalf("Failed to create index on created_at: %v", err)
	}

	fmt.Println("Indexes created successfully")
}
	
func main() {
	r := gin.Default()
	r.LoadHTMLGlob("public/*.html")

	// err := godotenv.Load("main.env")
	// if err != nil {
	// 	log.Fatalf("Error loading main.env file: %v", err)
	// }

	sessionKey := os.Getenv("SESSION_SECRET")
	if sessionKey == "" {
		log.Fatal("Session secret was not loaded.")
		return
	}

	store = sessions.NewCookieStore([]byte(sessionKey))

	ConnectToDatabase()
	InitializeIndexes()
	ConnectToProvider()

	// Ensure the mongodb client disconnects when app closes
	defer func() {
        if err := client.Disconnect(context.Background()); err != nil {
            log.Fatalf("Error disconnecting from MongoDB: %v", err)
        }
        fmt.Println("Disconnected from MongoDB")
    }()

	r.GET("/", indexHandler)
	r.GET("/login", func(c *gin.Context) {
		c.HTML(200, "login.html", nil)
	})
	r.GET("/auth/:provider", BeginAuthHandler)
	r.GET("/auth/:provider/callback", CompleteAuthHandler)

	r.GET("/feed", AuthRequired(store), FeedHandler)
	r.POST("/feed", AuthRequired(store), PostFeedHandler)

	err := r.Run(":3000")
	if err != nil {
		log.Fatal(err)
	}
}
	
func indexHandler(c *gin.Context) {
	// Access the MongoDB collection
	postsCollection := db.Collection("posts")

	// Find all posts sorted by CreatedAt descending (newest first)
	findOptions := options.Find()
	findOptions.SetSort(bson.D{{"created_at", -1}})

	cursor, err := postsCollection.Find(context.Background(), bson.D{}, findOptions)
	if err != nil {
		log.Printf("Error fetching posts: %v", err)
		c.HTML(http.StatusInternalServerError, "index.html", gin.H{
			"Error": "Failed to fetch posts",
		})
		return
	}
	defer cursor.Close(context.Background())

	var posts []Post
	for cursor.Next(context.Background()) {
		var post Post
		if err := cursor.Decode(&post); err != nil {
			log.Printf("Error decoding post: %v", err)
			continue
		}
		posts = append(posts, post)
	}

	if err := cursor.Err(); err != nil {
		log.Printf("Cursor error: %v", err)
		c.HTML(http.StatusInternalServerError, "index.html", gin.H{
			"Error": "Error reading posts",
		})
		return
	}

	// Render the index.html template with the posts
	c.HTML(http.StatusOK, "index.html", gin.H{
		"Posts": posts,
	})
}

func ConnectToProvider() {
	fmt.Println("***CONNECT TO PROVIDER RUNNING***")
	sessionKey := os.Getenv("SESSION_SECRET")
	if sessionKey == "" {
		log.Fatal("Session secret not loaded.")
		return
	}

	maxAge := 86400 * 30
	isProd := false // Change to true for production environment

	store = sessions.NewCookieStore([]byte(sessionKey))
	store.MaxAge(maxAge)
	store.Options.Path = ("/")
	store.Options.HttpOnly = true
	store.Options.Secure = isProd
	store.Options.SameSite = http.SameSiteLaxMode

	gothic.Store = store

	goth.UseProviders(
		//google.New(os.Getenv("GOOGLE_ID"), os.Getenv("GOOGLE_SECRET"), "http://localhost:3000/auth/google/callback", "email", "profile"),
		//twitter.New(os.Getenv("TWITTER_ID"), os.Getenv("TWITTER_SECRET"), "http://localhost:3000/auth/twitter/callback"),
		github.New(os.Getenv("GITHUB_ID"), os.Getenv("GITHUB_SECRET"), "http://localhost:3000/auth/github/callback"),
		spotify.New(os.Getenv("SPOTIFY_ID"), os.Getenv("SPOTIFY_SECRET"), "http://localhost:3000/auth/spotify/callback"),
		//facebook.New(os.Getenv("META_ID"), os.Getenv("META_SECRET"), "http://localhost:3000/auth/facebook/callback"),
	)
}

func AuthRequired(store *sessions.CookieStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := store.Get(c.Request, "session-name")
		if err != nil {
			log.Printf("Error getting session: %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// Check if user is already authenticated
		if userID, ok := session.Values["user_id"]; ok && userID != "" {
			// User is authenticated, proceed with request
			c.Next()
		} else {
			// User is not authenticated, redirect to login
			c.Redirect(http.StatusFound ,"/login")
			c.Abort()
		}
	}
}

func BeginAuthHandler(c *gin.Context) {
	fmt.Println("****BEGIN AUTH HANDLER RUNNING****")

	// Get the users session
	session, err := store.Get(c.Request, "session-name")
	if err != nil {
		fmt.Println("Error getting session, most likely not signed in")
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	// Check if user is already authenticated
	if userID, ok := session.Values["user_id"]; ok && userID != "" {
		// If user is already logged in, return to home
		c.Redirect(http.StatusFound, "/")
		return
	}

	// Extract the provider
	provider := c.Param("provider")
	if provider == "" {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"Message": "Provider not specified",
		})
		return
	}

	q := c.Request.URL.Query()
	q.Add("provider", provider)
	c.Request.URL.RawQuery = q.Encode()

	//fmt.Println("Request URL: ", c.Request.URL.String())

	gothic.BeginAuthHandler(c.Writer, c.Request)
}

func CompleteAuthHandler(c *gin.Context) {
	fmt.Println("****COMPLETE AUTH HANDLER RUNNING****")

	provider := c.Param("provider")
	//fmt.Println("Provider: ", provider)

	user, err := gothic.CompleteUserAuth(c. Writer, c.Request)
	if err != nil {
		fmt.Println("Could not complete user auth")
		c.Redirect(http.StatusTemporaryRedirect, "/login")
		return
	}

	//fmt.Println("Authenticated user: ", user)

	// fmt.Println("Connecting to DB")
	// db := ConnectToDatabase()
	// defer db.Close()

	// fmt.Println("Connected to DB")
	email := user.Email
	userid := user.UserID

	// Get or create session
	session, err := store.Get(c.Request, "session-name")
	if err != nil {
		fmt.Println(err)
		log.Fatal("Failed to create or retrieve session")
		return
	}

	//fmt.Println("Created or recieved session")

	// Access the MongoDB collection
    usersCollection := db.Collection("users")

	// Check for existing user
    var existingUser struct {
        ObfuscatedID string `bson:"obfuscatedid"`
    }
    err = usersCollection.FindOne(context.Background(), bson.M{"email": email}).Decode(&existingUser)

    var obfuscatedID string

    if err == mongo.ErrNoDocuments {
        // No existing user, create a new one
        obfuscatedID = generateObfuscatedID(userid)

        newUser := bson.M{
            "oauthuserid":  userid,
            "email":        email,
            "provider":     provider,
            "obfuscatedid": obfuscatedID,
        }

        _, err := usersCollection.InsertOne(context.Background(), newUser)
        if err != nil {
            log.Printf("Error inserting new user: %v", err)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
            return
        }
        fmt.Println("New user added to DB")
    } else if err != nil {
        log.Printf("Error querying user: %v", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
        return
    } else {
        // User already exists
        obfuscatedID = existingUser.ObfuscatedID
        fmt.Println("User already in database")
    }

	//fmt.Println("User added to DB")

	session.Values["obfuscated_id"] = obfuscatedID
	session.Values["user_id"] = userid

	// Save session
	if err = session.Save(c.Request, c.Writer); err != nil {
		fmt.Println("Error saving session:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Session error"})
		return
	}

	// fmt.Println("User Info stored in session")
	// fmt.Println("UserID: ", userid)
	// fmt.Println("Obfuscated UserID: ", obfuscatedID)

	c.Redirect(http.StatusFound, "/")
}

func generateObfuscatedID(userID string) string {
	// Create a sha256 hash of the userID
	hash := sha256.Sum256([]byte(userID))
	// Take the first 4 bytes (8 characters) of the hash
	return hex.EncodeToString(hash[:4])
}

func FeedHandler(c *gin.Context) {
	// Extract obfuscated_id from session
	session, err := store.Get(c.Request, "session-name")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Session error"})
		return
	}

	obfuscatedID, ok := session.Values["obfuscated_id"].(string)
	if !ok || obfuscatedID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"Error": "Unauthorizaed"})
		return
	}

	postsCollection := db.Collection("posts")

	// Find all posts sorted by CreatedAt desc (newest first)
	findOptions := options.Find()
	findOptions.SetSort(bson.D{{"created_at", -1}})

	cursor, err := postsCollection.Find(context.Background(), bson.D{}, findOptions)
	if err != nil {
		log.Printf("Error fetching posts: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Failed to fetch posts"})
		return
	}
	defer cursor.Close(context.Background())

	var posts []Post
	for cursor.Next(context.Background()) {
		var post Post
		if err := cursor.Decode(&post); err != nil {
			log.Printf("Error decoding post: %v", err)
			continue
		}
		posts =append(posts, post)
	}

	if err := cursor.Err(); err != nil {
		log.Printf("Cursor error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Error reading posts"})
		return
	}

	c.HTML(http.StatusOK, "feed.html", gin.H{"Posts": posts})
}

func PostFeedHandler(c *gin.Context) {
	// Retrieve the session
	session, err := store.Get(c.Request, "session-name")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Session error"})
		return
	}

	// Get obfuscated_id from session
	obfuscatedID, ok := session.Values["obfuscated_id"].(string)
	if !ok || obfuscatedID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Parse the form input
	text := c.PostForm("text")
	if text == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Text cannot be empty"})
		return
	}

	// Sanitize input by escaping HTML and trimming spaces
	sanitizedText := template.HTMLEscapeString(text)
	sanitizedText = strings.TrimSpace(sanitizedText)

	// Create a new post
	newPost := Post{
		ObfuscatedID: obfuscatedID,
		Text:         sanitizedText,
		CreatedAt:    time.Now(),
	}

	// Access the MongoDB collection
	postsCollection := db.Collection("posts")

	// Insert the new post
	_, err = postsCollection.InsertOne(context.Background(), newPost)
	if err != nil {
		log.Printf("Error inserting post: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create post"})
		return
	}

	// Redirect back to the feed
	c.Redirect(http.StatusFound, "/feed")
}