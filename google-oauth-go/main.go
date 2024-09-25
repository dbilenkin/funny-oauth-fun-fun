package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/golang-jwt/jwt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type UserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}

type User struct {
	UserId    string    `dynamodbav:"UserId" json:"userId"`
	Email     string    `dynamodbav:"Email" json:"email"`
	Name      string    `dynamodbav:"Name" json:"name"`
	CreatedAt time.Time `dynamodbav:"CreatedAt" json:"createdAt"`
	// Add other fields as needed
}

type Claims struct {
	User UserInfo `json:"user"`
	jwt.StandardClaims
}

func authenticateRequest(request events.APIGatewayProxyRequest, jwtKey []byte) (*UserInfo, error) {
	authHeader, ok := request.Headers["Authorization"]
	if !ok {
		return nil, errors.New("authorization header missing")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, errors.New("invalid authorization header format")
	}

	tokenString := parts[1]
	if tokenString == "" {
		return nil, errors.New("token missing")
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	return &claims.User, nil
}

var googleOauthConfig *oauth2.Config
var jwtKey = []byte(os.Getenv("JWT_KEY"))
var allowedOrigin = os.Getenv("ALLOWED_ORIGIN")
var db *dynamodb.DynamoDB
var tableName string

func init() {
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}

	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("us-east-2"), // Replace with your region
	}))
	db = dynamodb.New(sess)
	tableName = "funny-oauth-users"
}

func handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	method := request.HTTPMethod
	path := request.Path

	fmt.Printf("Method: %s, Path: %s\n", method, path)

	// Handle OPTIONS method for CORS preflight
	if method == "OPTIONS" {
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusOK,
			Headers:    getCORSHeaders(),
			Body:       "",
		}, nil
	}

	// Routing logic based on path
	switch path {
	case "/login":
		return loginHandler(request)
	case "/callback":
		return callbackHandler(request)
	case "/user":
		return userHandler(request)
	case "/users":
		return listUsersHandler(request)
	default:
		return events.APIGatewayProxyResponse{
			StatusCode: http.StatusNotFound,
			Headers:    getCORSHeaders(),
			Body:       "Not Found",
		}, nil
	}
}

func loginHandler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	state := "randomstate" // Implement proper state management for security
	url := googleOauthConfig.AuthCodeURL(state)

	headers := getCORSHeaders()
	headers["Location"] = url

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusFound,
		Headers:    headers,
		Body:       "",
	}, nil
}

func callbackHandler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	code := request.QueryStringParameters["code"]
	if code == "" {
		return errorResponse("Code not found in query parameters", http.StatusBadRequest)
	}

	token, err := googleOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		fmt.Println("Error exchanging token:", err)
		return errorResponse("Failed to exchange token", http.StatusInternalServerError)
	}

	client := googleOauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		fmt.Println("Error getting user info:", err)
		return errorResponse("Failed to get user info", http.StatusInternalServerError)
	}
	defer resp.Body.Close()

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		fmt.Println("Error decoding user info:", err)
		return errorResponse("Failed to decode user info", http.StatusInternalServerError)
	}

	// Save user to DynamoDB
	if err := saveUser(userInfo); err != nil {
		return errorResponse("Failed to save user data", http.StatusInternalServerError)
	}

	// Generate JWT
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &jwt.MapClaims{
		"exp":  expirationTime.Unix(),
		"user": userInfo,
	}

	tokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := tokenJWT.SignedString(jwtKey)
	if err != nil {
		fmt.Println("Error generating JWT:", err)
		return errorResponse("Failed to generate token", http.StatusInternalServerError)
	}

	// Redirect back to the React app with the token
	redirectURL := os.Getenv("FRONTEND_URL") + "?token=" + tokenString

	headers := getCORSHeaders()
	headers["Location"] = redirectURL

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusFound,
		Headers:    headers,
		Body:       "",
	}, nil
}

func saveUser(userInfo UserInfo) error {

	fmt.Println("userInfo: ", userInfo)
	fmt.Println("userInfo.ID: ", userInfo.ID)
	user := User{
		UserId:    userInfo.ID,
		Email:     userInfo.Email,
		Name:      userInfo.Name,
		CreatedAt: time.Now(),
		// Populate other fields if necessary
	}

	av, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		fmt.Println("Failed to marshal user data:", err)
		return err
	}

	// Log the marshalled item
	marshalledItem, _ := json.MarshalIndent(av, "", "  ")
	fmt.Println("Marshalled Item:", string(marshalledItem))

	input := &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      av,
		// Optionally, you can use a condition expression to prevent overwriting existing items
		// ConditionExpression: aws.String("attribute_not_exists(UserID)"),
	}

	_, err = db.PutItem(input)
	if err != nil {
		fmt.Println("Failed to put item into DynamoDB:", err)
		return err
	}

	return nil
}

func listUsersHandler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	_, err := authenticateRequest(request, jwtKey)
	if err != nil {
		return errorResponse(err.Error(), http.StatusUnauthorized)
	}

	// Optionally, restrict access based on userInfo
	// e.g., check if user has admin privileges

	input := &dynamodb.ScanInput{
		TableName: aws.String(tableName),
	}

	result, err := db.Scan(input)
	if err != nil {
		fmt.Println("Failed to scan DynamoDB:", err)
		return errorResponse("Failed to retrieve users", http.StatusInternalServerError)
	}

	var users []User
	err = dynamodbattribute.UnmarshalListOfMaps(result.Items, &users)
	if err != nil {
		fmt.Println("Failed to unmarshal users:", err)
		return errorResponse("Failed to process user data", http.StatusInternalServerError)
	}

	responseBody, err := json.Marshal(users)
	if err != nil {
		return errorResponse("Failed to marshal users", http.StatusInternalServerError)
	}

	headers := getCORSHeaders()
	headers["Content-Type"] = "application/json"

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers:    headers,
		Body:       string(responseBody),
	}, nil
}

func userHandler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	authHeader := request.Headers["Authorization"]
	if authHeader == "" {
		return errorResponse("Authorization header missing", http.StatusUnauthorized)
	}

	// Extract token from the header
	var tokenString string
	if _, err := fmt.Sscanf(authHeader, "Bearer %s", &tokenString); err != nil {
		return errorResponse("Invalid authorization header format", http.StatusUnauthorized)
	}

	if tokenString == "" {
		return errorResponse("Token missing", http.StatusUnauthorized)
	}

	// Parse and validate the JWT token
	claims := &jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		return errorResponse("Invalid token: "+err.Error(), http.StatusUnauthorized)
	}

	// Extract user info from claims
	userMap := (*claims)["user"].(map[string]interface{})
	userInfo := UserInfo{
		ID:            userMap["id"].(string),
		Email:         userMap["email"].(string),
		VerifiedEmail: userMap["verified_email"].(bool),
		Name:          userMap["name"].(string),
		GivenName:     userMap["given_name"].(string),
		FamilyName:    userMap["family_name"].(string),
		Picture:       userMap["picture"].(string),
		Locale:        userMap["locale"].(string),
	}

	responseBody, err := json.Marshal(userInfo)
	if err != nil {
		return errorResponse("Failed to marshal user info", http.StatusInternalServerError)
	}

	headers := getCORSHeaders()
	headers["Content-Type"] = "application/json"

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Headers:    headers,
		Body:       string(responseBody),
	}, nil
}

func errorResponse(message string, statusCode int) (events.APIGatewayProxyResponse, error) {
	headers := getCORSHeaders()
	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       message,
	}, nil
}

func getCORSHeaders() map[string]string {
	return map[string]string{
		"Access-Control-Allow-Origin":      allowedOrigin,
		"Access-Control-Allow-Methods":     "GET, POST, OPTIONS",
		"Access-Control-Allow-Headers":     "Content-Type, Authorization",
		"Access-Control-Allow-Credentials": "true",
	}
}

func main() {
	lambda.Start(handler)
}
