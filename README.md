# React / Vite / Golang / Google OAuth Integration using JWTs created completely by ChatGPT o1-preview

To run this locally:

## Testing the Application

### Add .env file to Go Server with actual client id and secret
```
GOOGLE_CLIENT_ID=real client id goes here
GOOGLE_CLIENT_SECRET=real client secret goes here
```

### Start the Go Server
`cd google-oauth-go`
Copy code \
`go run main.go`

### Start the React Application
`cd google-oauth-react`
Copy code \
`npm run dev`


# Text that ChatGPT created with the last prompt when I asked to add JWTs:


## **Table of Contents**



1. Understanding JWTs
2. Updating the Go Backend
    * a. Generate JWT after Authentication
    * b. Create Middleware for JWT Verification
    * c. Update Protected Endpoints
3. Updating the React Frontend
    * a. Store JWT Securely
    * b. Include JWT in API Requests
4. Testing the Application
5. Security Considerations
6. Additional Enhancements
7. Conclusion


---

&lt;a name="understanding-jwts">&lt;/a>


## **1. Understanding JWTs**

**JSON Web Tokens (JWTs)** are a compact and self-contained way for securely transmitting information between parties as a JSON object. They are commonly used for authentication and authorization.



* **Structure**: A JWT consists of three parts separated by dots: Header, Payload, and Signature.
* **Usage**: The token is signed using a secret or public/private key pair, ensuring that the content cannot be altered without detection.
* **Stateless Authentication**: Since all the necessary user information is contained within the token, the server doesn't need to maintain session state.


---

&lt;a name="updating-go-backend">&lt;/a>


## **2. Updating the Go Backend**

We'll modify the Go backend to generate and verify JWTs using the `github.com/golang-jwt/jwt` package.


### **a. Install JWT Package**

First, install the JWT package:

bash

Copy code


```
go get github.com/golang-jwt/jwt
```



### **b. Generate JWT after Authentication**

Update the `callbackHandler` to generate a JWT instead of setting a cookie.

**Updated <code>main.go</code></strong>

go

Copy code


```
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "os"
    "time"

    "github.com/golang-jwt/jwt"
    "github.com/gorilla/mux"
    "github.com/joho/godotenv"
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

var googleOauthConfig *oauth2.Config

// Secret key used to sign tokens (in production, store securely)
var jwtKey = []byte("your_secret_key")

func main() {
    // Load environment variables
    err := godotenv.Load()
    if err != nil {
        log.Fatal("Error loading .env file")
    }

    // Initialize OAuth2 config
    googleOauthConfig = &oauth2.Config{
        RedirectURL:  "http://localhost:8080/callback",
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
        Scopes: []string{
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
        },
        Endpoint: google.Endpoint,
    }

    // Initialize router
    r := mux.NewRouter()
    r.HandleFunc("/login", loginHandler)
    r.HandleFunc("/callback", callbackHandler)
    r.Handle("/user", jwtMiddleware(userHandler)).Methods("GET")
    r.HandleFunc("/logout", logoutHandler).Methods("POST")

    // Handle CORS
    handler := corsMiddleware(r)

    fmt.Println("Server started at http://localhost:8080")
    log.Fatal(http.ListenAndServe(":8080", handler))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    state := "randomstate" // Implement state verification for security
    url := googleOauthConfig.AuthCodeURL(state)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
    // TODO: Verify state parameter for security

    code := r.URL.Query().Get("code")
    token, err := googleOauthConfig.Exchange(context.Background(), code)
    if err != nil {
        http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Retrieve user info
    client := googleOauthConfig.Client(context.Background(), token)
    resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
    if err != nil {
        http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    var userInfo UserInfo
    if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
        http.Error(w, "Failed to decode user info: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Generate JWT
    expirationTime := time.Now().Add(24 * time.Hour)
    claims := &jwt.MapClaims{
        "exp":    expirationTime.Unix(),
        "user":   userInfo,
    }

    tokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := tokenJWT.SignedString(jwtKey)
    if err != nil {
        http.Error(w, "Failed to generate token: "+err.Error(), http.StatusInternalServerError)
        return
    }

    // Return the token to the client
    http.Redirect(w, r, "http://localhost:5173/?token="+tokenString, http.StatusTemporaryRedirect)
}

func userHandler(w http.ResponseWriter, r *http.Request) {
    // Retrieve the user info from the context
    userInfo := r.Context().Value("userInfo").(UserInfo)

    // Return the user info as JSON
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(userInfo)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
    // Client-side logout by removing the token
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Logged out"))
}

// Middleware to verify JWT
func jwtMiddleware(next http.HandlerFunc) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header missing", http.StatusUnauthorized)
            return
        }

        // Expected format: "Bearer <token>"
        tokenString := ""
        fmt.Sscanf(authHeader, "Bearer %s", &tokenString)

        if tokenString == "" {
            http.Error(w, "Token missing", http.StatusUnauthorized)
            return
        }

        // Parse and verify token
        claims := &jwt.MapClaims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method")
            }
            return jwtKey, nil
        })
        if err != nil || !token.Valid {
            http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
            return
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

        // Add user info to request context
        ctx := context.WithValue(r.Context(), "userInfo", userInfo)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// CORS middleware remains the same
func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
        w.Header().Set("Access-Control-Allow-Credentials", "true")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

        if r.Method == "OPTIONS" {
            return
        }

        next.ServeHTTP(w, r)
    })
}


---
```


**Explanation:**



* **JWT Key**: A secret key `jwtKey` is used to sign and verify tokens. **Important**: In production, store this key securely (e.g., in environment variables or a secrets manager).
* **Generating JWT**:
    * In `callbackHandler`, after authenticating with Google, we create a JWT containing the `userInfo`.
    * We set an expiration time (`exp` claim).
    * The token is signed using `HS256` algorithm.
    * We redirect back to the React app with the token as a query parameter.
* **Middleware for JWT Verification**:
    * The `jwtMiddleware` function parses and validates the JWT from the `Authorization` header.
    * If valid, it extracts the `userInfo` and adds it to the request context for use in handlers.
    * If invalid, it responds with `401 Unauthorized`.
* **Protected Endpoint**:
    * The `/user` endpoint is now protected by the `jwtMiddleware`.
    * It retrieves the `userInfo` from the context and returns it as JSON.
* **Logout Handler**:
    * Since JWTs are stateless, the server cannot invalidate a token. Logout is handled client-side by deleting the token.


---

&lt;a name="updating-react-frontend">&lt;/a>


## **3. Updating the React Frontend**


### **a. Store JWT Securely**

After the user is redirected back to the React app with the JWT, we'll store the token and use it for authenticated requests.

**Updated <code>src/App.tsx</code></strong>

tsx

Copy code


```
import React, { useEffect, useState } from 'react';
import axios from 'axios';

interface User {
  id?: string;
  email?: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  locale?: string;
}

const App: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    // Check if token is in URL parameters
    const params = new URLSearchParams(window.location.search);
    const tokenParam = params.get('token');
    if (tokenParam) {
      // Remove token from URL
      window.history.replaceState({}, document.title, '/');

      setToken(tokenParam);
      localStorage.setItem('token', tokenParam);
    } else {
      const storedToken = localStorage.getItem('token');
      if (storedToken) {
        setToken(storedToken);
      }
    }
  }, []);

  useEffect(() => {
    if (token) {
      // Fetch user data from the backend
      axios
        .get('http://localhost:8080/user', {
          headers: { Authorization: `Bearer ${token}` },
        })
        .then((response) => {
          setUser(response.data);
        })
        .catch((error) => {
          console.error('Not authenticated', error);
          setUser(null);
          setToken(null);
          localStorage.removeItem('token');
        });
    }
  }, [token]);

  const handleLogin = () => {
    window.location.href = 'http://localhost:8080/login';
  };

  const handleLogout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
  };

  return (
    <div className="App">
      <h1>React Google OAuth Example with JWT</h1>
      {user ? (
        <div>
          <h2>Welcome, {user.name}!</h2>
          {user.picture && <img src={user.picture} alt="Profile" />}
          <p>Email: {user.email}</p>
          <button onClick={handleLogout}>Logout</button>
        </div>
      ) : (
        <button onClick={handleLogin}>Login with Google</button>
      )}
    </div>
  );
};

export default App;


---
```


**Explanation:**



* **Token Management**:
    * We check if the `token` is present in the URL parameters after redirection.
    * If so, we store it in `localStorage` and in the `token` state.
    * We remove the token from the URL to keep it clean.
    * If there's no token in the URL, we check `localStorage` for an existing token.
* **Fetching User Data**:
    * When the `token` state changes, we make an API request to the `/user` endpoint.
    * We include the token in the `Authorization` header as `Bearer &lt;token>`.
* **Logout Functionality**:
    * On logout, we clear the `user` and `token` states and remove the token from `localStorage`.


---


### **b. Security Considerations for Storing JWTs**



* **Storing JWTs in Local Storage**:
    * Local Storage is vulnerable to XSS attacks.
    * If an attacker can inject JavaScript into your app, they can access the token.
    * **Alternative**: Store the token in memory or use HTTP-only cookies (which brings us back to the previous approach).
* **Token in URL Parameters**:
    * Exposing the token in URLs is not ideal because URLs can be logged in browser history and server logs.
    * **Alternative**: After redirection, send the token in the response body.

Given these concerns, you might consider using a more secure method to pass the token to the client. However, for simplicity and demonstration purposes, we'll proceed with the current approach.


---

&lt;a name="testing-application">&lt;/a>


## **4. Testing the Application**

**Start the Go Server \
**bash \
Copy code \
`go run main.go`



1. 

**Start the React Application \
**bash \
Copy code \
`npm run dev`



2. 
3. **Access the Application**
    * Open `http://localhost:5173` in your browser.
    * Click **Login with Google**.
    * After authentication, you'll be redirected back with the token.
    * The app will fetch your user data and display it.
4. **Verify the Network Requests**
    * Use the browser's developer tools to inspect the requests.
    * Ensure the `Authorization` header is present in the request to `/user`.


---

&lt;a name="security-considerations">&lt;/a>


## **5. Security Considerations**


### **1. Token Storage**



* **Local Storage Risks**: Storing tokens in `localStorage` or `sessionStorage` exposes them to XSS attacks.
* **Alternative**: Use HTTP-only cookies to store tokens securely. However, this requires the server to set cookies and handle CSRF protection.


### **2. Token Exposure in URL**



* **Avoid Tokens in URLs**: Tokens in URLs can be logged and cached.
* **Solution**: Instead of redirecting with the token in the URL, consider:
    * **Set Cookie**: Set the token in an HTTP-only cookie.
    * **Post Message**: Use the `postMessage` API to send the token from a popup window.
    * **Response Body**: If possible, make the callback endpoint return an HTML page that includes a script to send the token to the parent window.


### **3. Token Expiration and Refresh**



* **Expiration**: Tokens should have a reasonable expiration time.
* **Refresh Tokens**: Implement refresh tokens to allow obtaining new access tokens without re-authenticating.


### **4. HTTPS**



* **Use HTTPS**: Always use HTTPS in production to prevent man-in-the-middle attacks.


### **5. Validate JWT Signature**



* **Secure Key Management**: Store the `jwtKey` securely. Do not hardcode it in your source code.
* **Algorithm Selection**: Use a secure signing algorithm like `HS256` or `RS256`.


---

&lt;a name="additional-enhancements">&lt;/a>


## **6. Additional Enhancements**


### **Implementing Token Refresh**



* **Refresh Tokens**: Issue a long-lived refresh token to obtain new access tokens.
* **Endpoint**: Create a `/refresh` endpoint to issue new tokens.


### **Using State Parameter**



* **CSRF Protection**: Generate a random `state` parameter and verify it upon callback.
* **Implementation**: Store the `state` in a cookie or local storage before redirecting.


### **Handling Token Revocation**



* **Blacklist Tokens**: Maintain a blacklist of revoked tokens (e.g., in a database).
* **Considerations**: This introduces statefulness, which can impact scalability.


---

&lt;a name="conclusion">&lt;/a>


## **7. Conclusion**

You've now implemented JWT-based authentication in your React application with a Go backend. This approach provides a stateless authentication mechanism, which can improve the scalability of your application.

**Key Takeaways:**



* **JWTs** allow the server to authenticate requests without maintaining session state.
* **Security** is paramount; always consider the risks associated with token storage and transmission.
* **Logout** functionality is handled client-side by removing the token.


---


## **Next Steps**



* **Secure Token Handling**: Implement a more secure method for token storage and transmission.
* **State Verification**: Implement the `state` parameter for CSRF protection.
* **Token Refresh**: Implement refresh tokens to enhance user experience.
* **Production Readiness**: Securely store secrets, use HTTPS, and handle CORS appropriately in a production environment.


---


## **Additional Resources**



* **JWT Introduction**: jwt.io/introduction
* **Golang JWT Package**:[ github.com/golang-jwt/jwt](https://github.com/golang-jwt/jwt)
* **OWASP JWT Cheat Sheet**: owasp.org
* **React Security Best Practices**: React Security


---


## **Feel Free to Ask for Further Assistance**

If you have any questions or need help with implementing any of these features, such as secure token storage, token refresh mechanisms, or state parameter verification, please let me know, and I'll be happy to assist further!

o1
