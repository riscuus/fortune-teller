# Fortune teller
___

## 1 Introduction

This is an express-app that uses JWT inside a cookie to mantain a user logged.  It uses Sqlite3 to store the users and passport middleware for the management of the user authentication

## 2. API

The server runs on ``localhost:3000``

Currently there are implemented 6 routes:

1. ``GET \`` Main route. User must be logged (JWT strategy). Shows fortune telling
2. ``GET \login`` The login page. User can fill a form with username and password
3. ``POST \login`` Post of the login page. The user credentials are sent a local strategy is followed to check authenticate the user.
4. ``GET \logout`` If the user is logged the express app clears the cookie so the user get logged out.
5. ``GET \user`` If the user is logged (JWT strategy) returns the username.
6. ``GET \wrong-login`` If the user sends a wrong username or password the user is redirected to this page where is informed about his error. Has a link to return to the login page.

## 3. Users

Currently in the database are saved ``1`` user with credentials:

```
username: walrus
password: walrus
```
Note that more users could be easily added just repeating the process we use to add the user to the database. It would also easy to implement the logic to add users using a sign-up page.

## 4. Usage

1. Open a terminal in project root folder
2. run ``npm install`` to install project dependencies
3. Launch the app using ``node index.js``
4. Open a web browser tab on ``localhost:3000``

## 5. Contact

Project created by Albert Risco (MET Student) albert.risco@estudiantat.upc.edu