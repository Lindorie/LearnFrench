DROP TABLE if EXISTS users;

CREATE TABLE users (
    id integer PRIMARY KEY autoincrement,
    username varchar(100) NOT NULL,
    password varchar(300) NOT NULL,
    email varchar(150) NOT NULL
);