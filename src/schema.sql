DROP TABLE if EXISTS users;
DROP TABLE if EXISTS questions;
DROP TABLE if EXISTS answers;

CREATE TABLE users (
    id integer PRIMARY KEY autoincrement,
    username varchar(100) NOT NULL,
    password varchar(300) NOT NULL,
    email varchar(150) NOT NULL
    level varchar(50) NOT NULL DEFAULT "Beginner"
);

CREATE TABLE questions {
    id integer PRIMARY KEY autoincrement,
    question varchar(400) NOT NULL,
    answer_id integer NOT NULL
};

CREATE TABLE answers {
    id integer PRIMARY KEY autoincrement,
    answer varchar(200) NOT NULL,
    question_id integer NOT NULL
};